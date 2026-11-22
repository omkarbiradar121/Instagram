import os
import re
import uuid
import hmac
import threading
import time
from urllib.parse import urlsplit

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    make_response,
    send_from_directory,
    jsonify
)

from PIL import Image, UnidentifiedImageError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set the SECRET_KEY environment variable before starting the app.")
if not app.config["SQLALCHEMY_DATABASE_URI"]:
    raise RuntimeError("Set the DATABASE_URL environment variable before starting the app.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
# Keep the session cookie available to every app route, including auth form POSTs.
# Leave the domain unset so browsers use a host-only cookie (works with localhost
# and 127.0.0.1 when each is used consistently for both requests).
app.config["SESSION_COOKIE_PATH"] = "/"
app.config["SESSION_COOKIE_DOMAIN"] = None
app.config["LOGIN_RATE_LIMIT"] = 10
app.config["LOGIN_RATE_WINDOW_SECONDS"] = 15 * 60
app.config["REGISTER_RATE_LIMIT"] = 5
app.config["REGISTER_RATE_WINDOW_SECONDS"] = 60 * 60
app.config["PROFILE_PICTURE_FOLDER"] = os.path.join(
    app.root_path, "uploads", "profile_pictures"
)
app.config["POST_IMAGE_FOLDER"] = os.path.join(app.root_path, "uploads", "posts")
app.config["REEL_FOLDER"] = os.path.join(app.root_path, "uploads", "reels")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024 + 64 * 1024
app.config["POST_MAX_FILE_SIZE"] = 5 * 1024 * 1024
app.config["REEL_MAX_FILE_SIZE"] = 100 * 1024 * 1024

_AUTH_RATE_LIMIT_BUCKETS = {}
_AUTH_RATE_LIMIT_LOCK = threading.Lock()
_MAX_AUTH_RATE_LIMIT_BUCKETS = 4096

_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,78}[A-Za-z0-9])?\Z")
_EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")

# Ensure upload folders exist
os.makedirs(app.config["PROFILE_PICTURE_FOLDER"], exist_ok=True)
os.makedirs(app.config["POST_IMAGE_FOLDER"], exist_ok=True)
os.makedirs(app.config["REEL_FOLDER"], exist_ok=True)


def is_safe_image_filename(filename, allowed_extensions=("jpg", "jpeg", "png", "webp")):
    """Validate filename against path traversal and dangerous characters."""
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        return False
    parts = filename.rsplit(".", 1)
    if len(parts) != 2:
        return False
    ext = parts[1].lower()
    if ext not in allowed_extensions:
        return False
    return bool(re.fullmatch(r"^[a-zA-Z0-9_\-\.]+$", parts[0]))


def is_safe_reel_filename(filename):
    return bool(re.fullmatch(r"[a-f0-9]{32}\.(?:mp4|webm)", filename or ""))


def validate_reel_upload(upload):
    """Validate extension, declared MIME type, size, and container signature."""
    extension = os.path.splitext(upload.filename or "")[1].lower()
    expected_mimes = {".mp4": {"video/mp4"}, ".webm": {"video/webm"}}
    if extension not in expected_mimes:
        return None, "Choose an MP4 or WebM video."
    if (upload.mimetype or "").lower() not in expected_mimes[extension]:
        return None, "The video type does not match its file extension."

    try:
        upload.stream.seek(0, os.SEEK_END)
        file_size = upload.stream.tell()
        upload.stream.seek(0)
        if file_size > app.config["REEL_MAX_FILE_SIZE"]:
            return None, "Reels must be no larger than 100 MB."
        signature = upload.stream.read(12)
        upload.stream.seek(0)
    except (OSError, ValueError):
        return None, "The uploaded video could not be read."

    valid_signature = (
        extension == ".mp4" and len(signature) >= 8 and signature[4:8] == b"ftyp"
    ) or (
        extension == ".webm" and signature.startswith(b"\x1a\x45\xdf\xa3")
    )
    if not valid_signature:
        return None, "The uploaded file is not a valid MP4 or WebM video."
    return extension, None


def safe_referrer_path(referrer, fallback):
    """Return only a local path from a referrer to prevent external redirects."""
    if not referrer:
        return fallback
    parsed = urlsplit(referrer)
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return fallback
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def is_werkzeug_password_hash(value):
    """Recognize Werkzeug's encoded hash formats without misreading plain text."""
    return bool(re.fullmatch(
        r"(?:scrypt:\d+:\d+:\d+|pbkdf2:(?:sha1|sha256|sha512):\d+)\$[^$]+\$[0-9a-fA-F]+",
        value or "",
    ))


def is_valid_username(username):
    """Allow a simple username character set supported by profile URLs."""
    return bool(_USERNAME_PATTERN.fullmatch(username or ""))


def is_valid_email(email):
    """Apply the same basic email format check at registration and profile edit."""
    return bool(_EMAIL_PATTERN.fullmatch(email or ""))


def auth_rate_limit_retry_after(scope, limit, window_seconds):
    """Consume one in-memory auth attempt and return seconds to wait if limited."""
    now = time.monotonic()
    key = (scope, request.remote_addr or "unknown")
    with _AUTH_RATE_LIMIT_LOCK:
        attempts = [
            timestamp
            for timestamp in _AUTH_RATE_LIMIT_BUCKETS.get(key, [])
            if now - timestamp < window_seconds
        ]
        if len(attempts) >= limit:
            _AUTH_RATE_LIMIT_BUCKETS[key] = attempts
            return max(1, int(attempts[0] + window_seconds - now + 0.999))

        if (
            key not in _AUTH_RATE_LIMIT_BUCKETS
            and len(_AUTH_RATE_LIMIT_BUCKETS) >= _MAX_AUTH_RATE_LIMIT_BUCKETS
        ):
            expired_before = now - max(window_seconds, app.config["REGISTER_RATE_WINDOW_SECONDS"])
            for old_key, old_attempts in list(_AUTH_RATE_LIMIT_BUCKETS.items()):
                if not old_attempts or old_attempts[-1] <= expired_before:
                    _AUTH_RATE_LIMIT_BUCKETS.pop(old_key, None)
            if len(_AUTH_RATE_LIMIT_BUCKETS) >= _MAX_AUTH_RATE_LIMIT_BUCKETS:
                _AUTH_RATE_LIMIT_BUCKETS.pop(next(iter(_AUTH_RATE_LIMIT_BUCKETS)))

        attempts.append(now)
        _AUTH_RATE_LIMIT_BUCKETS[key] = attempts
    return 0


def remove_file_safely(path, operation):
    """Remove one file without turning cleanup failures into request failures."""
    try:
        os.remove(path)
    except FileNotFoundError:
        return True
    except OSError:
        app.logger.exception("%s", operation)
        return False
    return True


def _serve_fallback_post_image():
    """Serve a graceful fallback SVG when a post image is missing or invalid."""
    images_dir = os.path.join(app.root_path, "static", "images")
    placeholder_path = os.path.join(images_dir, "default-post.svg")
    if os.path.isfile(placeholder_path):
        response = send_from_directory(images_dir, "default-post.svg")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Type"] = "image/svg+xml"
        return response
    return "", 404


def _serve_fallback_profile_picture():
    """Serve a graceful fallback SVG when an avatar image is missing or invalid."""
    images_dir = os.path.join(app.root_path, "static", "images")
    avatar_path = os.path.join(images_dir, "default-avatar.svg")
    if os.path.isfile(avatar_path):
        response = send_from_directory(images_dir, "default-avatar.svg")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Type"] = "image/svg+xml"
        return response
    return "", 404


# ==========================================
# 3. CONNECT TO DATABASE
# ==========================================
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Log enough context to diagnose rejected forms without exposing tokens."""
    session_cookie_present = bool(
        request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    )
    csrf_session_token_present = bool(session.get("csrf_token"))
    app.logger.warning(
        "CSRF validation failed for %s %s: %s "
        "(host=%s, session_cookie_present=%s, csrf_session_token_present=%s, "
        "secure_request=%s, secure_cookie_required=%s)",
        request.method,
        request.path,
        error.description,
        request.host,
        session_cookie_present,
        csrf_session_token_present,
        request.is_secure,
        app.config["SESSION_COOKIE_SECURE"],
    )
    return "The form could not be verified. Refresh the page and try again.", 400


@app.after_request
def add_security_headers(response):
    """Set defensive headers that do not interfere with the current UI."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response

db = SQLAlchemy(app)


# ==========================================
# 4. USER DATABASE MODEL
# ==========================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    # Werkzeug password hashes fit in this existing column; no schema change is needed.
    password = db.Column(
        db.String(255),
        nullable=False
    )

    display_name = db.Column(
        db.String(80),
        nullable=True
    )

    bio = db.Column(
        db.String(150),
        nullable=True
    )

    profile_picture = db.Column(
        db.String(80),
        nullable=True
    )

    posts = db.relationship(
        "Post", back_populates="user", cascade="all, delete-orphan",
        order_by="Post.created_at.desc()"
    )
    likes = db.relationship("Like", back_populates="user", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="user", cascade="all, delete-orphan")
    following = db.relationship(
        "Follow",
        foreign_keys="Follow.follower_id",
        back_populates="follower",
        cascade="all, delete-orphan"
    )
    followers = db.relationship(
        "Follow",
        foreign_keys="Follow.following_id",
        back_populates="following",
        cascade="all, delete-orphan"
    )
    saved_posts = db.relationship(
        "SavedPost", back_populates="user", cascade="all, delete-orphan"
    )
    reels = db.relationship(
        "Reel", back_populates="user", cascade="all, delete-orphan",
        order_by="Reel.created_at.desc()"
    )
    reel_likes = db.relationship("ReelLike", back_populates="user", cascade="all, delete-orphan")
    reel_comments = db.relationship("ReelComment", back_populates="user", cascade="all, delete-orphan")
    saved_reels = db.relationship("SavedReel", back_populates="user", cascade="all, delete-orphan")
    received_notifications = db.relationship(
        "Notification",
        foreign_keys="Notification.recipient_id",
        back_populates="recipient",
        cascade="all, delete-orphan",
        order_by="Notification.created_at.desc()"
    )
    sent_notifications = db.relationship(
        "Notification",
        foreign_keys="Notification.sender_id",
        back_populates="sender",
        cascade="all, delete-orphan"
    )


class Post(db.Model):
    __tablename__ = "posts"
    __table_args__ = (
        db.Index("ix_posts_created_at", "created_at"),
        db.Index("ix_posts_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    image_filename = db.Column(db.String(40), nullable=False)
    caption = db.Column(db.String(2200), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    user = db.relationship("User", back_populates="posts")
    likes = db.relationship("Like", back_populates="post", cascade="all, delete-orphan")
    comments = db.relationship(
        "Comment",
        back_populates="post",
        cascade="all, delete-orphan",
        order_by="Comment.created_at, Comment.id"
    )
    saved_by_users = db.relationship("SavedPost", back_populates="post", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="post", cascade="all, delete-orphan")


class Like(db.Model):
    __tablename__ = "likes"
    __table_args__ = (
        db.UniqueConstraint("user_id", "post_id", name="uq_likes_user_post"),
        db.Index("ix_likes_post_id", "post_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    user = db.relationship("User", back_populates="likes")
    post = db.relationship("Post", back_populates="likes")


class Comment(db.Model):
    __tablename__ = "comments"
    __table_args__ = (
        db.Index("ix_comments_post_created", "post_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    user = db.relationship("User", back_populates="comments")
    post = db.relationship("Post", back_populates="comments")


class Follow(db.Model):
    __tablename__ = "follows"
    __table_args__ = (
        db.UniqueConstraint("follower_id", "following_id", name="uq_follows_follower_following"),
        db.CheckConstraint("follower_id != following_id", name="ck_follows_not_self"),
        db.Index("ix_follows_following_id", "following_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    follower = db.relationship(
        "User", foreign_keys=[follower_id], back_populates="following"
    )
    following = db.relationship(
        "User", foreign_keys=[following_id], back_populates="followers"
    )


class SavedPost(db.Model):
    __tablename__ = "saved_posts"
    __table_args__ = (
        db.UniqueConstraint("user_id", "post_id", name="uq_saved_posts_user_post"),
        db.Index("ix_saved_posts_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    user = db.relationship("User", back_populates="saved_posts")
    post = db.relationship("Post", back_populates="saved_by_users")


class Reel(db.Model):
    __tablename__ = "reels"
    __table_args__ = (
        db.Index("ix_reels_created_at", "created_at"),
        db.Index("ix_reels_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    video_filename = db.Column(db.String(40), nullable=False, unique=True)
    caption = db.Column(db.String(2200), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    user = db.relationship("User", back_populates="reels")
    likes = db.relationship("ReelLike", back_populates="reel", cascade="all, delete-orphan")
    comments = db.relationship(
        "ReelComment", back_populates="reel", cascade="all, delete-orphan",
        order_by="ReelComment.created_at, ReelComment.id"
    )
    saved_by_users = db.relationship("SavedReel", back_populates="reel", cascade="all, delete-orphan")


class ReelLike(db.Model):
    __tablename__ = "reel_likes"
    __table_args__ = (
        db.UniqueConstraint("user_id", "reel_id", name="uq_reel_likes_user_reel"),
        db.Index("ix_reel_likes_reel_id", "reel_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey("reels.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    user = db.relationship("User", back_populates="reel_likes")
    reel = db.relationship("Reel", back_populates="likes")


class ReelComment(db.Model):
    __tablename__ = "reel_comments"
    __table_args__ = (db.Index("ix_reel_comments_reel_created", "reel_id", "created_at"),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey("reels.id", ondelete="CASCADE"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    user = db.relationship("User", back_populates="reel_comments")
    reel = db.relationship("Reel", back_populates="comments")


class SavedReel(db.Model):
    __tablename__ = "saved_reels"
    __table_args__ = (
        db.UniqueConstraint("user_id", "reel_id", name="uq_saved_reels_user_reel"),
        db.Index("ix_saved_reels_user_created", "user_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey("reels.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    user = db.relationship("User", back_populates="saved_reels")
    reel = db.relationship("Reel", back_populates="saved_by_users")


class Notification(db.Model):
    __tablename__ = "notifications"
    __table_args__ = (
        db.Index("ix_notifications_recipient_created", "recipient_id", "created_at"),
        db.Index("ix_notifications_recipient_unread", "recipient_id", "is_read"),
    )

    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    notification_type = db.Column(db.String(30), nullable=False)  # 'like', 'comment', 'follow'
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), nullable=True)
    content = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    recipient = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_notifications")
    sender = db.relationship("User", foreign_keys=[sender_id], back_populates="sent_notifications")
    post = db.relationship("Post", back_populates="notifications")


class Conversation(db.Model):
    __tablename__ = "conversations"
    __table_args__ = (
        db.UniqueConstraint("user1_id", "user2_id", name="uq_conversations_user1_user2"),
        db.Index("ix_conversations_user1", "user1_id"),
        db.Index("ix_conversations_user2", "user2_id"),
        db.Index("ix_conversations_updated", "updated_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp()
    )

    user1 = db.relationship("User", foreign_keys=[user1_id])
    user2 = db.relationship("User", foreign_keys=[user2_id])
    messages = db.relationship(
        "Message",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="Message.created_at.asc()"
    )

    def get_other_user(self, current_user_id):
        """Helper to get the other participant in the conversation."""
        if self.user1_id == current_user_id:
            return self.user2
        return self.user1

    def get_last_message(self):
        """Helper to get the most recent message in the conversation."""
        return (
            Message.query.filter_by(conversation_id=self.id)
            .order_by(Message.created_at.desc(), Message.id.desc())
            .first()
        )

    def get_unread_count(self, user_id):
        """Count unread messages sent to user_id in this conversation."""
        return Message.query.filter(
            Message.conversation_id == self.id,
            Message.sender_id != user_id,
            Message.is_read == False
        ).count()


class Message(db.Model):
    __tablename__ = "messages"
    __table_args__ = (
        db.Index("ix_messages_conv_created", "conversation_id", "created_at"),
        db.Index("ix_messages_sender", "sender_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    content = db.Column(db.String(2000), nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())

    conversation = db.relationship("Conversation", back_populates="messages")
    sender = db.relationship("User", foreign_keys=[sender_id])


def get_or_create_conversation(user_a_id, user_b_id):
    """Retrieve existing conversation or create a new one between two users."""
    if not user_a_id or not user_b_id or user_a_id == user_b_id:
        return None
    u1, u2 = sorted([user_a_id, user_b_id])
    conv = Conversation.query.filter_by(user1_id=u1, user2_id=u2).first()
    if not conv:
        conv = Conversation(user1_id=u1, user2_id=u2)
        db.session.add(conv)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            conv = Conversation.query.filter_by(user1_id=u1, user2_id=u2).first()
    return conv


def create_notification(recipient_id, sender_id, notification_type, post_id=None, content=None):
    """Helper to safely create a notification and prevent users from receiving notifications for self-actions."""
    if not recipient_id or not sender_id or recipient_id == sender_id:
        return None

    if notification_type in ("like", "follow"):
        existing = Notification.query.filter_by(
            recipient_id=recipient_id,
            sender_id=sender_id,
            notification_type=notification_type,
            post_id=post_id
        ).first()
        if existing:
            existing.is_read = False
            existing.created_at = db.func.current_timestamp()
            return existing

    notif = Notification(
        recipient_id=recipient_id,
        sender_id=sender_id,
        notification_type=notification_type,
        post_id=post_id,
        content=content
    )
    db.session.add(notif)
    return notif


def get_saved_post_ids(posts, user_id):
    """Return a set of post IDs saved by the user."""
    if not posts or not user_id:
        return set()
    post_ids = [p.id for p in posts]
    rows = db.session.query(SavedPost.post_id).filter(
        SavedPost.user_id == user_id,
        SavedPost.post_id.in_(post_ids)
    ).all()
    return {r[0] for r in rows}


def get_like_data(posts, user_id):
    """Return database like totals and liked post IDs for a rendered page."""
    post_ids = [post.id for post in posts]
    if not post_ids:
        return {}, set()
    counts = dict(
        db.session.query(Like.post_id, func.count(Like.id))
        .filter(Like.post_id.in_(post_ids))
        .group_by(Like.post_id)
        .all()
    )
    liked_ids = {
        row[0] for row in db.session.query(Like.post_id)
        .filter(Like.user_id == user_id, Like.post_id.in_(post_ids)).all()
    }
    return counts, liked_ids


def get_comment_data(posts):
    """Return comments and their totals for a set of posts."""
    post_ids = [post.id for post in posts]
    if not post_ids:
        return {}, {}

    comments_by_post = {post_id: [] for post_id in post_ids}
    comments = (
        Comment.query.join(Comment.user)
        .filter(Comment.post_id.in_(post_ids))
        .order_by(Comment.created_at, Comment.id)
        .all()
    )
    for comment in comments:
        comments_by_post[comment.post_id].append(comment)
    return comments_by_post, {
        post_id: len(post_comments)
        for post_id, post_comments in comments_by_post.items()
    }


def get_reel_like_data(reels, user_id):
    reel_ids = [reel.id for reel in reels]
    if not reel_ids:
        return {}, set()
    counts = dict(
        db.session.query(ReelLike.reel_id, func.count(ReelLike.id))
        .filter(ReelLike.reel_id.in_(reel_ids))
        .group_by(ReelLike.reel_id)
        .all()
    )
    liked_ids = {
        row[0] for row in db.session.query(ReelLike.reel_id)
        .filter(ReelLike.user_id == user_id, ReelLike.reel_id.in_(reel_ids)).all()
    }
    return counts, liked_ids


def get_reel_comment_data(reels):
    reel_ids = [reel.id for reel in reels]
    if not reel_ids:
        return {}, {}
    comments_by_reel = {reel_id: [] for reel_id in reel_ids}
    comments = (
        ReelComment.query.join(ReelComment.user)
        .filter(ReelComment.reel_id.in_(reel_ids))
        .order_by(ReelComment.created_at, ReelComment.id)
        .all()
    )
    for comment in comments:
        comments_by_reel[comment.reel_id].append(comment)
    return comments_by_reel, {
        reel_id: len(reel_comments)
        for reel_id, reel_comments in comments_by_reel.items()
    }


@app.context_processor
def inject_current_user():
    user_id = session.get("user_id")
    current_user = db.session.get(User, user_id) if user_id else None
    unread_notifications_count = 0
    unread_messages_count = 0
    if current_user:
        try:
            unread_notifications_count = Notification.query.filter_by(
                recipient_id=current_user.id, is_read=False
            ).count()
        except SQLAlchemyError:
            app.logger.exception("Unread notification counter query failed")
            db.session.rollback()
            unread_notifications_count = 0
        try:
            unread_messages_count = (
                Message.query.join(Conversation, Message.conversation_id == Conversation.id)
                .filter(
                    (Conversation.user1_id == current_user.id) | (Conversation.user2_id == current_user.id),
                    Message.sender_id != current_user.id,
                    Message.is_read == False
                )
                .count()
            )
        except SQLAlchemyError:
            app.logger.exception("Unread message counter query failed")
            db.session.rollback()
            unread_messages_count = 0
    return {
        "current_user": current_user,
        "unread_notifications_count": unread_notifications_count,
        "unread_messages_count": unread_messages_count
    }


# ==========================================
# 5. HOMEPAGE
# ==========================================

@app.route("/")
def home():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


def render_rate_limited_auth_form(template_name, retry_after, message):
    """Render an auth form with a clear 429 response and retry hint."""
    flash(message, "error")
    response = make_response(render_template(template_name), 429)
    response.headers["Retry-After"] = str(retry_after)
    response.headers["Cache-Control"] = "no-store"
    return response


# ==========================================
# 6. USER REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        retry_after = auth_rate_limit_retry_after(
            "register",
            app.config["REGISTER_RATE_LIMIT"],
            app.config["REGISTER_RATE_WINDOW_SECONDS"],
        )
        if retry_after:
            return render_rate_limited_auth_form(
                "register.html",
                retry_after,
                "Too many registration attempts. Please wait before trying again.",
            )

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        # Check required values and their database limits before querying or inserting.
        if not username or not email or not password:

            flash(
                "Please fill in all fields.",
                "error"
            )

            return redirect(url_for("register"))

        if not is_valid_username(username):
            flash(
                "Usernames may use letters, numbers, periods, underscores, and hyphens (up to 80 characters).",
                "error",
            )
            return redirect(url_for("register"))

        if len(email) > 120 or not is_valid_email(email):
            flash("Enter a valid email address (maximum 120 characters).", "error")
            return redirect(url_for("register"))

        # Bound new password work while retaining compatibility with existing accounts.
        if len(password) < 8 or len(password) > 128:

            flash(
                "Password must contain between 8 and 128 characters.",
                "error"
            )

            return redirect(url_for("register"))

        # Check whether the username already exists
        existing_username = User.query.filter(
            func.lower(User.username) == username.lower()
        ).first()

        if existing_username:

            flash(
                "This username is already taken.",
                "error"
            )

            return redirect(url_for("register"))

        # Check whether the email already exists
        existing_email = User.query.filter(
            func.lower(User.email) == email.lower()
        ).first()

        if existing_email:

            flash(
                "This email is already registered.",
                "error"
            )

            return redirect(url_for("register"))

        # Store only a one-way password hash.
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )

        # Save the user to MySQL
        try:

            db.session.add(new_user)

            db.session.commit()

        except Exception:

            db.session.rollback()

            app.logger.exception("Registration failed")

            flash(
                "Registration failed. Please try again.",
                "error"
            )

            return redirect(url_for("register"))

        # Clear any previous login session
        session.clear()

        # Display the success message
        flash(
            "Account created successfully! Please log in.",
            "success"
        )

        # Registration always redirects to login
        return redirect(url_for("login"))

    response = make_response(render_template("register.html"))
    response.headers["Cache-Control"] = "no-store"
    return response


# ==========================================
# 7. USER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        retry_after = auth_rate_limit_retry_after(
            "login",
            app.config["LOGIN_RATE_LIMIT"],
            app.config["LOGIN_RATE_WINDOW_SECONDS"],
        )
        if retry_after:
            return render_rate_limited_auth_form(
                "login.html",
                retry_after,
                "Too many login attempts. Please wait before trying again.",
            )

        identifier = request.form.get(
            "email", ""
        ).strip()

        password = request.form.get("password", "")

        # Find the user using the entered email or username
        user = User.query.filter(
            (func.lower(User.email) == identifier.lower()) |
            (func.lower(User.username) == identifier.lower())
        ).first()

        stored_password = user.password if user else ""
        is_werkzeug_hash = is_werkzeug_password_hash(stored_password)
        if is_werkzeug_hash:
            try:
                password_matches = check_password_hash(stored_password, password)
            except (TypeError, ValueError):
                password_matches = False
        else:
            # Existing accounts used plaintext. Compare safely, then upgrade after
            # successful authentication so no user's password or account is lost.
            password_matches = bool(user) and hmac.compare_digest(
                stored_password.encode("utf-8"), password.encode("utf-8")
            )

        if user and password_matches:
            if not is_werkzeug_hash:
                user.password = generate_password_hash(password)
                try:
                    db.session.commit()
                except SQLAlchemyError:
                    db.session.rollback()
                    app.logger.exception("Legacy password hash upgrade failed")

            # Clear any previous session
            session.clear()

            # Store the ID of the logged-in user
            session["user_id"] = user.id

            # Redirect to the dashboard
            return redirect(url_for("dashboard"))

        # Display an error if login fails
        flash(
            "Invalid email or password.",
            "error"
        )

        return redirect(url_for("login"))

    response = make_response(render_template("login.html"))
    response.headers["Cache-Control"] = "no-store"
    return response


# ==========================================
# 8. USER DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

     
    user_id = session.get("user_id")

    if not user_id:

        flash(
            "Please log in to continue.",
            "error"
        )

        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if not user:

        session.clear()

        flash(
            "Please log in again.",
            "error"
        )

        return redirect(url_for("login"))

    followed_user_ids = [
        f.following_id for f in Follow.query.filter_by(follower_id=user.id).all()
    ]
    visible_user_ids = [user.id] + followed_user_ids

    posts = (
        Post.query.join(User)
        .filter(Post.user_id.in_(visible_user_ids))
        .order_by(Post.created_at.desc(), Post.id.desc())
        .all()
    )
    like_counts, liked_post_ids = get_like_data(posts, user.id)
    comments_by_post, comment_counts = get_comment_data(posts)
    following_ids = set(followed_user_ids)
    saved_post_ids = get_saved_post_ids(posts, user.id)

    return render_template(
        "dashboard.html",
        user=user,
        posts=posts,
        like_counts=like_counts,
        liked_post_ids=liked_post_ids,
        comments_by_post=comments_by_post,
        comment_counts=comment_counts,
        following_ids=following_ids,
        saved_post_ids=saved_post_ids
    )


# ==========================================
# 9. SEARCH USERS
# ==========================================

@app.route("/search")
def search():

    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)

    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip()

    if query:
        users = (
            User.query.filter(
                (func.lower(User.username).like(f"%{query.lower()}%")) |
                (func.lower(User.display_name).like(f"%{query.lower()}%"))
            )
            .order_by(User.username)
            .all()
        )
    else:
        users = (
            User.query.filter(User.id != viewer.id)
            .order_by(User.username)
            .limit(30)
            .all()
        )

    following_ids = {
        f.following_id for f in Follow.query.filter_by(follower_id=viewer.id).all()
    }

    return render_template(
        "search.html",
        user=viewer,
        users=users,
        query=query,
        following_ids=following_ids
    )


# ==========================================
# 10. USER PROFILE
# ==========================================

@app.route("/profile")
@app.route("/users/<username>")
def profile(username=None):

    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first_or_404() if username else viewer
    posts = user.posts
    active_tab = request.args.get("tab", "posts")
    if active_tab not in {"posts", "reels"}:
        active_tab = "posts"
    user_reels = user.reels if active_tab == "reels" else []
    like_counts, liked_post_ids = get_like_data(posts, viewer.id)
    comments_by_post, comment_counts = get_comment_data(posts)
    saved_post_ids = get_saved_post_ids(posts, viewer.id)
    return render_template(
        "profile.html",
        user=user,
        viewer=viewer,
        is_own_profile=(user.id == viewer.id),
        active_tab=active_tab,
        posts=posts,
        profile_reels=user_reels,
        post_count=len(posts),
        like_counts=like_counts,
        liked_post_ids=liked_post_ids,
        comments_by_post=comments_by_post,
        comment_counts=comment_counts,
        saved_post_ids=saved_post_ids,
        followers_count=Follow.query.filter_by(following_id=user.id).count(),
        following_count=Follow.query.filter_by(follower_id=user.id).count(),
        is_following=Follow.query.filter_by(
            follower_id=viewer.id, following_id=user.id
        ).first() is not None
    )


@app.route("/reels")
def reels_feed():
    user_id = session.get("user_id")
    viewer = db.session.get(User, user_id) if user_id else None
    if not viewer:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    following_ids = {
        row.following_id for row in Follow.query.filter_by(follower_id=viewer.id).all()
    }
    reels = Reel.query.order_by(Reel.created_at.desc(), Reel.id.desc()).all()
    if following_ids:
        reels.sort(key=lambda reel: (reel.user_id not in following_ids, -reel.id))

    like_counts, liked_reel_ids = get_reel_like_data(reels, viewer.id)
    comments_by_reel, comment_counts = get_reel_comment_data(reels)
    saved_reel_ids = {
        row[0] for row in db.session.query(SavedReel.reel_id)
        .filter(SavedReel.user_id == viewer.id).all()
    }
    return render_template(
        "reels.html",
        user=viewer,
        reels=reels,
        following_ids=following_ids,
        like_counts=like_counts,
        liked_reel_ids=liked_reel_ids,
        comments_by_reel=comments_by_reel,
        comment_counts=comment_counts,
        saved_reel_ids=saved_reel_ids,
    )


@app.route("/reels/upload", methods=["GET", "POST"])
def upload_reel():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        flash("Please log in to upload a Reel.", "error")
        return redirect(url_for("login"))

    caption = ""
    if request.method == "POST":
        caption = request.form.get("caption", "").strip()
        upload = request.files.get("video")
        if len(caption) > 2200:
            flash("Captions can be up to 2,200 characters.", "error")
        elif not upload or not upload.filename:
            flash("Choose an MP4 or WebM video to upload.", "error")
        else:
            extension, upload_error = validate_reel_upload(upload)
            if upload_error:
                flash(upload_error, "error")
            else:
                filename = f"{uuid.uuid4().hex}{extension}"
                video_path = os.path.join(app.config["REEL_FOLDER"], filename)
                try:
                    upload.save(video_path)
                    reel = Reel(user_id=user.id, video_filename=filename, caption=caption)
                    db.session.add(reel)
                    db.session.commit()
                except (OSError, SQLAlchemyError):
                    db.session.rollback()
                    app.logger.exception("Reel upload failed")
                    remove_file_safely(video_path, "Partial Reel upload cleanup failed")
                    flash("Your Reel could not be saved. Please try again.", "error")
                else:
                    flash("Your Reel has been uploaded.", "success")
                    return redirect(url_for("reels_feed"))

    return render_template("upload_reel.html", user=user, caption=caption)


@app.route("/uploads/reels/<filename>")
def uploaded_reel_video(filename):
    if not is_safe_reel_filename(filename):
        return "Not found", 404
    if not os.path.isfile(os.path.join(app.config["REEL_FOLDER"], filename)):
        return "Not found", 404
    response = send_from_directory(app.config["REEL_FOLDER"], filename, conditional=True)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/reels/<int:reel_id>/like", methods=["POST"])
def like_reel(reel_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to like Reels."), 401
    reel = db.session.get(Reel, reel_id)
    if not reel:
        return jsonify(error="Reel not found."), 404
    if not ReelLike.query.filter_by(user_id=user_id, reel_id=reel_id).first():
        db.session.add(ReelLike(user_id=user_id, reel_id=reel_id))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            if not ReelLike.query.filter_by(user_id=user_id, reel_id=reel_id).first():
                return jsonify(error="Your like could not be saved."), 500
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Reel like failed")
            return jsonify(error="Your like could not be saved."), 500
    return jsonify(
        liked=True,
        like_count=ReelLike.query.filter_by(reel_id=reel_id).count(),
    )


@app.route("/reels/<int:reel_id>/unlike", methods=["POST"])
def unlike_reel(reel_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to unlike Reels."), 401
    reel = db.session.get(Reel, reel_id)
    if not reel:
        return jsonify(error="Reel not found."), 404
    like = ReelLike.query.filter_by(user_id=user_id, reel_id=reel_id).first()
    if like:
        db.session.delete(like)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Reel unlike failed")
            return jsonify(error="Your like could not be removed."), 500
    return jsonify(liked=False, like_count=ReelLike.query.filter_by(reel_id=reel_id).count())


@app.route("/reels/<int:reel_id>/comments", methods=["POST"])
def add_reel_comment(reel_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to comment."), 401
    reel = db.session.get(Reel, reel_id)
    if not reel:
        return jsonify(error="Reel not found."), 404
    payload = request.get_json(silent=True)
    content = payload.get("content", "") if isinstance(payload, dict) else ""
    if not isinstance(content, str) or not content.strip():
        return jsonify(error="Comments cannot be empty."), 400
    content = content.strip()
    if len(content) > 500:
        return jsonify(error="Comments can be up to 500 characters."), 400
    comment = ReelComment(user_id=user.id, reel_id=reel.id, content=content)
    db.session.add(comment)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Reel comment creation failed")
        return jsonify(error="Your comment could not be saved."), 500
    return jsonify(
        id=comment.id,
        username=user.username,
        content=comment.content,
        created_at=comment.created_at.strftime("%b %d, %Y · %I:%M %p"),
        delete_url=url_for("delete_reel_comment", comment_id=comment.id),
        comment_count=ReelComment.query.filter_by(reel_id=reel.id).count(),
    ), 201


@app.route("/reel-comments/<int:comment_id>/delete", methods=["POST"])
def delete_reel_comment(comment_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to delete comments."), 401
    comment = db.session.get(ReelComment, comment_id)
    if not comment:
        return jsonify(error="Comment not found."), 404
    if comment.user_id != user_id:
        return jsonify(error="You can only delete your own comments."), 403
    reel_id = comment.reel_id
    db.session.delete(comment)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Reel comment deletion failed")
        return jsonify(error="Your comment could not be deleted."), 500
    return jsonify(
        deleted=True,
        comment_count=ReelComment.query.filter_by(reel_id=reel_id).count(),
    )


@app.route("/reels/<int:reel_id>/save", methods=["POST"])
def toggle_save_reel(reel_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to save Reels."), 401
    reel = db.session.get(Reel, reel_id)
    if not reel:
        return jsonify(error="Reel not found."), 404
    saved = SavedReel.query.filter_by(user_id=user.id, reel_id=reel.id).first()
    is_saved = saved is None
    if saved:
        db.session.delete(saved)
    else:
        db.session.add(SavedReel(user_id=user.id, reel_id=reel.id))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        is_saved = SavedReel.query.filter_by(user_id=user.id, reel_id=reel.id).first() is not None
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Saved Reel update failed")
        return jsonify(error="Could not update saved status."), 500
    return jsonify(success=True, saved=is_saved, reel_id=reel.id)


@app.route("/reels/<int:reel_id>/delete", methods=["POST"])
def delete_reel(reel_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to delete Reels."), 401
    reel = Reel.query.filter_by(id=reel_id, user_id=user.id).first_or_404()
    filename = reel.video_filename
    video_path = os.path.join(app.config["REEL_FOLDER"], filename)
    db.session.delete(reel)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Reel deletion failed")
        return jsonify(error="The Reel could not be deleted."), 500
    media_removed = is_safe_reel_filename(filename) and remove_file_safely(
        video_path, "Deleted Reel media cleanup failed"
    )
    if not media_removed:
        app.logger.error("Reel row %s was deleted but its media needs cleanup", reel_id)
        flash("Your Reel was deleted, but its video file could not be removed.", "warning")
    else:
        flash("Your Reel has been deleted.", "success")
    return redirect(url_for("reels_feed"))


@app.route("/posts/<int:post_id>/like", methods=["POST"])
def toggle_like(post_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to like posts."), 401

    post = db.session.get(Post, post_id)
    if not post:
        return jsonify(error="Post not found."), 404

    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if not existing_like:
        db.session.add(Like(user_id=user_id, post_id=post_id))
        try:
            create_notification(post.user_id, user_id, "like", post_id=post.id)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            if not Like.query.filter_by(user_id=user_id, post_id=post_id).first():
                app.logger.exception("Like insert failed unexpectedly")
                return jsonify(error="Your like could not be saved. Please try again."), 500
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Like update failed")
            return jsonify(error="Your like could not be saved. Please try again."), 500

    liked = Like.query.filter_by(user_id=user_id, post_id=post_id).first() is not None
    like_count = Like.query.filter_by(post_id=post_id).count()
    return jsonify(liked=liked, like_count=like_count)


@app.route("/posts/<int:post_id>/unlike", methods=["POST"])
def unlike_post(post_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to unlike posts."), 401
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify(error="Post not found."), 404

    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if existing_like:
        db.session.delete(existing_like)
        try:
            Notification.query.filter_by(
                recipient_id=post.user_id,
                sender_id=user_id,
                notification_type="like",
                post_id=post.id
            ).delete()
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Unlike failed")
            return jsonify(error="Your like could not be removed. Please try again."), 500

    return jsonify(
        liked=False,
        like_count=Like.query.filter_by(post_id=post_id).count()
    )


@app.route("/posts/<int:post_id>/comments", methods=["POST"])
def add_comment(post_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to comment."), 401

    post = db.session.get(Post, post_id)
    if not post:
        return jsonify(error="Post not found."), 404

    payload = request.get_json(silent=True)
    content = payload.get("content", "") if isinstance(payload, dict) else ""
    if not isinstance(content, str):
        return jsonify(error="Comments must be text."), 400
    content = content.strip()
    if not content:
        return jsonify(error="Comments cannot be empty."), 400
    if len(content) > 500:
        return jsonify(error="Comments can be up to 500 characters."), 400

    comment = Comment(user_id=user.id, post_id=post.id, content=content)
    db.session.add(comment)
    try:
        create_notification(
            post.user_id, user.id, "comment", post_id=post.id, content=content[:100]
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Comment creation failed")
        return jsonify(error="Your comment could not be saved. Please try again."), 500

    return jsonify(
        id=comment.id,
        username=user.username,
        content=comment.content,
        created_at=comment.created_at.strftime("%b %d, %Y · %I:%M %p"),
        delete_url=url_for("delete_comment", comment_id=comment.id),
        comment_count=Comment.query.filter_by(post_id=post.id).count()
    ), 201


@app.route("/comments/<int:comment_id>/delete", methods=["POST"])
def delete_comment(comment_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to delete comments."), 401

    comment = db.session.get(Comment, comment_id)
    if not comment:
        return jsonify(error="Comment not found."), 404
    if comment.user_id != user_id:
        return jsonify(error="You can only delete your own comments."), 403

    post_id = comment.post_id
    db.session.delete(comment)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Comment deletion failed")
        return jsonify(error="Your comment could not be deleted. Please try again."), 500

    return jsonify(
        deleted=True,
        comment_count=Comment.query.filter_by(post_id=post_id).count()
    )


def update_follow(target_id, should_follow):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to follow users."), 401
    target = db.session.get(User, target_id)
    if not target:
        return jsonify(error="User not found."), 404
    if user.id == target.id:
        return jsonify(error="You cannot follow yourself."), 400

    follow = Follow.query.filter_by(
        follower_id=user.id, following_id=target.id
    ).first()
    if should_follow and not follow:
        db.session.add(Follow(follower_id=user.id, following_id=target.id))
    elif not should_follow and follow:
        db.session.delete(follow)

    try:
        if should_follow and not follow:
            create_notification(target.id, user.id, "follow")
        elif not should_follow and follow:
            Notification.query.filter_by(
                recipient_id=target.id,
                sender_id=user.id,
                notification_type="follow"
            ).delete()
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        is_following = Follow.query.filter_by(
            follower_id=user.id, following_id=target.id
        ).first() is not None
        if is_following != should_follow:
            app.logger.exception("Follow update failed unexpectedly")
            return jsonify(error="The follow could not be updated. Please try again."), 500
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Follow update failed")
        return jsonify(error="The follow could not be updated. Please try again."), 500

    is_following = Follow.query.filter_by(
        follower_id=user.id, following_id=target.id
    ).first() is not None

    followers_count = Follow.query.filter_by(following_id=target.id).count()
    following_count = Follow.query.filter_by(follower_id=user.id).count()
    target_following_count = Follow.query.filter_by(follower_id=target.id).count()

    if request.content_type == "application/x-www-form-urlencoded":
        flash(f"You are now following {target.username}." if is_following else f"You unfollowed {target.username}.", "success")
        return redirect(safe_referrer_path(
            request.referrer, url_for("profile", username=target.username)
        ))

    return jsonify(
        success=True,
        following=is_following,
        followers_count=followers_count,
        following_count=following_count,
        target_following_count=target_following_count,
        target_id=target.id
    )


@app.route("/follow/<int:user_id>", methods=["POST"])
@app.route("/users/<int:user_id>/follow", methods=["POST"])
def follow_user(user_id):
    return update_follow(user_id, True)


@app.route("/unfollow/<int:user_id>", methods=["POST"])
@app.route("/users/<int:user_id>/unfollow", methods=["POST"])
def unfollow_user(user_id):
    return update_follow(user_id, False)


def render_follow_list(username, list_type):
    viewer_id = session.get("user_id")
    if not viewer_id or not db.session.get(User, viewer_id):
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))
    profile_user = User.query.filter_by(username=username).first_or_404()

    if list_type == "followers":
        accounts = (
            User.query.join(Follow, Follow.follower_id == User.id)
            .filter(Follow.following_id == profile_user.id)
            .order_by(User.username)
            .all()
        )
    else:
        accounts = (
            User.query.join(Follow, Follow.following_id == User.id)
            .filter(Follow.follower_id == profile_user.id)
            .order_by(User.username)
            .all()
        )
    following_ids = {
        f.following_id for f in Follow.query.filter_by(follower_id=viewer_id).all()
    }
    return render_template(
        "follow_list.html",
        profile_user=profile_user,
        accounts=accounts,
        list_type=list_type,
        following_ids=following_ids
    )


@app.route("/users/<username>/followers")
def user_followers(username):
    return render_follow_list(username, "followers")


@app.route("/users/<username>/following")
def user_following(username):
    return render_follow_list(username, "following")


@app.route("/create-post", methods=["GET", "POST"])
def create_post():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        session.clear()
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        image_file = request.files.get("image")
        caption = request.form.get("caption", "")
        if not image_file or not image_file.filename:
            flash("Choose an image before sharing.", "error")
            return render_template("create_post.html", user=user, caption=caption)
        if len(caption) > 2200:
            flash("Captions can be up to 2,200 characters.", "error")
            return render_template("create_post.html", user=user, caption=caption)

        extension = os.path.splitext(image_file.filename)[1].lower()
        formats = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".webp": "WEBP"}
        upload_error = None
        if extension not in formats:
            upload_error = "Choose a JPG, JPEG, PNG, or WEBP image."
        else:
            try:
                image_file.stream.seek(0, os.SEEK_END)
                file_size = image_file.stream.tell()
                image_file.stream.seek(0)
                if file_size > app.config["POST_MAX_FILE_SIZE"]:
                    upload_error = "The image must be no larger than 5 MB."
                else:
                    image = Image.open(image_file.stream)
                    if image.format != formats[extension]:
                        upload_error = "The file contents do not match its image extension."
                    elif image.width * image.height > 40_000_000:
                        upload_error = "The image dimensions are too large."
                    else:
                        image.verify()
                        image_file.stream.seek(0)
            except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
                upload_error = "The uploaded file is not a valid image."

        if upload_error:
            flash(upload_error, "error")
            return render_template("create_post.html", user=user, caption=caption)

        filename = f"{uuid.uuid4().hex}{extension}"
        image_path = os.path.join(app.config["POST_IMAGE_FOLDER"], filename)
        post = Post(user_id=user.id, image_filename=filename, caption=caption)
        try:
            os.makedirs(app.config["POST_IMAGE_FOLDER"], exist_ok=True)
            image_file.save(image_path)
            db.session.add(post)
            db.session.commit()
        except (OSError, SQLAlchemyError):
            db.session.rollback()
            app.logger.exception("Post creation failed")
            remove_file_safely(image_path, "Partial post upload cleanup failed")
            flash("Your post could not be saved. Please try again.", "error")
            return render_template("create_post.html", user=user, caption=caption)
        flash("Your post has been shared.", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_post.html", user=user, caption="")


@app.route("/uploads/posts/<filename>")
def uploaded_post_image(filename):
    if not is_safe_image_filename(filename, ("jpg", "jpeg", "png", "webp")):
        return _serve_fallback_post_image()
    file_path = os.path.join(app.config["POST_IMAGE_FOLDER"], filename)
    if not os.path.isfile(file_path):
        return _serve_fallback_post_image()
    response = send_from_directory(app.config["POST_IMAGE_FOLDER"], filename)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))
    post = Post.query.filter_by(id=post_id, user_id=user.id).first_or_404()
    deleted_post_id = post.id
    image_path = None
    if is_safe_image_filename(post.image_filename):
        image_path = os.path.join(app.config["POST_IMAGE_FOLDER"], post.image_filename)
    else:
        app.logger.error("Refused to remove unsafe image path for post %s", post.id)
    db.session.delete(post)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Post deletion failed")
        flash("The post could not be deleted. Please try again.", "error")
    else:
        media_removed = image_path is not None and remove_file_safely(
            image_path, "Deleted post image cleanup failed"
        )
        if not media_removed:
            app.logger.error(
                "Post row %s was deleted but its image needs cleanup", deleted_post_id
            )
            flash("Your post was deleted, but its image file could not be removed.", "warning")
        else:
            flash("Your post has been deleted.", "success")
    return redirect(safe_referrer_path(request.referrer, url_for("dashboard")))


# ==========================================
# EXPLORE PAGE
# ==========================================

@app.route("/explore")
def explore():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    posts = (
        Post.query.join(User)
        .order_by(Post.created_at.desc(), Post.id.desc())
        .all()
    )
    like_counts, liked_post_ids = get_like_data(posts, viewer.id)
    _, comment_counts = get_comment_data(posts)
    saved_post_ids = get_saved_post_ids(posts, viewer.id)

    return render_template(
        "explore.html",
        user=viewer,
        posts=posts,
        like_counts=like_counts,
        comment_counts=comment_counts,
        saved_post_ids=saved_post_ids
    )


# ==========================================
# POST DETAIL (FULL VIEW)
# ==========================================

@app.route("/posts/<int:post_id>")
def post_detail(post_id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    post = db.session.get(Post, post_id)
    if not post:
        flash("Post not found.", "error")
        return redirect(url_for("dashboard"))

    like_counts, liked_post_ids = get_like_data([post], viewer.id)
    comments_by_post, comment_counts = get_comment_data([post])
    saved_post_ids = get_saved_post_ids([post], viewer.id)

    following_ids = {
        f.following_id for f in Follow.query.filter_by(follower_id=viewer.id).all()
    }

    return render_template(
        "post_detail.html",
        user=viewer,
        post=post,
        like_counts=like_counts,
        liked_post_ids=liked_post_ids,
        comments_by_post=comments_by_post,
        comment_counts=comment_counts,
        saved_post_ids=saved_post_ids,
        following_ids=following_ids
    )


# ==========================================
# SAVED POSTS (SAVE / UNSAVE)
# ==========================================

@app.route("/posts/<int:post_id>/save", methods=["POST"])
def toggle_save_post(post_id):
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user:
        return jsonify(error="Please log in to save posts."), 401

    post = db.session.get(Post, post_id)
    if not post:
        return jsonify(error="Post not found."), 404

    saved_record = SavedPost.query.filter_by(user_id=user.id, post_id=post.id).first()
    if saved_record:
        db.session.delete(saved_record)
        is_saved = False
    else:
        db.session.add(SavedPost(user_id=user.id, post_id=post.id))
        is_saved = True

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        is_saved = SavedPost.query.filter_by(user_id=user.id, post_id=post.id).first() is not None
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Save post toggle failed")
        return jsonify(error="Could not update saved status. Please try again."), 500

    return jsonify(
        success=True,
        saved=is_saved,
        post_id=post.id
    )


@app.route("/saved")
@app.route("/saved-posts")
def saved_posts():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    saved_type = request.args.get("type", "posts")
    if saved_type not in {"posts", "reels"}:
        saved_type = "posts"
    posts = []
    reels = []
    if saved_type == "reels":
        reels = (
            Reel.query.join(SavedReel, SavedReel.reel_id == Reel.id)
            .filter(SavedReel.user_id == viewer.id)
            .order_by(SavedReel.created_at.desc(), Reel.id.desc())
            .all()
        )
    else:
        posts = (
            Post.query.join(SavedPost, SavedPost.post_id == Post.id)
            .filter(SavedPost.user_id == viewer.id)
            .order_by(SavedPost.created_at.desc())
            .all()
        )
    like_counts, liked_post_ids = get_like_data(posts, viewer.id)
    _, comment_counts = get_comment_data(posts)
    saved_post_ids = {post.id for post in posts}
    reel_like_counts, _ = get_reel_like_data(reels, viewer.id)
    _, reel_comment_counts = get_reel_comment_data(reels)

    return render_template(
        "saved_posts.html",
        user=viewer,
        saved_type=saved_type,
        posts=posts,
        reels=reels,
        like_counts=like_counts,
        comment_counts=comment_counts,
        saved_post_ids=saved_post_ids,
        reel_like_counts=reel_like_counts,
        reel_comment_counts=reel_comment_counts,
    )


# ==========================================
# NOTIFICATIONS
# ==========================================

@app.route("/notifications")
def notifications():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    user_notifications = (
        Notification.query.filter_by(recipient_id=viewer.id)
        .order_by(Notification.created_at.desc())
        .limit(60)
        .all()
    )

    following_ids = {
        f.following_id for f in Follow.query.filter_by(follower_id=viewer.id).all()
    }

    return render_template(
        "notifications.html",
        user=viewer,
        notifications=user_notifications,
        following_ids=following_ids
    )


@app.route("/notifications/mark-read", methods=["POST"])
@app.route("/notifications/read-all", methods=["POST"])
def mark_all_notifications_read():
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in."), 401

    try:
        Notification.query.filter_by(recipient_id=user_id, is_read=False).update(
            {"is_read": True}
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Mark all notifications read failed")
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify(error="Notifications could not be marked as read."), 500
        flash("Notifications could not be marked as read. Please try again.", "error")
        return redirect(url_for("notifications"))

    if request.is_json or "application/json" in request.headers.get("Accept", ""):
        return jsonify(success=True, unread_count=0)
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications"))


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
def mark_single_notification_read(notification_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in."), 401

    notif = db.session.get(Notification, notification_id)
    if not notif or notif.recipient_id != user_id:
        return jsonify(error="Notification not found."), 404

    try:
        notif.is_read = True
        db.session.commit()
        unread_count = Notification.query.filter_by(
            recipient_id=user_id, is_read=False
        ).count()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Mark notification read failed")
        return jsonify(error="Notification could not be marked as read."), 500
    return jsonify(success=True, unread_count=unread_count)


# ==========================================
# DIRECT MESSAGES
# ==========================================

@app.route("/messages")
@app.route("/direct")
def messages():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    user_conversations = (
        Conversation.query.filter(
            (Conversation.user1_id == viewer.id) | (Conversation.user2_id == viewer.id)
        )
        .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
        .all()
    )

    available_users = (
        User.query.filter(User.id != viewer.id)
        .order_by(User.username.asc())
        .all()
    )

    return render_template(
        "messages.html",
        user=viewer,
        conversations=user_conversations,
        active_conversation=None,
        active_messages=[],
        other_user=None,
        available_users=available_users
    )


@app.route("/messages/<int:conversation_id>")
def conversation_detail(conversation_id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    conv = db.session.get(Conversation, conversation_id)
    if not conv:
        flash("Conversation not found.", "error")
        return redirect(url_for("messages"))

    if conv.user1_id != viewer.id and conv.user2_id != viewer.id:
        flash("You do not have permission to view this conversation.", "error")
        return redirect(url_for("messages")), 403

    unread_messages = Message.query.filter(
        Message.conversation_id == conv.id,
        Message.sender_id != viewer.id,
        Message.is_read == False
    ).all()
    if unread_messages:
        for m in unread_messages:
            m.is_read = True
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

    user_conversations = (
        Conversation.query.filter(
            (Conversation.user1_id == viewer.id) | (Conversation.user2_id == viewer.id)
        )
        .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
        .all()
    )

    active_messages = (
        Message.query.filter_by(conversation_id=conv.id)
        .order_by(Message.created_at.asc(), Message.id.asc())
        .all()
    )

    available_users = (
        User.query.filter(User.id != viewer.id)
        .order_by(User.username.asc())
        .all()
    )

    other_user = conv.get_other_user(viewer.id)

    return render_template(
        "messages.html",
        user=viewer,
        conversations=user_conversations,
        active_conversation=conv,
        active_messages=active_messages,
        other_user=other_user,
        available_users=available_users
    )


@app.route("/messages/<int:conversation_id>/send", methods=["POST"])
def send_message(conversation_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Please log in to send messages."), 401

    conv = db.session.get(Conversation, conversation_id)
    if not conv:
        return jsonify(error="Conversation not found."), 404

    if conv.user1_id != user_id and conv.user2_id != user_id:
        return jsonify(error="You do not have permission to post in this conversation."), 403

    content = ""
    if request.is_json:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Message request must contain a JSON object."), 400
        content = payload.get("content", "")
    else:
        content = request.form.get("content", "")

    if not isinstance(content, str):
        return jsonify(error="Message content must be text."), 400
    content = content.strip()
    if not content:
        if request.is_json:
            return jsonify(error="Message cannot be empty."), 400
        flash("Message cannot be empty.", "error")
        return redirect(url_for("conversation_detail", conversation_id=conv.id))

    if len(content) > 2000:
        if request.is_json:
            return jsonify(error="Message cannot exceed 2,000 characters."), 400
        flash("Message cannot exceed 2,000 characters.", "error")
        return redirect(url_for("conversation_detail", conversation_id=conv.id))

    new_msg = Message(
        conversation_id=conv.id,
        sender_id=user_id,
        content=content
    )
    conv.updated_at = db.func.current_timestamp()
    db.session.add(new_msg)

    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Send message failed")
        if request.is_json:
            return jsonify(error="Failed to send message. Please try again."), 500
        flash("Failed to send message. Please try again.", "error")
        return redirect(url_for("conversation_detail", conversation_id=conv.id))

    if request.is_json:
        return jsonify(
            success=True,
            message={
                "id": new_msg.id,
                "content": new_msg.content,
                "sender_id": new_msg.sender_id,
                "sender_username": new_msg.sender.username,
                "created_at": new_msg.created_at.strftime("%b %d, %Y · %I:%M %p"),
                "is_own": True
            }
        ), 201

    return redirect(url_for("conversation_detail", conversation_id=conv.id))


@app.route("/messages/start/<username>", methods=["POST"])
def start_conversation_with_user(username):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    viewer = db.session.get(User, user_id)
    if not viewer:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    target_user = User.query.filter_by(username=username).first_or_404()
    if target_user.id == viewer.id:
        flash("You cannot start a direct message with yourself.", "error")
        return redirect(url_for("messages"))

    conv = get_or_create_conversation(viewer.id, target_user.id)
    return redirect(url_for("conversation_detail", conversation_id=conv.id))


@app.route("/messages/<int:conversation_id>/poll")
def poll_messages(conversation_id):
    user_id = session.get("user_id")
    if not user_id or not db.session.get(User, user_id):
        return jsonify(error="Unauthorized"), 401

    conv = db.session.get(Conversation, conversation_id)
    if not conv or (conv.user1_id != user_id and conv.user2_id != user_id):
        return jsonify(error="Forbidden"), 403

    after_id = request.args.get("after", 0, type=int)
    new_messages = (
        Message.query.filter(
            Message.conversation_id == conv.id,
            Message.id > after_id
        )
        .order_by(Message.created_at.asc(), Message.id.asc())
        .all()
    )

    result = []
    need_commit = False
    for m in new_messages:
        if m.sender_id != user_id and not m.is_read:
            m.is_read = True
            need_commit = True
        result.append({
            "id": m.id,
            "content": m.content,
            "sender_id": m.sender_id,
            "sender_username": m.sender.username,
            "created_at": m.created_at.strftime("%b %d, %Y · %I:%M %p"),
            "is_own": (m.sender_id == user_id)
        })

    if need_commit:
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

    return jsonify(messages=result)


# ==========================================
# 10. EDIT USER PROFILE
# ==========================================

@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    form_data = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        bio = request.form.get("bio", "").strip()
        email = request.form.get("email", "").strip().lower()
        profile_picture = request.files.get("profile_picture")

        form_data = {
            "username": username,
            "display_name": display_name,
            "bio": bio,
            "email": email
        }

        if (
            not username
            or len(username) > 80
            or (username != user.username and not is_valid_username(username))
        ):
            flash(
                "Username is required and may use letters, numbers, periods, underscores, and hyphens.",
                "error",
            )
        elif len(email) > 120 or not is_valid_email(email):
            flash("Enter a valid email address (maximum 120 characters).", "error")
        elif len(display_name) > 80:
            flash("Display name must be 80 characters or fewer.", "error")
        elif len(bio) > 150:
            flash("Bio must be 150 characters or fewer.", "error")
        else:
            duplicate_username = User.query.filter(
                func.lower(User.username) == username.lower(),
                User.id != user.id
            ).first()
            duplicate_email = User.query.filter(
                func.lower(User.email) == email.lower(),
                User.id != user.id
            ).first()

            if duplicate_username:
                flash("That username is already in use.", "error")
            elif duplicate_email:
                flash("That email address is already in use.", "error")
            else:
                new_picture_name = None
                upload_error = None

                if profile_picture and profile_picture.filename:
                    extension = os.path.splitext(profile_picture.filename)[1].lower()
                    image_formats = {
                        ".jpg": "JPEG",
                        ".jpeg": "JPEG",
                        ".png": "PNG"
                    }

                    if extension not in image_formats:
                        upload_error = "Choose a JPG, JPEG, or PNG image."
                    else:
                        try:
                            profile_picture.stream.seek(0, os.SEEK_END)
                            file_size = profile_picture.stream.tell()
                            profile_picture.stream.seek(0)
                            if file_size > app.config["POST_MAX_FILE_SIZE"]:
                                upload_error = "The profile picture must be no larger than 5 MB."
                            else:
                                image = Image.open(profile_picture.stream)
                                if image.format != image_formats[extension]:
                                    upload_error = "The file contents do not match its image extension."
                                elif image.width * image.height > 40_000_000:
                                    upload_error = "The image dimensions are too large."
                                else:
                                    image.verify()
                                    profile_picture.stream.seek(0)
                        except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
                            upload_error = "The uploaded file is not a valid image."

                    if not upload_error:
                        new_picture_name = f"{uuid.uuid4().hex}{extension}"
                        new_picture_path = os.path.join(
                            app.config["PROFILE_PICTURE_FOLDER"],
                            new_picture_name
                        )
                        try:
                            os.makedirs(
                                app.config["PROFILE_PICTURE_FOLDER"],
                                exist_ok=True
                            )
                            profile_picture.save(new_picture_path)
                        except OSError:
                            app.logger.exception("Profile picture upload failed")
                            remove_file_safely(
                                new_picture_path,
                                "Partial profile picture cleanup failed",
                            )
                            upload_error = "The profile picture could not be saved. Please try again."

                if upload_error:
                    flash(upload_error, "error")
                else:
                    old_picture_name = user.profile_picture
                    user.username = username
                    user.display_name = display_name or None
                    user.bio = bio or None
                    user.email = email

                    if new_picture_name:
                        user.profile_picture = new_picture_name

                    try:
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
                        if new_picture_name:
                            remove_file_safely(
                                os.path.join(
                                    app.config["PROFILE_PICTURE_FOLDER"],
                                    new_picture_name,
                                ),
                                "Unused profile picture cleanup failed",
                            )
                        flash("That username or email address is already in use.", "error")
                    except SQLAlchemyError:
                        db.session.rollback()
                        if new_picture_name:
                            remove_file_safely(
                                os.path.join(
                                    app.config["PROFILE_PICTURE_FOLDER"],
                                    new_picture_name,
                                ),
                                "Unused profile picture cleanup failed",
                            )
                        app.logger.exception("Profile update failed")
                        flash("Your profile could not be saved. Please try again.", "error")
                    else:
                        if new_picture_name and old_picture_name:
                            old_picture_path = os.path.join(
                                app.config["PROFILE_PICTURE_FOLDER"],
                                old_picture_name
                            )
                            if is_safe_image_filename(old_picture_name):
                                remove_file_safely(
                                    old_picture_path,
                                    "Replaced profile picture cleanup failed",
                                )
                            else:
                                app.logger.error(
                                    "Refused to remove unsafe old profile picture for user %s",
                                    user.id,
                                )
                        flash("Your profile has been updated.", "success")
                        return redirect(url_for("profile"))

        return render_template(
            "edit_profile.html",
            user=user,
            form_data=form_data
        )

    return render_template(
        "edit_profile.html",
        user=user,
        form_data=form_data
    )


@app.route("/uploads/profile_pictures/<filename>")
def uploaded_profile_picture(filename):
    if not is_safe_image_filename(filename, ("jpg", "jpeg", "png", "webp")):
        return _serve_fallback_profile_picture()

    file_path = os.path.join(app.config["PROFILE_PICTURE_FOLDER"], filename)
    if not os.path.isfile(file_path):
        return _serve_fallback_profile_picture()

    response = send_from_directory(
        app.config["PROFILE_PICTURE_FOLDER"],
        filename
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(413)
def request_entity_too_large(_error):
    flash(
        "Reels must be no larger than 100 MB." if request.path == "/reels/upload"
        else "The upload must be no larger than 5 MB.",
        "error"
    )
    if request.path == "/create-post":
        return redirect(url_for("create_post"))
    if request.path == "/reels/upload":
        return redirect(url_for("upload_reel"))
    if session.get("user_id"):
        return redirect(url_for("edit_profile"))
    return redirect(url_for("login"))


# ==========================================
# 11. USER LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
def logout():

    # Clear the current user's session
    session.clear()

    flash(
        "You have logged out successfully.",
        "success"
    )

    return redirect(url_for("login"))


# ==========================================
# 12. START THE APPLICATION
# ==========================================

if __name__ == "__main__":
    # Schema creation and migrations are explicit setup tasks, never startup side effects.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
    
