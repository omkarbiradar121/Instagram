"""Isolated Flask feature tests using a temporary SQLite database and uploads."""

import os
import re
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-only-secret-key"

from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash

from app import (
    Comment,
    Conversation,
    Follow,
    Like,
    Message,
    Notification,
    Post,
    Reel,
    ReelComment,
    ReelLike,
    SavedReel,
    SavedPost,
    User,
    _AUTH_RATE_LIMIT_BUCKETS,
    _AUTH_RATE_LIMIT_LOCK,
    app,
    db,
)


class FlaskFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uploads = tempfile.TemporaryDirectory(
            prefix=".instagram-test-uploads-",
            dir=Path(__file__).resolve().parent.parent,
        )
        upload_root = Path(cls.uploads.name)
        app.config.update(
            TESTING=True,
            PROFILE_PICTURE_FOLDER=str(upload_root / "profile_pictures"),
            POST_IMAGE_FOLDER=str(upload_root / "posts"),
            REEL_FOLDER=str(upload_root / "reels"),
            POST_MAX_FILE_SIZE=5 * 1024 * 1024,
        )
        Path(app.config["PROFILE_PICTURE_FOLDER"]).mkdir()
        Path(app.config["POST_IMAGE_FOLDER"]).mkdir()
        Path(app.config["REEL_FOLDER"]).mkdir()
        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        cls.uploads.cleanup()

    def setUp(self):
        with _AUTH_RATE_LIMIT_LOCK:
            _AUTH_RATE_LIMIT_BUCKETS.clear()
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.create_all()
            self.alice = User(
                username="alice",
                email="alice@example.test",
                password=generate_password_hash("alice-password"),
            )
            self.bob = User(
                username="bob",
                email="bob@example.test",
                password=generate_password_hash("bob-password"),
            )
            self.charlie = User(
                username="charlie",
                email="charlie@example.test",
                password=generate_password_hash("charlie-password"),
            )
            db.session.add_all([self.alice, self.bob, self.charlie])
            db.session.commit()
            self.alice_id = self.alice.id
            self.bob_id = self.bob.id
            self.charlie_id = self.charlie.id
        self.client = app.test_client()

    def csrf_token(self, path="/login", client=None):
        client = client or self.client
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', page)
        if not match:
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', page)
        self.assertIsNotNone(match, "Expected the base template CSRF token")
        return match.group(1)

    def login_as(self, username="alice", password="alice-password"):
        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={"email": username, "password": password, "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        return self.csrf_token("/dashboard")

    @staticmethod
    def png_upload(name="photo.png"):
        image_bytes = BytesIO()
        Image.new("RGB", (24, 24), color=(20, 120, 210)).save(image_bytes, "PNG")
        image_bytes.seek(0)
        return image_bytes, name

    @staticmethod
    def webm_upload(name="clip.webm"):
        # A transient EBML-signature fixture exercises the upload/storage path;
        # it is not a playable media asset or a product placeholder.
        return BytesIO(b"\x1a\x45\xdf\xa3" + b"test-container-fixture"), name

    def upload_test_reel(self, client=None, token=None, caption="Test Reel"):
        client = client or self.client
        token = token or self.csrf_token("/reels/upload", client=client)
        video, filename = self.webm_upload()
        response = client.post(
            "/reels/upload",
            data={"csrf_token": token, "caption": caption, "video": (video, filename, "video/webm")},
            content_type="multipart/form-data",
        )
        return response

    def test_registration_hashes_password_and_legacy_login_upgrades_it(self):
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={
                "username": "new-user",
                "email": "new@example.test",
                "password": "new-password",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            created = User.query.filter_by(username="new-user").one()
            self.assertTrue(check_password_hash(created.password, "new-password"))
            self.assertNotEqual(created.password, "new-password")

            legacy = User(
                username="legacy",
                email="legacy@example.test",
                password="scrypt:old-plaintext-password",
            )
            db.session.add(legacy)
            db.session.commit()

        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={
                "email": "legacy",
                "password": "incorrect-password",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        token = self.csrf_token("/login")
        response = self.client.post(
            "/login",
            data={
                "email": "legacy",
                "password": "scrypt:old-plaintext-password",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            upgraded = User.query.filter_by(username="legacy").one()
            self.assertTrue(check_password_hash(upgraded.password, "scrypt:old-plaintext-password"))
            self.assertNotEqual(upgraded.password, "scrypt:old-plaintext-password")

    def test_registration_rejects_malformed_email_username_and_password_length(self):
        token = self.csrf_token("/register")
        invalid_forms = [
            {"username": "bad name", "email": "valid@example.test", "password": "valid-password"},
            {"username": "valid-name", "email": "not-an-email", "password": "valid-password"},
            {"username": "valid-name", "email": "valid@example.test", "password": "short"},
            {"username": "valid-name", "email": "valid@example.test", "password": "x" * 129},
        ]
        for form_data in invalid_forms:
            response = self.client.post(
                "/register", data={**form_data, "csrf_token": token}
            )
            self.assertEqual(response.status_code, 302)
        with app.app_context():
            self.assertIsNone(User.query.filter_by(username="valid-name").first())

    def test_login_and_registration_rate_limits_return_user_friendly_429(self):
        login_token = self.csrf_token("/login")
        for _ in range(app.config["LOGIN_RATE_LIMIT"]):
            response = self.client.post(
                "/login",
                data={
                    "email": "missing-user",
                    "password": "incorrect-password",
                    "csrf_token": login_token,
                },
            )
            self.assertEqual(response.status_code, 302)
        limited_login = self.client.post(
            "/login",
            data={
                "email": "missing-user",
                "password": "incorrect-password",
                "csrf_token": login_token,
            },
        )
        self.assertEqual(limited_login.status_code, 429)
        self.assertIn("Retry-After", limited_login.headers)
        self.assertIn(b"Too many login attempts", limited_login.data)

        register_token = self.csrf_token("/register")
        for _ in range(app.config["REGISTER_RATE_LIMIT"]):
            response = self.client.post(
                "/register", data={"csrf_token": register_token}
            )
            self.assertEqual(response.status_code, 302)
        limited_registration = self.client.post(
            "/register", data={"csrf_token": register_token}
        )
        self.assertEqual(limited_registration.status_code, 429)
        self.assertIn("Retry-After", limited_registration.headers)
        self.assertIn(b"Too many registration attempts", limited_registration.data)

    def test_auth_forms_keep_csrf_session_and_reject_invalid_tokens(self):
        for path in ("/login", "/register"):
            with self.subTest(path=path):
                client = app.test_client()
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                page = response.get_data(as_text=True)
                self.assertIn(f'<form action="{path}" method="POST">', page)
                match = re.search(
                    r'name="csrf_token"\s+value="([^"]+)"', page
                )
                self.assertIsNotNone(match, "Expected an auth form CSRF token")
                self.assertIn("Set-Cookie", response.headers)
                self.assertIsNotNone(
                    client.get_cookie(app.config["SESSION_COOKIE_NAME"]),
                    "The test browser should store the session cookie from GET",
                )
                cookie = response.headers["Set-Cookie"]
                self.assertIn("Path=/", cookie)
                self.assertIn("HttpOnly", cookie)
                self.assertIn("SameSite=Lax", cookie)
                self.assertNotIn("Domain=", cookie)
                self.assertIn("no-store", response.headers["Cache-Control"])
                self.assertEqual(
                    "Secure" in cookie,
                    app.config["SESSION_COOKIE_SECURE"],
                )

                rejected = client.post(path, data={})
                self.assertEqual(rejected.status_code, 400)
                self.assertIn(b"Refresh the page", rejected.data)

                rejected = client.post(path, data={"csrf_token": "invalid-token"})
                self.assertEqual(rejected.status_code, 400)

    def test_csrf_form_token_without_its_session_cookie_is_rejected_and_logged(self):
        token = self.csrf_token("/login", client=self.client)
        separate_client = app.test_client()

        with self.assertLogs("app", level="WARNING") as captured:
            response = separate_client.post(
                "/login",
                data={"email": "alice", "password": "alice-password", "csrf_token": token},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("CSRF session token is missing", "\n".join(captured.output))
        self.assertIn("session_cookie_present=False", "\n".join(captured.output))

    def test_login_and_registration_posts_accept_tokens_from_their_get_session(self):
        register_token = self.csrf_token("/register")
        register_response = self.client.post(
            "/register",
            data={
                "username": "csrf-user",
                "email": "csrf-user@example.test",
                "password": "csrf-password",
                "csrf_token": register_token,
            },
        )
        self.assertEqual(register_response.status_code, 302)

        login_token = self.csrf_token("/login")
        login_response = self.client.post(
            "/login",
            data={
                "email": "csrf-user",
                "password": "csrf-password",
                "csrf_token": login_token,
            },
        )
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(login_response.headers["Location"], "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_protected_routes_and_global_csrf(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        token = self.login_as()
        response = self.client.post(f"/users/{self.bob_id}/follow")
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"/users/{self.bob_id}/follow", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)

    def test_logout_is_post_only_and_csrf_protected(self):
        token = self.login_as()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        response = self.client.post("/logout", headers={"X-CSRFToken": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_follow_form_referrer_cannot_redirect_off_site(self):
        token = self.login_as()
        response = self.client.post(
            f"/users/{self.bob_id}/follow",
            data={"csrf_token": token},
            headers={"Referer": "https://outside.example/landing"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/landing")

    def test_post_upload_profile_edit_and_image_storage(self):
        token = self.login_as()
        image, filename = self.png_upload()
        response = self.client.post(
            "/create-post",
            data={
                "csrf_token": token,
                "caption": "A real uploaded test image",
                "image": (image, filename),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            post = Post.query.filter_by(user_id=self.alice_id).one()
            self.assertEqual(post.caption, "A real uploaded test image")
            stored_post_image = Path(app.config["POST_IMAGE_FOLDER"]) / post.image_filename
            self.assertTrue(stored_post_image.is_file())
            post_image_url = f"/uploads/posts/{post.image_filename}"
        response = self.client.get(post_image_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        response.close()

        token = self.csrf_token("/edit-profile")
        avatar, avatar_name = self.png_upload("avatar.png")
        response = self.client.post(
            "/edit-profile",
            data={
                "csrf_token": token,
                "username": "alice-updated",
                "display_name": "Alice Updated",
                "bio": "Updated biography",
                "email": "alice@example.test",
                "profile_picture": (avatar, avatar_name),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            updated = db.session.get(User, self.alice_id)
            self.assertEqual(updated.username, "alice-updated")
            self.assertEqual(updated.display_name, "Alice Updated")
            self.assertEqual(updated.bio, "Updated biography")
            self.assertTrue(
                (Path(app.config["PROFILE_PICTURE_FOLDER"]) / updated.profile_picture).is_file()
            )
            avatar_url = f"/uploads/profile_pictures/{updated.profile_picture}"
        response = self.client.get(avatar_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "image/png")
        response.close()

    def test_profile_search_explore_post_and_follow_lists_render(self):
        with app.app_context():
            post = Post(user_id=self.bob_id, image_filename="existing.png", caption="hello")
            db.session.add(post)
            db.session.commit()
            post_id = post.id
        self.login_as()
        for path in (
            "/users/bob",
            "/search?q=bob",
            "/explore",
            f"/posts/{post_id}",
            "/users/bob/followers",
            "/users/bob/following",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_reel_upload_feed_likes_comments_saves_and_profile_tab(self):
        self.assertEqual(self.client.get("/reels").status_code, 302)
        self.assertEqual(self.client.get("/reels/upload").status_code, 302)
        token = self.login_as()
        self.assertEqual(self.client.get("/reels/upload").status_code, 200)
        empty_feed = self.client.get("/reels")
        self.assertEqual(empty_feed.status_code, 200)
        self.assertIn("No Reels yet", empty_feed.get_data(as_text=True))
        self.assertIn("Upload your first Reel", empty_feed.get_data(as_text=True))

        response = self.upload_test_reel(token=token, caption="First Reel")
        self.assertEqual(response.status_code, 302)

        with app.app_context():
            reel = Reel.query.filter_by(user_id=self.alice_id).one()
            reel_id = reel.id
            filename = reel.video_filename
            stored_path = Path(app.config["REEL_FOLDER"]) / filename
            self.assertTrue(stored_path.is_file())
        media_response = self.client.get(f"/uploads/reels/{filename}")
        self.assertEqual(media_response.status_code, 200)
        self.assertEqual(media_response.mimetype, "video/webm")
        self.assertEqual(media_response.headers["X-Content-Type-Options"], "nosniff")
        media_response.close()

        feed = self.client.get("/reels")
        feed_html = feed.get_data(as_text=True)
        self.assertIn("First Reel", feed_html)
        self.assertIn(f"/uploads/reels/{filename}", feed_html)
        self.assertIn("reel-play-toggle", feed_html)

        response = self.client.post(
            f"/reels/{reel_id}/like", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["liked"])
        self.client.post(f"/reels/{reel_id}/like", headers={"X-CSRFToken": token})
        with app.app_context():
            self.assertEqual(ReelLike.query.filter_by(reel_id=reel_id).count(), 1)
        response = self.client.post(
            f"/reels/{reel_id}/unlike", headers={"X-CSRFToken": token}
        )
        self.assertFalse(response.json["liked"])

        response = self.client.post(
            f"/reels/{reel_id}/comments",
            json={"content": "A Reel comment"},
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 201)
        comment_id = response.json["id"]
        self.assertIn("A Reel comment", self.client.get("/reels").get_data(as_text=True))

        response = self.client.post(
            f"/reels/{reel_id}/save", headers={"X-CSRFToken": token}
        )
        self.assertTrue(response.json["saved"])
        saved_page = self.client.get("/saved?type=reels")
        self.assertEqual(saved_page.status_code, 200)
        self.assertIn(f'data-saved-reel-id="{reel_id}"', saved_page.get_data(as_text=True))
        response = self.client.post(
            f"/reels/{reel_id}/save", headers={"X-CSRFToken": token}
        )
        self.assertFalse(response.json["saved"])

        profile_page = self.client.get("/users/alice?tab=reels")
        self.assertEqual(profile_page.status_code, 200)
        self.assertIn("profile-reel-grid", profile_page.get_data(as_text=True))

        bob_client = app.test_client()
        bob_login_token = self.csrf_token("/login", client=bob_client)
        response = bob_client.post(
            "/login",
            data={"email": "bob", "password": "bob-password", "csrf_token": bob_login_token},
        )
        self.assertEqual(response.status_code, 302)
        bob_token = self.csrf_token("/dashboard", client=bob_client)
        response = bob_client.post(
            f"/reel-comments/{comment_id}/delete", headers={"X-CSRFToken": bob_token}
        )
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            f"/reel-comments/{comment_id}/delete", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["comment_count"], 0)

    def test_reel_upload_rejects_executables_mismatched_mime_and_oversize(self):
        token = self.login_as()
        executable_response = self.client.post(
            "/reels/upload",
            data={
                "csrf_token": token,
                "caption": "",
                "video": (BytesIO(b"MZ executable"), "program.exe", "application/x-msdownload"),
            },
            content_type="multipart/form-data",
        )
        self.assertIn("Choose an MP4 or WebM video", executable_response.get_data(as_text=True))

        mismatch_video, mismatch_name = self.webm_upload()
        mime_response = self.client.post(
            "/reels/upload",
            data={
                "csrf_token": token,
                "caption": "",
                "video": (mismatch_video, mismatch_name, "video/mp4"),
            },
            content_type="multipart/form-data",
        )
        self.assertIn("does not match its file extension", mime_response.get_data(as_text=True))

        original_limit = app.config["REEL_MAX_FILE_SIZE"]
        try:
            app.config["REEL_MAX_FILE_SIZE"] = 4
            large_video, large_name = self.webm_upload()
            size_response = self.client.post(
                "/reels/upload",
                data={
                    "csrf_token": token,
                    "caption": "",
                    "video": (large_video, large_name, "video/webm"),
                },
                content_type="multipart/form-data",
            )
            self.assertIn("no larger than 100 MB", size_response.get_data(as_text=True))
        finally:
            app.config["REEL_MAX_FILE_SIZE"] = original_limit

        with app.app_context():
            self.assertEqual(Reel.query.count(), 0)

    def test_reel_delete_is_owner_only_and_cleans_related_records_and_file(self):
        token = self.login_as()
        response = self.upload_test_reel(token=token, caption="Delete test")
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            reel = Reel.query.filter_by(user_id=self.alice_id).one()
            reel_id, filename = reel.id, reel.video_filename
            db.session.add_all([
                ReelLike(user_id=self.bob_id, reel_id=reel_id),
                ReelComment(user_id=self.bob_id, reel_id=reel_id, content="related comment"),
                SavedReel(user_id=self.bob_id, reel_id=reel_id),
            ])
            db.session.commit()
            video_path = Path(app.config["REEL_FOLDER"]) / filename
            self.assertTrue(video_path.exists())

        bob_client = app.test_client()
        bob_login_token = self.csrf_token("/login", client=bob_client)
        bob_client.post(
            "/login",
            data={"email": "bob", "password": "bob-password", "csrf_token": bob_login_token},
        )
        bob_token = self.csrf_token("/dashboard", client=bob_client)
        response = bob_client.post(
            f"/reels/{reel_id}/delete", headers={"X-CSRFToken": bob_token}
        )
        self.assertEqual(response.status_code, 404)
        self.assertTrue(video_path.exists())
        with app.app_context():
            self.assertIsNotNone(db.session.get(Reel, reel_id))

        token = self.csrf_token("/dashboard")
        response = self.client.post(
            f"/reels/{reel_id}/delete", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(video_path.exists())
        with app.app_context():
            self.assertIsNone(db.session.get(Reel, reel_id))
            self.assertEqual(ReelLike.query.filter_by(reel_id=reel_id).count(), 0)
            self.assertEqual(ReelComment.query.filter_by(reel_id=reel_id).count(), 0)
            self.assertEqual(SavedReel.query.filter_by(reel_id=reel_id).count(), 0)

    def test_follow_like_comment_save_and_notification_persistence(self):
        with app.app_context():
            post = Post(user_id=self.bob_id, image_filename="existing.png", caption="hello")
            db.session.add(post)
            db.session.commit()
            post_id = post.id
        token = self.login_as()

        response = self.client.post(
            f"/users/{self.alice_id}/follow", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            f"/users/{self.bob_id}/follow", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["following"])
        with app.app_context():
            self.assertEqual(Follow.query.filter_by(follower_id=self.alice_id).count(), 1)
            self.assertEqual(Notification.query.filter_by(recipient_id=self.bob_id).count(), 1)

        response = self.client.post(
            f"/posts/{post_id}/like", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["liked"])
        response = self.client.post(
            f"/posts/{post_id}/unlike", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["liked"])
        response = self.client.post(
            f"/posts/{post_id}/like", headers={"X-CSRFToken": token}
        )
        self.assertTrue(response.json["liked"])
        response = self.client.post(
            f"/posts/{post_id}/comments",
            json={"content": "<script>safe text</script>"},
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 201)
        comment_id = response.json["id"]
        rendered_post = self.client.get(f"/posts/{post_id}").get_data(as_text=True)
        self.assertNotIn("<script>safe text</script>", rendered_post)
        response = self.client.post(
            f"/comments/{comment_id}/delete", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            other_comment = Comment(
                user_id=self.bob_id, post_id=post_id, content="Bob's comment"
            )
            db.session.add(other_comment)
            db.session.commit()
            other_comment_id = other_comment.id
        response = self.client.post(
            f"/comments/{other_comment_id}/delete", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            f"/posts/{post_id}/save", headers={"X-CSRFToken": token}
        )
        self.assertTrue(response.json["saved"])
        saved_page = self.client.get("/saved")
        self.assertEqual(saved_page.status_code, 200)
        self.assertIn(f'data-post-id="{post_id}"', saved_page.get_data(as_text=True))
        response = self.client.post(
            f"/posts/{post_id}/save", headers={"X-CSRFToken": token}
        )
        self.assertFalse(response.json["saved"])

        bob_client = app.test_client()
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            bob_client.get("/login").get_data(as_text=True),
        ).group(1)
        response = bob_client.post(
            "/login",
            data={"email": "bob", "password": "bob-password", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            bob_client.get("/notifications").get_data(as_text=True),
        ).group(1)
        with app.app_context():
            notification_id = Notification.query.filter_by(recipient_id=self.bob_id).first().id
        response = bob_client.post(
            f"/notifications/{notification_id}/read",
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 200)
        response = bob_client.post(
            "/notifications/mark-read",
            headers={"X-CSRFToken": token, "Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["unread_count"], 0)
        with app.app_context():
            self.assertTrue(db.session.get(Notification, notification_id).is_read)

        token = self.csrf_token("/dashboard")
        response = self.client.post(
            f"/users/{self.bob_id}/unfollow", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["following"])

    def test_messages_persist_poll_and_enforce_participants(self):
        token = self.login_as()
        self.assertEqual(self.client.get("/messages/start/bob").status_code, 405)
        response = self.client.post(
            "/messages/start/bob", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            conversation = Conversation.query.one()
            conversation_id = conversation.id
        malformed_payloads = [
            "{",
            "[]",
            "{}",
            '{"content": null}',
            '{"content": 5}',
            '{"content": "   "}',
        ]
        for body in malformed_payloads:
            response = self.client.post(
                f"/messages/{conversation_id}/send",
                data=body,
                content_type="application/json",
                headers={"X-CSRFToken": token},
            )
            self.assertEqual(response.status_code, 400, body)

        response = self.client.post(
            f"/messages/{conversation_id}/send",
            json={"content": "Hello Bob"},
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 201)
        message_id = response.json["message"]["id"]

        bob_client = app.test_client()
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            bob_client.get("/login").get_data(as_text=True),
        ).group(1)
        response = bob_client.post(
            "/login",
            data={"email": "bob", "password": "bob-password", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        token = re.search(
            r'<meta name="csrf-token" content="([^"]+)"',
            bob_client.get("/dashboard").get_data(as_text=True),
        ).group(1)
        response = bob_client.get(f"/messages/{conversation_id}/poll?after=0")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["messages"][0]["content"], "Hello Bob")
        self.assertEqual(bob_client.get(f"/messages/{conversation_id}").status_code, 200)

        with app.app_context():
            self.assertEqual(db.session.get(Message, message_id).content, "Hello Bob")
        charlie_client = app.test_client()
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"',
            charlie_client.get("/login").get_data(as_text=True),
        ).group(1)
        charlie_client.post(
            "/login",
            data={"email": "charlie", "password": "charlie-password", "csrf_token": token},
        )
        token = re.search(
            r'<meta name="csrf-token" content="([^"]+)"',
            charlie_client.get("/dashboard").get_data(as_text=True),
        ).group(1)
        self.assertEqual(
            charlie_client.get(f"/messages/{conversation_id}/poll").status_code, 403
        )
        response = charlie_client.post(
            f"/messages/{conversation_id}/send",
            json={"content": "Unauthorized"},
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(response.status_code, 403)

    def test_post_delete_requires_ownership_and_removes_uploaded_file(self):
        token = self.login_as()
        image, _ = self.png_upload()
        response = self.client.post(
            "/create-post",
            data={"csrf_token": token, "caption": "temporary", "image": (image, "x.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            post = Post.query.filter_by(user_id=self.alice_id).one()
            post_id = post.id
            image_path = Path(app.config["POST_IMAGE_FOLDER"]) / post.image_filename
            self.assertTrue(image_path.exists())

        bob = app.test_client()
        token = re.search(
            r'name="csrf_token"\s+value="([^"]+)"', bob.get("/login").get_data(as_text=True)
        ).group(1)
        bob.post(
            "/login",
            data={"email": "bob", "password": "bob-password", "csrf_token": token},
        )
        token = re.search(
            r'<meta name="csrf-token" content="([^"]+)"',
            bob.get("/dashboard").get_data(as_text=True),
        ).group(1)
        response = bob.post(f"/posts/{post_id}/delete", headers={"X-CSRFToken": token})
        self.assertEqual(response.status_code, 404)

        token = self.csrf_token("/dashboard")
        response = self.client.post(
            f"/posts/{post_id}/delete", headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(image_path.exists())
        with app.app_context():
            self.assertIsNone(db.session.get(Post, post_id))


if __name__ == "__main__":
    unittest.main()
