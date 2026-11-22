# Instagram-inspired Flask application

A Flask application with a MySQL database, server-rendered Jinja templates, custom CSS, and vanilla JavaScript. It includes account registration and login, profiles, photo posts, likes, comments, follows, notifications, saved posts, search, explore, and direct messages.

## Project structure

```text
Instagram/
â”œâ”€â”€ app.py                     # Models, routes, upload handling, and application setup
â”œâ”€â”€ requirements.txt
â”œâ”€â”€ README.md
â”œâ”€â”€ migrations/
â”‚   â””â”€â”€ 001_add_reels.sql      # Additive MySQL Reel-table migration
â”œâ”€â”€ tests/
â”‚   â””â”€â”€ test_app.py            # Isolated feature tests (SQLite and temporary uploads)
â”œâ”€â”€ templates/                 # Jinja templates for application pages
â”œâ”€â”€ static/
â”‚   â”œâ”€â”€ css/style.css
â”‚   â”œâ”€â”€ js/script.js
â”‚   â””â”€â”€ images/                 # Default avatar and post fallbacks
â”œâ”€â”€ uploads/
â”‚   â”œâ”€â”€ posts/                  # User post images; preserve these files
â”‚   â”œâ”€â”€ profile_pictures/       # User avatars; preserve these files
â”‚   â””â”€â”€ reels/                  # Uploaded MP4/WebM files
â”œâ”€â”€ instance/                  # Flask instance data, if used
â””â”€â”€ venv/                       # Local virtual environment
```

The application currently keeps its SQLAlchemy models and routes in `app.py`. The existing tables are users, posts, likes, comments, follows, saved posts, notifications, conversations, and messages. Reels add separate `reels`, `reel_likes`, `reel_comments`, and `saved_reels` tables.

## Requirements

- Python 3.10 or newer
- MySQL 8.x (or a compatible MySQL server)
- Dependencies from `requirements.txt`

Install dependencies in the existing virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Environment configuration

The app requires `SECRET_KEY` and `DATABASE_URL`; it does not load `.env` files. Set both in the PowerShell window used to start Flask. Generate a long random secret and keep it private:

```powershell
$env:SECRET_KEY = "paste-a-random-secret-of-at-least-32-bytes-here"
$env:DATABASE_URL = "mysql+pymysql://DB_USER:URL_ENCODED_PASSWORD@127.0.0.1:3306/instagram_clone_db"
```

Use a dedicated MySQL account with access limited to this application database. URL-encode special characters in the database username or password. Do not commit secrets or place them in source files.

For a local HTTP development server, `SESSION_COOKIE_SECURE` defaults to `0`. Set it to `1` when serving the app over HTTPS:

```powershell
$env:SESSION_COOKIE_SECURE = "1"
```

Debug mode is disabled by default. To enable Flask debug mode for local development only:

```powershell
$env:FLASK_DEBUG = "1"
```

Do not enable debug mode on a public or production server. The Flask development server is for local development; deploy behind a production WSGI server and HTTPS.

## Database setup

Create the database and a restricted MySQL user using your own credentials. For example, in MySQL:

```sql
CREATE DATABASE instagram_clone_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'instagram_app'@'127.0.0.1' IDENTIFIED BY 'choose-a-unique-password';
GRANT SELECT, INSERT, UPDATE, DELETE
  ON instagram_clone_db.* TO 'instagram_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

Choose a unique password and put its URL-encoded value in `DATABASE_URL`. Adjust the database account host to match how MySQL accepts local connections.

For a **new, empty installation only**, initialize tables explicitly:

```powershell
$env:DATABASE_URL = "mysql+pymysql://SCHEMA_USER:URL_ENCODED_PASSWORD@127.0.0.1:3306/instagram_clone_db"
python -c "from app import app, db; app.app_context().push(); db.create_all()"
$env:DATABASE_URL = "mysql+pymysql://instagram_app:URL_ENCODED_PASSWORD@127.0.0.1:3306/instagram_clone_db"
```

`db.create_all()` creates missing tables; it is not a schema migration tool. Normal application startup does not create or alter tables. The runtime application account needs only the DML privileges above. Existing installations should keep their database and data. This audit did not run migrations or change the schema. The existing `user.password` column is wide enough for Werkzeug hashes, so password hardening does not require a column change.

The application uses `DATABASE_URL` at startup. Check connectivity without changing data with:

```powershell
python -c "from app import app, db; from sqlalchemy import text; c=db.engine.connect(); print(c.execute(text('SELECT 1')).scalar()); c.close()"
```

## Run the app

With the environment variables set and the database initialized:

```powershell
python app.py
```

Open `http://127.0.0.1:5000`. Startup does not run schema changes. To inspect registered routes without starting the server:

```powershell
flask --app app routes
```

## Tests

Run the in-project backend feature suite:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite forces an in-memory SQLite database and temporary upload directories. It does not connect to MySQL or write to the existing `uploads/` directories. It covers registration and password hashing (including gradual upgrade of legacy plaintext passwords), CSRF enforcement, protected routes, post and avatar uploads, profile editing, follows, post likes/comments and saved posts, Reels upload validation/storage/serving, Reel likes/comments/saves/profile tabs/deletion, notifications, messaging privacy, and post deletion ownership. Reel upload tests use a transient container-signature fixture and do not verify that a real encoded video plays in a browser.

Browser-based responsive checks and MySQL persistence checks must be performed in an environment with a configured MySQL service and browser. They are not part of the SQLite test suite.

## Security and data handling

- Passwords are stored with Werkzeugâ€™s password hashing. A legacy plaintext password is converted to a hash only after that account successfully logs in; accounts remain usable during the transition.
- Configure a private, persistent `SECRET_KEY`. Changing it invalidates existing sessions.
- Flask-WTF CSRF protection covers state-changing requests. JavaScript requests send the CSRF token in `X-CSRFToken`.
- ORM queries use SQLAlchemy expressions. Message routes verify that the current user belongs to the conversation.
- Post and profile image uploads are size-limited, checked with Pillow, assigned generated filenames, and served from their upload directories.
- Existing database data and files under `uploads/` are user data. Back them up before any separately planned database migration or media cleanup.

## Existing database credentials

If credentials were previously stored in source code or shared, rotate the MySQL password and use a new random Flask secret. Configure replacements through environment variables; do not put the new values in this repository.

## Reels feature and database migration

Reels use the existing authenticated Flask app and add four tables: `reels`, `reel_likes`, `reel_comments`, and `saved_reels`. Existing `posts`, `likes`, `comments`, and `saved_posts` tables are not changed. Like and save constraints prevent duplicate rows; foreign keys cascade Reel-related rows when a Reel or user is deleted.

Before using Reels with the existing MySQL database, back it up, then review and run [`migrations/001_add_reels.sql`](migrations/001_add_reels.sql) against `instagram_clone_db` with a schema-admin account. This is an additive migration using `CREATE TABLE IF NOT EXISTS`; it creates only the four new tables and does not copy, alter, or delete existing rows. The migration has not been run by this project audit. Once applied, run the app with its normal restricted runtime account.

Authenticated users can upload MP4 or WebM videos up to 100 MB. Videos are stored under `uploads/reels/` using generated filenames. The feed prioritizes Reels from followed users and includes community Reels for discovery. Reel saves appear under the separate **Saved Reels** tab; existing Saved Posts remain under **Saved Posts**.
