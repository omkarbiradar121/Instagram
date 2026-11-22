-- Additive MySQL 8 migration. Existing tables and rows are not modified.
-- Back up the database before applying. Run once with a schema-admin account.

CREATE TABLE IF NOT EXISTS reels (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    video_filename VARCHAR(40) NOT NULL,
    caption VARCHAR(2200) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reels_video_filename (video_filename),
    KEY ix_reels_created_at (created_at),
    KEY ix_reels_user_created (user_id, created_at),
    CONSTRAINT fk_reels_user FOREIGN KEY (user_id)
        REFERENCES `user` (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS reel_likes (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    reel_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_reel_likes_user_reel UNIQUE (user_id, reel_id),
    KEY ix_reel_likes_reel_id (reel_id),
    CONSTRAINT fk_reel_likes_user FOREIGN KEY (user_id)
        REFERENCES `user` (id) ON DELETE CASCADE,
    CONSTRAINT fk_reel_likes_reel FOREIGN KEY (reel_id)
        REFERENCES reels (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS reel_comments (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    reel_id INT NOT NULL,
    content VARCHAR(500) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY ix_reel_comments_reel_created (reel_id, created_at),
    CONSTRAINT fk_reel_comments_user FOREIGN KEY (user_id)
        REFERENCES `user` (id) ON DELETE CASCADE,
    CONSTRAINT fk_reel_comments_reel FOREIGN KEY (reel_id)
        REFERENCES reels (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS saved_reels (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    reel_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_saved_reels_user_reel UNIQUE (user_id, reel_id),
    KEY ix_saved_reels_user_created (user_id, created_at),
    CONSTRAINT fk_saved_reels_user FOREIGN KEY (user_id)
        REFERENCES `user` (id) ON DELETE CASCADE,
    CONSTRAINT fk_saved_reels_reel FOREIGN KEY (reel_id)
        REFERENCES reels (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
