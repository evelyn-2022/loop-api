-- 1. Add is_verified column to users
ALTER TABLE users
    ADD COLUMN verified BOOLEAN DEFAULT FALSE NOT NULL;

-- 2. Create verification_tokens table
CREATE TABLE verification_tokens
(
    id          BIGSERIAL PRIMARY KEY,
    token       VARCHAR(255) NOT NULL UNIQUE,
    user_id     BIGINT       NOT NULL,
    expiry_date TIMESTAMP    NOT NULL,
    CONSTRAINT fk_verification_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Optional: Indexes for fast lookup
CREATE INDEX idx_verification_token ON verification_tokens (token);
CREATE INDEX idx_verification_user_id ON verification_tokens (user_id);
CREATE INDEX idx_verification_expiry_date ON verification_tokens (expiry_date);
