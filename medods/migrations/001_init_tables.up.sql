CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_guid VARCHAR(36) NOT NULL,
    token_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip VARCHAR(45) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_user_guid ON refresh_tokens(user_guid);
CREATE INDEX idx_refresh_tokens_is_used ON refresh_tokens(is_used);