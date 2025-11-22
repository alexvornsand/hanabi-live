-- Adds auth token fields to the users table.
-- Run this against existing databases before/with deploys that use the new schema.

BEGIN;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS auth_token TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS auth_token_expires_at TIMESTAMPTZ;

COMMIT;
