CREATE TABLE IF NOT EXISTS access_keys (
  id TEXT PRIMARY KEY,
  access_key TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT 'Flowrad user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  max_sessions INTEGER NOT NULL DEFAULT 1,
  device_hash TEXT,
  device_bound_at TIMESTAMPTZ,
  first_ip TEXT,
  last_ip TEXT,
  first_user_agent TEXT,
  last_user_agent TEXT,
  last_used_at TIMESTAMPTZ,
  use_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS access_keys_hash_idx ON access_keys(key_hash);
CREATE INDEX IF NOT EXISTS access_keys_revoked_idx ON access_keys(revoked);
