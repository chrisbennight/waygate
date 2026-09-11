-- Phase 0 schema stub. Real tables land with the storage phase; this file
-- exists so `sqlx migrate` has something to see and the Docker build layer
-- that copies `migrations/` has a source.

CREATE TABLE IF NOT EXISTS schema_sentinel (
    key         TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_sentinel (key) VALUES ('init') ON CONFLICT DO NOTHING;
