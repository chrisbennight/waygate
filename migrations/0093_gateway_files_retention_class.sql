-- Each file's retention class, recorded at staging so batch keepalive and
-- publication preserve the per-file promise instead of applying a batch-wide
-- window. Pre-existing rows get the general default.
ALTER TABLE gateway_files
    ADD COLUMN retention_seconds BIGINT NOT NULL DEFAULT 86400
    CHECK (retention_seconds > 0);
