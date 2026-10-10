CREATE TABLE response_delivery_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    inline_response_threshold_bytes BIGINT NOT NULL CHECK (inline_response_threshold_bytes > 0),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO response_delivery_settings (inline_response_threshold_bytes) VALUES (16384);
