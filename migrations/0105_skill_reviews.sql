CREATE TABLE skill_reviews (
    tenant_id TEXT NOT NULL,
    source_key TEXT NOT NULL,
    skill_uri TEXT NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    candidate JSONB NOT NULL,
    serving JSONB,
    candidate_status TEXT NOT NULL CHECK (candidate_status IN ('pending', 'approved', 'rejected')),
    quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source_key, skill_uri)
);

CREATE TABLE skill_review_decisions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_key TEXT NOT NULL,
    skill_uri TEXT NOT NULL,
    generation BIGINT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject', 'quarantine')),
    candidate JSONB NOT NULL,
    actor TEXT NOT NULL CHECK (length(actor) > 0),
    actor_issuer TEXT NOT NULL CHECK (length(actor_issuer) > 0),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_key, skill_uri, generation),
    FOREIGN KEY (tenant_id, source_key, skill_uri)
        REFERENCES skill_reviews (tenant_id, source_key, skill_uri)
);

CREATE INDEX skill_review_queue ON skill_reviews (tenant_id, candidate_status, updated_at);
CREATE INDEX skill_review_history ON skill_review_decisions (tenant_id, source_key, skill_uri, id DESC);
