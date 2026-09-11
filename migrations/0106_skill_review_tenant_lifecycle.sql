LOCK TABLE tenants IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE skill_reviews IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE skill_review_decisions
    DROP CONSTRAINT skill_review_decisions_tenant_id_source_key_skill_uri_fkey,
    ADD CONSTRAINT skill_review_decisions_review_fkey
        FOREIGN KEY (tenant_id, source_key, skill_uri)
        REFERENCES skill_reviews (tenant_id, source_key, skill_uri) ON DELETE CASCADE;

DELETE FROM skill_reviews r WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id);

ALTER TABLE skill_reviews
    ADD CONSTRAINT skill_reviews_tenant_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;
