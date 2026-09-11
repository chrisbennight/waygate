-- Policy bundles for a tenant deleted before lifecycle cleanup became atomic
-- are unreachable residue. Remove them once, then make the tenant registry the
-- authoritative lifetime boundary for every future bundle write.
LOCK TABLE tenants, policy_bundles IN SHARE ROW EXCLUSIVE MODE;

DELETE FROM policy_bundles AS bundle
WHERE NOT EXISTS (
    SELECT 1
    FROM tenants
    WHERE tenants.id = bundle.tenant_id
);

ALTER TABLE policy_bundles
    ADD CONSTRAINT policy_bundles_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
