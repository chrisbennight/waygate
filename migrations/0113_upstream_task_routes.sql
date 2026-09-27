CREATE TABLE upstream_task_routes (
    id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    expires_at bigint NOT NULL,
    route jsonb NOT NULL,
    CONSTRAINT upstream_task_route_tenant CHECK (route->>'tenant' = tenant_id),
    CONSTRAINT upstream_task_route_expiry CHECK ((route->>'exp')::bigint = expires_at)
);

CREATE INDEX upstream_task_routes_expiry ON upstream_task_routes (expires_at);
