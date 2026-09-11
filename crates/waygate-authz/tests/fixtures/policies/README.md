# Synthetic Cedar policy fixtures

This directory contains a deliberately fictional policy estate for tests,
documentation, and local evaluation. Every server, tool, group, principal, and
resource name is an `example-*` identity or a generic role. None corresponds to
a running deployment.

The fixtures demonstrate reusable authorization patterns:

- deny by default with authenticated discovery and low-risk read baselines;
- API-key restrictions for protected data;
- SCIM deactivation;
- server-scoped operator roles and explicit confinement forbids;
- read/write/high-risk tier separation;
- directional service identities such as send-only and read-only roles;
- step-up for a named irreversible operation;
- per-call approval for side-effecting Code Mode calls; and
- enterprise cross-application access grants.

The test suite, dashboard simulator tests, policy-annotation guard, and image
boot smoke load these files. The published image does not include them as a
production policy set. A deployment must provide its own policies through
`GATEWAY_POLICIES_DIR`; copying this fixture directory is suitable only as a
learning or local-development starting point.

Every policy must have unique `@id` and `@layer` annotations. Run
`scripts/check-policy-annotations.sh` after editing the set.
