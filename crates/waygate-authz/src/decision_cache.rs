//! Bounded per-engine cache for Cedar decisions.
//!
//! ## Why a verdict is cacheable
//!
//! A [`CedarEngine`](crate::CedarEngine) owns an immutable policy set: it is
//! built once by `load_dir`/`from_source` and exposes no method that mutates
//! `policies`. Every policy change — SIGHUP reload, a published tenant bundle,
//! a ledger recovery — constructs a *new* engine and swaps the `Arc` in
//! `ReloadableCedar`. So for the lifetime of one engine, evaluation is a pure
//! function of the facts and the strictness flag.
//!
//! That makes invalidation structural rather than something this module has to
//! implement: a new policy set is a new engine, and a new engine starts with an
//! empty cache. There is no generation counter to get wrong and no window in
//! which a retired policy set can answer a live request.
//!
//! ## Why the key is the whole fact set
//!
//! The key is a digest over *every* field the fact tree carries, assembled by
//! destructuring each struct without a `..` rest pattern. Adding a fact field
//! is therefore a compile error here, not a silently unkeyed input — which is
//! the failure that would let one principal's verdict answer another's request.
//!
//! Strings are length-prefixed and sequences are count-prefixed so no two
//! distinct fact sets can produce the same byte stream by concatenation.
//! Sequence order is preserved rather than normalized: Cedar treats the
//! principal's groups and scopes as sets, so a reordered vector is the same
//! decision, but hashing it to a different key only costs a lookup miss
//! whereas normalizing incorrectly would serve a wrong verdict. Miss on the
//! safe side.
//!
//! ## The one excluded field
//!
//! `RuntimeContextFacts::time` is excluded. It is the only fact that changes on
//! every call, so keying on it would make every lookup a miss. Excluding it is
//! sound *because the engine never publishes it*: `build_context` assembles the
//! Cedar request context from `discovery`, `email_recipients`, `client_id`,
//! `channel`, and `approval_present` only, and no entity attribute carries the
//! timestamp either. A policy therefore cannot observe it, so it cannot change
//! a decision.
//!
//! **If a future change publishes the timestamp to the Cedar request, this
//! cache must key on it — quantized to the coarsest granularity the policy
//! needs — or be bypassed for time-dependent policy sets.** The exclusion is
//! marked at its hash site and at `build_context`.
//!
//! Every other ambient fact is keyed, including `mfa` and `source_ip`, which
//! are stable for a given caller and so cost nothing in hit rate.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use waygate_core::{
    ActionFacts, ClientFacts, EmailRecipients, Facts, InvocationChannelFact, PrincipalFacts,
    RequestFacts, ResourceFacts, RiskTier, RuntimeContextFacts, ScimFacts, TenantFacts,
};

use crate::AuthzResult;

/// Entries retained per engine before the oldest is evicted.
///
/// Sized so an authorization-filtered catalog traversal — the workload that
/// motivated the cache, where one listing evaluates once per visible tool —
/// stays resident for several concurrent principals. An entry is a 32-byte
/// digest plus a decision and its fired-policy identifiers, so the whole cache
/// is a small, fixed cost that does not grow with uptime.
const CAPACITY: usize = 4_096;

/// Digest of one complete evaluation input.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DecisionKey([u8; 32]);

impl std::fmt::Debug for DecisionKey {
    /// Render a short prefix only. The digest is one-way, but it is derived
    /// from the caller's identity, so a full value in a diagnostic would be a
    /// stable cross-request correlator for no diagnostic benefit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecisionKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

impl DecisionKey {
    /// Derive the key for `facts` under `strict`.
    ///
    /// `strict` participates because the lenient and strict paths can reach
    /// different outcomes for the same facts: an erroring `permit` is skipped
    /// leniently and refused strictly.
    pub(crate) fn new(facts: &Facts, strict: bool) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[u8::from(strict)]);
        hash_facts(&mut hasher, facts);
        Self(*hasher.finalize().as_bytes())
    }
}

/// Bounded first-in-first-out cache of decisions for one policy set.
///
/// Eviction is insertion-ordered rather than access-ordered: a traversal reads
/// each key about equally often, so recency carries little signal and FIFO
/// avoids maintaining access order under the lock.
pub(crate) struct DecisionCache {
    inner: Mutex<Inner>,
}

struct Inner {
    entries: HashMap<DecisionKey, AuthzResult>,
    order: VecDeque<DecisionKey>,
}

impl DecisionCache {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Return the cached verdict for `key`, if present.
    pub(crate) fn get(&self, key: &DecisionKey) -> Option<AuthzResult> {
        let guard = self.lock();
        guard.entries.get(key).cloned()
    }

    /// Record `result` for `key`, evicting the oldest entry when full.
    ///
    /// A concurrent duplicate evaluation is allowed rather than coordinated:
    /// Cedar evaluation is pure and cheap relative to the cost of parking a
    /// request behind another's in-flight work, so the second writer simply
    /// stores the same value it would have read.
    pub(crate) fn insert(&self, key: DecisionKey, result: &AuthzResult) {
        let mut guard = self.lock();
        if guard.entries.contains_key(&key) {
            return;
        }
        while guard.order.len() >= CAPACITY {
            match guard.order.pop_front() {
                Some(oldest) => {
                    guard.entries.remove(&oldest);
                    waygate_telemetry::metrics::record_authz_decision_cache_eviction();
                }
                None => break,
            }
        }
        guard.order.push_back(key);
        guard.entries.insert(key, result.clone());
    }

    /// A poisoned cache lock cannot corrupt a decision — the protected state is
    /// only a lookup table whose entries are each independently re-derivable —
    /// so recover the guard instead of propagating a panic into the
    /// authorization path.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Key derivation
//
// Each function destructures its struct with no `..` rest pattern, so a new
// fact field fails to compile until it is keyed. Keep the write order aligned
// with the destructuring order; the order itself is arbitrary but must stay
// stable for a process, which it does because it is source order.
// ---------------------------------------------------------------------------

fn hash_facts(hasher: &mut blake3::Hasher, facts: &Facts) {
    let Facts {
        principal,
        client,
        tenant,
        action,
        resource,
        request,
        context,
    } = facts;
    hash_principal(hasher, principal);
    hash_client(hasher, client);
    hash_tenant(hasher, tenant);
    hash_action(hasher, action);
    hash_resource(hasher, resource);
    hash_option(hasher, request.as_ref(), hash_request);
    hash_context(hasher, context);
}

fn hash_principal(hasher: &mut blake3::Hasher, principal: &PrincipalFacts) {
    let PrincipalFacts {
        sub,
        email,
        groups,
        scopes,
        auth_method,
        roles,
        scim,
    } = principal;
    hash_str(hasher, sub);
    hash_opt_str(hasher, email.as_deref());
    hash_strs(hasher, groups);
    hash_strs(hasher, scopes);
    hash_str(hasher, auth_method);
    hash_strs(hasher, roles);
    hash_option(hasher, scim.as_ref(), hash_scim);
}

fn hash_scim(hasher: &mut blake3::Hasher, scim: &ScimFacts) {
    let ScimFacts {
        user_id,
        user_name,
        external_id,
        active,
        group_names,
        attrs,
    } = scim;
    hash_str(hasher, user_id);
    hash_str(hasher, user_name);
    hash_opt_str(hasher, external_id.as_deref());
    hash_bool(hasher, *active);
    hash_strs(hasher, group_names);
    // `serde_json::Value` maps are ordered (the workspace does not enable
    // serde_json's `preserve_order`), so the serialization is canonical for a
    // given value and safe to key on.
    hash_str(hasher, &attrs.to_string());
}

fn hash_client(hasher: &mut blake3::Hasher, client: &ClientFacts) {
    let ClientFacts { client_id } = client;
    hash_opt_str(hasher, client_id.as_deref());
}

fn hash_tenant(hasher: &mut blake3::Hasher, tenant: &TenantFacts) {
    let TenantFacts { tenant_id } = tenant;
    hash_str(hasher, tenant_id.as_str());
}

fn hash_action(hasher: &mut blake3::Hasher, action: &ActionFacts) {
    let ActionFacts {
        kind,
        required_scope,
    } = action;
    hash_str(hasher, kind);
    hash_opt_str(hasher, required_scope.as_deref());
}

fn hash_resource(hasher: &mut blake3::Hasher, resource: &ResourceFacts) {
    let ResourceFacts {
        server,
        tool,
        risk,
        side_effects,
        pii,
        data_classification,
        cost_class,
        uri,
        source_origin,
        artifact_digest,
        source_tree_digest,
        skill_uri,
        revision_digest,
        content_digest,
        source_path,
        source_object,
        resource_type,
        operation,
    } = resource;
    hash_str(hasher, server);
    hash_str(hasher, tool);
    hash_risk(hasher, *risk);
    hash_bool(hasher, *side_effects);
    hash_bool(hasher, *pii);
    hash_opt_str(hasher, data_classification.as_deref());
    hash_opt_str(hasher, cost_class.as_deref());
    hash_opt_str(hasher, uri.as_deref());
    hash_opt_str(hasher, source_origin.as_deref());
    hash_opt_str(hasher, artifact_digest.as_deref());
    hash_opt_str(hasher, source_tree_digest.as_deref());
    hash_opt_str(hasher, skill_uri.as_deref());
    hash_opt_str(hasher, revision_digest.as_deref());
    hash_opt_str(hasher, content_digest.as_deref());
    hash_opt_str(hasher, source_path.as_deref());
    hash_opt_str(hasher, source_object.as_deref());
    hash_opt_str(hasher, resource_type.as_deref());
    hash_opt_str(hasher, operation.as_deref());
}

fn hash_request(hasher: &mut blake3::Hasher, request: &RequestFacts) {
    let RequestFacts {
        discovery_only,
        email_recipients,
        target_domain,
        recipient_count,
        destructive,
        file_paths,
        argument_hash,
    } = request;
    hash_bool(hasher, *discovery_only);
    hash_option(hasher, email_recipients.as_ref(), hash_email_recipients);
    hash_opt_str(hasher, target_domain.as_deref());
    hash_option(hasher, recipient_count.as_ref(), |hasher, count| {
        hasher.update(&count.to_le_bytes());
    });
    hash_option(hasher, destructive.as_ref(), |hasher, flag| {
        hash_bool(hasher, *flag);
    });
    hash_strs(hasher, file_paths);
    hash_str(hasher, argument_hash);
}

fn hash_email_recipients(hasher: &mut blake3::Hasher, recipients: &EmailRecipients) {
    let EmailRecipients { valid, domains } = recipients;
    hash_bool(hasher, *valid);
    hash_count(hasher, domains.len());
    for domain in domains {
        hash_str(hasher, domain);
    }
}

fn hash_context(hasher: &mut blake3::Hasher, context: &RuntimeContextFacts) {
    let RuntimeContextFacts {
        approval_present,
        mfa,
        // Deliberately unkeyed: the timestamp is never published to the Cedar
        // request, so no policy can observe it, and it is the only fact that
        // changes on every call. Publishing it to `build_context` or to an
        // entity attribute makes it decision-relevant and this cache must then
        // key on it. See this module's header.
        time: _,
        source_ip,
        channel,
    } = context;
    hash_bool(hasher, *approval_present);
    hash_bool(hasher, *mfa);
    hash_option(hasher, source_ip.as_ref(), hash_ip);
    hash_channel(hasher, *channel);
}

fn hash_ip(hasher: &mut blake3::Hasher, ip: &IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            hasher.update(&[4]);
            hasher.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update(&[6]);
            hasher.update(&v6.octets());
        }
    }
}

fn hash_channel(hasher: &mut blake3::Hasher, channel: InvocationChannelFact) {
    hasher.update(&[match channel {
        InvocationChannelFact::Direct => 0,
        InvocationChannelFact::CodeMode => 1,
    }]);
}

fn hash_risk(hasher: &mut blake3::Hasher, risk: RiskTier) {
    hasher.update(&[match risk {
        RiskTier::Low => 0,
        RiskTier::Medium => 1,
        RiskTier::High => 2,
    }]);
}

/// Length-prefixed, so no concatenation of neighbouring strings can collide
/// with a different split of the same bytes.
fn hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hash_count(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_opt_str(hasher: &mut blake3::Hasher, value: Option<&str>) {
    hash_option(hasher, value, hash_str);
}

fn hash_strs(hasher: &mut blake3::Hasher, values: &[String]) {
    hash_count(hasher, values.len());
    for value in values {
        hash_str(hasher, value);
    }
}

fn hash_bool(hasher: &mut blake3::Hasher, value: bool) {
    hasher.update(&[u8::from(value)]);
}

/// Presence byte then the payload, so `None` cannot collide with a present
/// value whose encoding happens to start with the same bytes.
fn hash_option<T>(
    hasher: &mut blake3::Hasher,
    value: Option<T>,
    hash_present: impl FnOnce(&mut blake3::Hasher, T),
) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(present) => {
            hasher.update(&[1]);
            hash_present(hasher, present);
        }
    }
}

fn hash_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use time::OffsetDateTime;
    use waygate_core::TenantId;

    use super::*;
    use crate::{CedarEngine, Decision};

    /// Discriminates on a wide spread of entity and context attributes, so a
    /// mutation that the key fails to distinguish shows up as a verdict
    /// mismatch rather than passing unnoticed.
    const DISCRIMINATING_POLICY: &str = r#"
        @id("permit-invokers")
        permit(principal, action, resource) when {
            principal.groups.contains("invokers") && resource.risk != "high"
        };
        @id("permit-operators-high")
        permit(principal, action, resource) when {
            principal.roles.contains("operator") && principal.scopes.contains("mcp:invoke:high")
        };
        @id("forbid-pii-without-approval")
        forbid(principal, action, resource) when {
            resource has pii && resource.pii
            && context has approval_present && !context.approval_present
        };
        @id("forbid-codemode-side-effects")
        forbid(principal, action, resource) when {
            context has channel && context.channel == "codemode"
            && resource has side_effects && resource.side_effects
        };
        @id("forbid-named-client")
        forbid(principal, action, resource) when {
            context has client_id && context.client_id == "blocked-client"
        };
        @id("forbid-named-tool")
        forbid(principal, action, resource) when {
            resource has name && resource.name == "drop_everything"
        };
        @id("forbid-named-subject")
        forbid(principal == User::"banned", action, resource);
    "#;

    fn baseline() -> Facts {
        Facts {
            principal: PrincipalFacts {
                sub: "alice".into(),
                email: Some("alice@example.test".into()),
                groups: vec!["invokers".into()],
                scopes: vec!["mcp:invoke".into()],
                auth_method: "oauth".into(),
                roles: vec!["reader".into()],
                scim: None,
            },
            client: ClientFacts {
                client_id: Some("client-a".into()),
            },
            tenant: TenantFacts {
                tenant_id: TenantId::default(),
            },
            action: ActionFacts {
                kind: "CallTool".into(),
                required_scope: None,
            },
            resource: ResourceFacts {
                server: "server-a".into(),
                tool: "read_thing".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                data_classification: None,
                cost_class: None,
                uri: None,
                source_origin: None,
                artifact_digest: None,
                source_tree_digest: None,
                skill_uri: None,
                revision_digest: None,
                content_digest: None,
                source_path: None,
                source_object: None,
                resource_type: None,
                operation: None,
            },
            request: None,
            context: RuntimeContextFacts {
                approval_present: false,
                mfa: false,
                time: OffsetDateTime::UNIX_EPOCH,
                source_ip: None,
                channel: InvocationChannelFact::Direct,
            },
        }
    }

    fn scim() -> ScimFacts {
        ScimFacts {
            user_id: "scim-1".into(),
            user_name: "alice".into(),
            external_id: Some("ext-1".into()),
            active: true,
            group_names: vec!["staff".into()],
            attrs: serde_json::json!({"department": "eng"}),
        }
    }

    fn request() -> RequestFacts {
        RequestFacts {
            discovery_only: false,
            email_recipients: Some(EmailRecipients {
                valid: true,
                domains: BTreeSet::from(["example.test".to_string()]),
            }),
            target_domain: Some("example.test".into()),
            recipient_count: Some(1),
            destructive: Some(false),
            file_paths: vec!["/tmp/a".into()],
            argument_hash: "hash-a".into(),
        }
    }

    /// One mutation per keyed fact field. Every entry must produce a key
    /// distinct from the baseline and from every other entry; a new fact field
    /// should gain a row here when it is added to the hasher.
    fn mutations() -> Vec<(&'static str, Facts)> {
        let with = |f: fn(&mut Facts)| {
            let mut facts = baseline();
            f(&mut facts);
            facts
        };
        vec![
            ("principal.sub", with(|f| f.principal.sub = "bob".into())),
            (
                "principal.email.some",
                with(|f| f.principal.email = Some("b@example.test".into())),
            ),
            ("principal.email.none", with(|f| f.principal.email = None)),
            (
                "principal.groups",
                with(|f| f.principal.groups = vec!["readers".into()]),
            ),
            (
                "principal.groups.empty",
                with(|f| f.principal.groups = vec![]),
            ),
            (
                "principal.groups.extra",
                with(|f| f.principal.groups.push("extra".into())),
            ),
            (
                "principal.scopes",
                with(|f| f.principal.scopes = vec!["mcp:invoke:high".into()]),
            ),
            (
                "principal.auth_method",
                with(|f| f.principal.auth_method = "api_key".into()),
            ),
            (
                "principal.roles",
                with(|f| f.principal.roles = vec!["operator".into()]),
            ),
            (
                "principal.scim.some",
                with(|f| f.principal.scim = Some(scim())),
            ),
            (
                "principal.scim.user_id",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        user_id: "scim-2".into(),
                        ..scim()
                    })
                }),
            ),
            (
                "principal.scim.user_name",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        user_name: "bob".into(),
                        ..scim()
                    })
                }),
            ),
            (
                "principal.scim.external_id",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        external_id: None,
                        ..scim()
                    })
                }),
            ),
            (
                "principal.scim.active",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        active: false,
                        ..scim()
                    })
                }),
            ),
            (
                "principal.scim.group_names",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        group_names: vec!["contractors".into()],
                        ..scim()
                    })
                }),
            ),
            (
                "principal.scim.attrs",
                with(|f| {
                    f.principal.scim = Some(ScimFacts {
                        attrs: serde_json::json!({"department": "sales"}),
                        ..scim()
                    })
                }),
            ),
            (
                "client.client_id.some",
                with(|f| f.client.client_id = Some("blocked-client".into())),
            ),
            ("client.client_id.none", with(|f| f.client.client_id = None)),
            (
                "tenant.tenant_id",
                with(|f| f.tenant.tenant_id = TenantId::parse("other").expect("valid tenant id")),
            ),
            (
                "action.kind",
                with(|f| f.action.kind = "ReadResource".into()),
            ),
            (
                "action.required_scope",
                with(|f| f.action.required_scope = Some("mcp:invoke:high".into())),
            ),
            (
                "resource.server",
                with(|f| f.resource.server = "server-b".into()),
            ),
            (
                "resource.tool",
                with(|f| f.resource.tool = "drop_everything".into()),
            ),
            ("resource.risk", with(|f| f.resource.risk = RiskTier::High)),
            (
                "resource.risk.medium",
                with(|f| f.resource.risk = RiskTier::Medium),
            ),
            (
                "resource.side_effects",
                with(|f| f.resource.side_effects = true),
            ),
            ("resource.pii", with(|f| f.resource.pii = true)),
            (
                "resource.data_classification",
                with(|f| f.resource.data_classification = Some("restricted".into())),
            ),
            (
                "resource.cost_class",
                with(|f| f.resource.cost_class = Some("premium".into())),
            ),
            (
                "resource.uri",
                with(|f| f.resource.uri = Some("file:///a".into())),
            ),
            (
                "resource.source_origin",
                with(|f| f.resource.source_origin = Some("git".into())),
            ),
            (
                "resource.artifact_digest",
                with(|f| f.resource.artifact_digest = Some("sha256-a".into())),
            ),
            (
                "resource.source_tree_digest",
                with(|f| f.resource.source_tree_digest = Some("sha256-b".into())),
            ),
            (
                "resource.skill_uri",
                with(|f| f.resource.skill_uri = Some("skill://a".into())),
            ),
            (
                "resource.revision_digest",
                with(|f| f.resource.revision_digest = Some("sha256-c".into())),
            ),
            (
                "resource.content_digest",
                with(|f| f.resource.content_digest = Some("sha256-d".into())),
            ),
            (
                "resource.source_path",
                with(|f| f.resource.source_path = Some("a/b.md".into())),
            ),
            (
                "resource.source_object",
                with(|f| f.resource.source_object = Some("blob-a".into())),
            ),
            (
                "resource.resource_type",
                with(|f| f.resource.resource_type = Some(waygate_core::MODEL_RESOURCE_TYPE.into())),
            ),
            (
                "resource.operation",
                with(|f| f.resource.operation = Some("delete".into())),
            ),
            ("request.some", with(|f| f.request = Some(request()))),
            (
                "request.discovery_only",
                with(|f| {
                    f.request = Some(RequestFacts {
                        discovery_only: true,
                        ..request()
                    })
                }),
            ),
            (
                "request.email_recipients.none",
                with(|f| {
                    f.request = Some(RequestFacts {
                        email_recipients: None,
                        ..request()
                    })
                }),
            ),
            (
                "request.email_recipients.valid",
                with(|f| {
                    f.request = Some(RequestFacts {
                        email_recipients: Some(EmailRecipients {
                            valid: false,
                            domains: BTreeSet::from(["example.test".to_string()]),
                        }),
                        ..request()
                    })
                }),
            ),
            (
                "request.email_recipients.domains",
                with(|f| {
                    f.request = Some(RequestFacts {
                        email_recipients: Some(EmailRecipients {
                            valid: true,
                            domains: BTreeSet::from(["other.test".to_string()]),
                        }),
                        ..request()
                    })
                }),
            ),
            (
                "request.target_domain",
                with(|f| {
                    f.request = Some(RequestFacts {
                        target_domain: Some("other.test".into()),
                        ..request()
                    })
                }),
            ),
            (
                "request.recipient_count",
                with(|f| {
                    f.request = Some(RequestFacts {
                        recipient_count: Some(2),
                        ..request()
                    })
                }),
            ),
            (
                "request.recipient_count.none",
                with(|f| {
                    f.request = Some(RequestFacts {
                        recipient_count: None,
                        ..request()
                    })
                }),
            ),
            (
                "request.destructive",
                with(|f| {
                    f.request = Some(RequestFacts {
                        destructive: Some(true),
                        ..request()
                    })
                }),
            ),
            (
                "request.destructive.none",
                with(|f| {
                    f.request = Some(RequestFacts {
                        destructive: None,
                        ..request()
                    })
                }),
            ),
            (
                "request.file_paths",
                with(|f| {
                    f.request = Some(RequestFacts {
                        file_paths: vec!["/tmp/b".into()],
                        ..request()
                    })
                }),
            ),
            (
                "request.argument_hash",
                with(|f| {
                    f.request = Some(RequestFacts {
                        argument_hash: "hash-b".into(),
                        ..request()
                    })
                }),
            ),
            (
                "context.approval_present",
                with(|f| f.context.approval_present = true),
            ),
            ("context.mfa", with(|f| f.context.mfa = true)),
            (
                "context.source_ip.v4",
                with(|f| f.context.source_ip = Some(Ipv4Addr::new(10, 0, 0, 1).into())),
            ),
            (
                "context.source_ip.v4.other",
                with(|f| f.context.source_ip = Some(Ipv4Addr::new(10, 0, 0, 2).into())),
            ),
            (
                "context.source_ip.v6",
                with(|f| f.context.source_ip = Some(Ipv6Addr::LOCALHOST.into())),
            ),
            (
                "context.channel",
                with(|f| f.context.channel = InvocationChannelFact::CodeMode),
            ),
        ]
    }

    #[test]
    fn every_keyed_fact_field_changes_the_key() {
        let base = DecisionKey::new(&baseline(), false);
        let mut seen: HashMap<DecisionKey, &'static str> = HashMap::new();
        seen.insert(base, "baseline");
        for (name, facts) in mutations() {
            let key = DecisionKey::new(&facts, false);
            if let Some(previous) = seen.insert(key, name) {
                panic!(
                    "`{name}` collides with `{previous}`: a decision for one would answer the \
                     other. Every fact a policy can observe must be part of the key."
                );
            }
        }
    }

    /// Length- and count-prefixing exists for these: without it a field
    /// boundary could be shifted without changing the hashed bytes.
    #[test]
    fn shifting_a_field_boundary_changes_the_key() {
        let pairs: Vec<(Facts, Facts)> = vec![
            {
                let mut left = baseline();
                let mut right = baseline();
                left.principal.sub = "ab".into();
                left.principal.auth_method = "c".into();
                right.principal.sub = "a".into();
                right.principal.auth_method = "bc".into();
                (left, right)
            },
            {
                let mut left = baseline();
                let mut right = baseline();
                left.principal.groups = vec!["ab".into(), "c".into()];
                right.principal.groups = vec!["a".into(), "bc".into()];
                (left, right)
            },
            {
                let mut left = baseline();
                let mut right = baseline();
                left.principal.groups = vec!["a".into(), "b".into()];
                left.principal.scopes = vec![];
                right.principal.groups = vec!["a".into()];
                right.principal.scopes = vec!["b".into()];
                (left, right)
            },
            {
                let mut left = baseline();
                let mut right = baseline();
                left.resource.server = "a".into();
                left.resource.tool = "bc".into();
                right.resource.server = "ab".into();
                right.resource.tool = "c".into();
                (left, right)
            },
        ];
        for (index, (left, right)) in pairs.into_iter().enumerate() {
            assert_ne!(
                DecisionKey::new(&left, false),
                DecisionKey::new(&right, false),
                "pair {index}: a shifted field boundary must change the key",
            );
        }
    }

    #[test]
    fn strict_and_lenient_evaluations_are_keyed_apart() {
        let facts = baseline();
        assert_ne!(
            DecisionKey::new(&facts, false),
            DecisionKey::new(&facts, true),
        );
    }

    /// The deliberate exclusion. This test documents it rather than guarding
    /// it: if the call timestamp ever becomes observable to a policy — see the
    /// note on `build_context` — the key must account for it and this
    /// expectation must change with the same commit.
    #[test]
    fn only_the_call_timestamp_is_absent_from_the_key() {
        let mut later = baseline();
        later.context.time = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(9);
        assert_eq!(
            DecisionKey::new(&baseline(), false),
            DecisionKey::new(&later, false),
            "the timestamp is excluded because no policy can observe it",
        );
    }

    /// Normalized outcome, so an evaluation error compares as faithfully as a
    /// verdict. Some fact combinations below are deliberately shapes the entity
    /// builder refuses; the invariant under test is that the cache never
    /// changes the answer, not that every shape is decidable.
    fn outcome(result: Result<AuthzResult, crate::cedar::CedarError>) -> String {
        match result {
            Ok(verdict) => format!(
                "ok:{:?}:{:?}:{:?}",
                verdict.decision, verdict.policy_ids, verdict.reasons
            ),
            Err(error) => format!("err:{error}"),
        }
    }

    #[test]
    fn a_cached_verdict_matches_a_freshly_evaluated_one_for_every_mutation() {
        let cached = CedarEngine::from_source(DISCRIMINATING_POLICY).expect("policy parses");
        let mut cases = vec![("baseline", baseline())];
        cases.extend(mutations());
        let mut decided = 0_usize;
        for (name, facts) in cases {
            // A new engine shares the policy set but starts with an empty
            // cache, so this is the uncached answer to the same question.
            let cold = CedarEngine::from_source(DISCRIMINATING_POLICY).expect("policy parses");
            let expected = outcome(cold.evaluate_facts(&facts));
            let before = cached.cached_decision_count();
            let first = outcome(cached.evaluate_facts(&facts));
            let after_first = cached.cached_decision_count();
            let second = outcome(cached.evaluate_facts(&facts));
            let after_second = cached.cached_decision_count();
            assert_eq!(
                expected, first,
                "{name}: first answer differs from uncached"
            );
            assert_eq!(
                expected, second,
                "{name}: cached answer differs from uncached",
            );
            if expected.starts_with("ok:") {
                decided += 1;
                // Equal answers alone would still hold with no cache at all.
                // Retaining the new decision and then not deciding again is
                // what makes removing the lookup a test failure.
                assert_eq!(
                    after_first,
                    before + 1,
                    "{name}: deciding a new question must retain it",
                );
                assert_eq!(
                    after_second, after_first,
                    "{name}: asking again must be answered from the retained decision",
                );
            } else {
                assert_eq!(
                    after_second, before,
                    "{name}: a failed evaluation must retain nothing",
                );
            }
        }
        assert!(
            decided > 40,
            "most mutations must reach a real verdict for this to be meaningful; got {decided}",
        );
    }

    #[test]
    fn an_evaluation_error_is_not_retained_as_a_verdict() {
        // References an attribute the resource entity does not carry, so the
        // forbid errors and the engine fails closed rather than dropping it.
        let engine = CedarEngine::from_source(
            r#"
            @id("permit-all") permit(principal, action, resource);
            @id("forbid-on-missing-attribute")
            forbid(principal, action, resource) when { resource.absent_attribute == "x" };
            "#,
        )
        .expect("policy parses");
        let facts = baseline();

        assert!(engine.evaluate_facts(&facts).is_err());
        assert_eq!(
            engine.cached_decision_count(),
            0,
            "a failure is a property of the attempt, not a decision to retain",
        );
        assert!(
            engine.evaluate_facts(&facts).is_err(),
            "a failure must not be answered from cache, and must not be \
             replaced by a verdict on the next ask",
        );
    }

    #[test]
    fn a_new_policy_set_does_not_inherit_decided_verdicts() {
        let facts = baseline();
        let permissive =
            CedarEngine::from_source(r#"@id("permit-all") permit(principal, action, resource);"#)
                .expect("policy parses");
        assert_eq!(
            permissive
                .evaluate_facts(&facts)
                .expect("evaluate")
                .decision,
            Decision::Allow,
        );

        // What a reload installs: a different policy set in a different engine.
        let restrictive =
            CedarEngine::from_source(r#"@id("forbid-all") forbid(principal, action, resource);"#)
                .expect("policy parses");
        assert_eq!(
            restrictive
                .evaluate_facts(&facts)
                .expect("evaluate")
                .decision,
            Decision::Deny,
            "a verdict decided against a retired policy set must not answer a live request",
        );
    }

    #[test]
    fn a_step_up_verdict_survives_the_cache() {
        let engine = CedarEngine::from_source(
            r#"
            @id("permit-high-with-scope")
            permit(principal, action, resource) when {
                principal.scopes.contains("mcp:invoke:high")
            };
            "#,
        )
        .expect("policy parses");
        let mut facts = baseline();
        facts.resource.risk = RiskTier::High;
        facts.action.required_scope = Some("mcp:invoke:high".into());

        let first = engine.evaluate_facts(&facts).expect("first evaluation");
        assert_eq!(first.decision, Decision::StepUpRequired);
        assert_eq!(
            engine.cached_decision_count(),
            1,
            "the step-up verdict must be the retained entry under test",
        );
        let second = engine.evaluate_facts(&facts).expect("cached evaluation");
        assert_eq!(
            second.decision,
            Decision::StepUpRequired,
            "a step-up requirement must not be served back as an allow",
        );
        assert_eq!(
            engine.cached_decision_count(),
            1,
            "the second answer must come from that entry, not a fresh decision",
        );
    }

    #[test]
    fn an_approval_requirement_survives_the_cache() {
        let engine = CedarEngine::from_source(
            r#"
            @id("permit-invokers")
            permit(principal, action, resource) when {
                principal.groups.contains("invokers")
            };
            @id("forbid-without-approval")
            forbid(principal, action, resource) when { !context.approval_present };
            "#,
        )
        .expect("policy parses");
        let facts = baseline();

        let first = engine.evaluate_facts(&facts).expect("first evaluation");
        assert_eq!(first.decision, Decision::ApprovalRequired);
        assert_eq!(
            engine.cached_decision_count(),
            1,
            "the approval verdict must be the retained entry under test",
        );
        let second = engine.evaluate_facts(&facts).expect("cached evaluation");
        assert_eq!(
            second.decision,
            Decision::ApprovalRequired,
            "an approval requirement must not be served back as an allow",
        );
        assert_eq!(
            engine.cached_decision_count(),
            1,
            "the second answer must come from that entry, not a fresh decision",
        );
    }

    #[test]
    fn the_cache_stays_within_its_capacity() {
        let cache = DecisionCache::new();
        let allow = AuthzResult {
            decision: Decision::Allow,
            reasons: vec![],
            policy_ids: vec![],
        };
        for index in 0..(CAPACITY + 128) {
            let mut facts = baseline();
            facts.resource.tool = format!("tool-{index}");
            cache.insert(DecisionKey::new(&facts, false), &allow);
        }
        assert_eq!(cache.len(), CAPACITY);
    }

    #[test]
    fn eviction_drops_the_oldest_entry_and_keeps_the_newest() {
        let cache = DecisionCache::new();
        let allow = AuthzResult {
            decision: Decision::Allow,
            reasons: vec![],
            policy_ids: vec![],
        };
        let key_for = |index: usize| {
            let mut facts = baseline();
            facts.resource.tool = format!("tool-{index}");
            DecisionKey::new(&facts, false)
        };
        for index in 0..CAPACITY {
            cache.insert(key_for(index), &allow);
        }
        assert!(cache.get(&key_for(0)).is_some());
        cache.insert(key_for(CAPACITY), &allow);
        assert!(
            cache.get(&key_for(0)).is_none(),
            "the oldest entry is evicted first",
        );
        assert!(cache.get(&key_for(CAPACITY)).is_some());
    }
}
