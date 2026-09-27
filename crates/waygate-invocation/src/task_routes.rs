//! Upstream task ownership and routing persistence seam, independent of the wire adapter.
use crate::InvocationContractIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;
use waygate_core::store::StoreError;
use waygate_oidc::Principal;

#[derive(Clone, Serialize, Deserialize)]
pub struct TaskRoute {
    sub: String,
    issuer: String,
    pub tenant: String,
    profile: Value,
    auth_method: String,
    pub server: String,
    pub tool: String,
    pub upstream_id: String,
    pub binding: String,
    pub contract: InvocationContractIdentity,
    /// Only reviewed operation selection is retained, never tool arguments.
    pub operation_arguments: Map<String, Value>,
    pub request_facts: waygate_core::RequestFacts,
    pub created_at: String,
    pub ttl_ms: u64,
    pub exp: i64,
}
impl TaskRoute {
    pub fn belongs_to(&self, principal: &Principal) -> bool {
        self.sub == principal.sub
            && self.issuer == principal.issuer
            && self.tenant == principal.tenant.as_str()
            && self.profile == profile(principal)
            && self.auth_method == principal.auth_method.as_str()
    }

    pub fn new(
        principal: &Principal,
        server: &str,
        tool: &str,
        binding: String,
        contract: InvocationContractIdentity,
        operation_arguments: Map<String, Value>,
        request_facts: waygate_core::RequestFacts,
    ) -> Self {
        Self {
            sub: principal.sub.clone(),
            issuer: principal.issuer.clone(),
            tenant: principal.tenant.as_str().into(),
            profile: profile(principal),
            auth_method: principal.auth_method.as_str().into(),
            server: server.into(),
            tool: tool.into(),
            binding,
            contract,
            operation_arguments,
            request_facts,
            upstream_id: String::new(),
            created_at: String::new(),
            ttl_ms: 0,
            exp: 0,
        }
    }
}

fn profile(principal: &Principal) -> Value {
    principal
        .api_key_profile_restrictions
        .as_ref()
        .map_or(Value::Null, |p| {
            let mut servers = p.allowed_servers.clone().unwrap_or_default();
            servers.sort();
            servers.dedup();
            let mut tools = p.allowed_tools.clone().unwrap_or_default();
            tools.sort();
            tools.dedup();
            serde_json::json!({"profile_id": p.profile_id, "servers": servers, "tools": tools})
        })
}
#[async_trait::async_trait]
pub trait TaskRouteStore: Send + Sync {
    /// Insert only. An existing identifier must never be rebound or have its expiry extended.
    async fn insert(&self, id: Uuid, route: &TaskRoute) -> Result<(), StoreError>;
    /// Return a live route in this tenant. Callers must additionally check ownership and policy.
    async fn get(&self, id: Uuid, tenant: &str) -> Result<Option<TaskRoute>, StoreError>;
}
