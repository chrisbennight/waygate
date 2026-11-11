//! Injected API credentials for inference. No consumer sign-in, token refresh,
//! JWT decoding, network client, or credential write-back is implemented here.
//! OpenAI/Gemini require explicit API-key envelopes; Anthropic/OpenRouter retain
//! bare API keys. Scoped rotation uses the same parser and preserves a prior key
//! when replacement material is invalid.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Google,
    OpenRouter,
}

impl LlmProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::OpenRouter => "openrouter",
        }
    }
    /// Persisted identifiers remain stable for historical usage and audit.
    pub fn from_canonical_str(value: &str) -> Option<Self> {
        match value {
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "google" => Some(Self::Google),
            "openrouter" => Some(Self::OpenRouter),
            _ => None,
        }
    }
    /// Shared vocabulary for injected keys and scoped API-key rotation.
    pub fn from_env_token(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "OPENAI" => Some(Self::OpenAi),
            "ANTHROPIC" => Some(Self::Anthropic),
            "GOOGLE" | "GEMINI" => Some(Self::Google),
            "OPENROUTER" => Some(Self::OpenRouter),
            _ => None,
        }
    }
}

/// Locally loaded API key; this does not attest provider validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialStatus {
    pub provider: LlmProvider,
    pub label: String,
    pub health: Health,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("no API credential configured for {provider}/{label}")]
    NotConfigured {
        provider: &'static str,
        label: String,
    },
}

/// Rejected values are never included in errors or diagnostic metadata.
#[derive(Debug, thiserror::Error)]
pub enum CredentialConfigError {
    #[error("consumer subscription credentials are no longer supported for {provider}/{label}; configure a provider API key using the API migration guide")]
    SubscriptionUnsupported {
        provider: &'static str,
        label: String,
    },
    #[error("invalid API credential for {provider}/{label}; OpenAI/Gemini require an explicit api_key envelope, Anthropic/OpenRouter require a bare API key")]
    InvalidApiKey {
        provider: &'static str,
        label: String,
    },
    #[error("consumer OAuth setting {name} is no longer supported; remove it and configure provider API credentials")]
    RemovedOAuthSetting { name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("no credential configured for {provider}/{label} to reload")]
    NotConfigured {
        provider: &'static str,
        label: String,
    },
    #[error("the reloaded value is not a valid API credential for {0}; prior key retained")]
    Unparseable(&'static str),
    #[error(
        "consumer subscription credentials are no longer supported for {0}; prior API key retained"
    )]
    SubscriptionUnsupported(&'static str),
}

enum ValueError {
    Subscription,
    Invalid,
}

fn parse_env_key(key: &str) -> Option<(LlmProvider, String)> {
    let (provider, label) = key.strip_prefix("LLM_CRED_")?.split_once('_')?;
    let provider = LlmProvider::from_env_token(provider)?;
    (!label.is_empty()).then(|| (provider, label.to_owned()))
}

fn valid_key(value: &str) -> bool {
    !value.is_empty() && !value.starts_with(['{', '[']) && !value.chars().any(char::is_control)
}

fn parse_api_key(provider: LlmProvider, raw: &str) -> Result<String, ValueError> {
    let value = raw.trim();
    let object = serde_json::from_str::<serde_json::Value>(value).ok();
    if object.as_ref().is_some_and(|object| {
        [
            "tokens",
            "access_token",
            "refresh_token",
            "id_token",
            "claudeAiOauth",
        ]
        .iter()
        .any(|key| object.get(key).is_some())
    }) {
        return Err(ValueError::Subscription);
    }
    if matches!(provider, LlmProvider::OpenAi | LlmProvider::Google) {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            api_key: String,
        }
        let envelope: Envelope = serde_json::from_str(value).map_err(|_| ValueError::Invalid)?;
        let key = envelope.api_key.trim();
        if valid_key(key) {
            Ok(key.to_owned())
        } else {
            Err(ValueError::Invalid)
        }
    } else if valid_key(value) {
        Ok(value.to_owned())
    } else {
        Err(ValueError::Invalid)
    }
}

/// In-memory keys supplied by deployment, with atomic replacement per credential.
pub struct LlmCredentialStore {
    creds: HashMap<(LlmProvider, String), Arc<Mutex<String>>>,
}

impl LlmCredentialStore {
    pub fn from_env() -> Result<Self, CredentialConfigError> {
        Self::try_from_vars(std::env::vars())
    }

    /// Convenience constructor for explicit valid fixture configuration.
    pub fn from_vars<I: IntoIterator<Item = (String, String)>>(vars: I) -> Self {
        Self::try_from_vars(vars).expect("valid injected API credential configuration")
    }

    /// Fail unsupported configuration instead of silently changing routing pools.
    pub fn try_from_vars<I: IntoIterator<Item = (String, String)>>(
        vars: I,
    ) -> Result<Self, CredentialConfigError> {
        let mut creds = HashMap::new();
        for (name, raw) in vars {
            if let Some((provider, label)) = parse_env_key(&name) {
                let key = parse_api_key(provider, &raw).map_err(|error| match error {
                    ValueError::Subscription => CredentialConfigError::SubscriptionUnsupported {
                        provider: provider.as_str(),
                        label: label.clone(),
                    },
                    ValueError::Invalid => CredentialConfigError::InvalidApiKey {
                        provider: provider.as_str(),
                        label: label.clone(),
                    },
                })?;
                creds.insert((provider, label), Arc::new(Mutex::new(key)));
            } else if name.starts_with("LLM_OAUTH_") && !raw.trim().is_empty() {
                return Err(CredentialConfigError::RemovedOAuthSetting { name });
            }
        }
        Ok(Self { creds })
    }

    pub fn labels(&self, provider: LlmProvider) -> Vec<String> {
        let mut labels: Vec<_> = self
            .creds
            .keys()
            .filter(|(p, _)| *p == provider)
            .map(|(_, label)| label.clone())
            .collect();
        labels.sort();
        labels
    }

    pub async fn health(&self, provider: LlmProvider, label: &str) -> Option<Health> {
        self.creds
            .contains_key(&(provider, label.to_owned()))
            .then_some(Health::Healthy)
    }

    pub async fn status_snapshot(&self) -> Vec<CredentialStatus> {
        let mut rows: Vec<_> = self
            .creds
            .keys()
            .map(|(provider, label)| CredentialStatus {
                provider: *provider,
                label: label.clone(),
                health: Health::Healthy,
            })
            .collect();
        rows.sort_by(|a, b| (a.provider.as_str(), &a.label).cmp(&(b.provider.as_str(), &b.label)));
        rows
    }

    /// Invalid material cannot overwrite an admitted key. Reads and replacement
    /// share the credential lock; parsing needs no network or external authority.
    pub async fn reload(
        &self,
        provider: LlmProvider,
        label: &str,
        raw: &str,
    ) -> Result<(), ReloadError> {
        let cell = self
            .creds
            .get(&(provider, label.to_owned()))
            .ok_or_else(|| ReloadError::NotConfigured {
                provider: provider.as_str(),
                label: label.to_owned(),
            })?;
        let key = parse_api_key(provider, raw).map_err(|error| match error {
            ValueError::Subscription => ReloadError::SubscriptionUnsupported(provider.as_str()),
            ValueError::Invalid => ReloadError::Unparseable(provider.as_str()),
        })?;
        *cell.lock().await = key;
        Ok(())
    }

    pub async fn api_key(
        &self,
        provider: LlmProvider,
        label: &str,
    ) -> Result<String, CredentialError> {
        let cell = self
            .creds
            .get(&(provider, label.to_owned()))
            .ok_or_else(|| CredentialError::NotConfigured {
                provider: provider.as_str(),
                label: label.to_owned(),
            })?;
        Ok(cell.lock().await.clone())
    }

    /// API-key bearer authentication for compatible APIs. No token refresh.
    pub async fn bearer(
        &self,
        provider: LlmProvider,
        label: &str,
    ) -> Result<String, CredentialError> {
        self.api_key(provider, label).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_identifiers_and_configuration_aliases_remain_distinct() {
        for p in [
            LlmProvider::OpenAi,
            LlmProvider::Anthropic,
            LlmProvider::Google,
            LlmProvider::OpenRouter,
        ] {
            assert_eq!(LlmProvider::from_canonical_str(p.as_str()), Some(p));
        }
        assert_eq!(LlmProvider::from_canonical_str("gemini"), None);
        assert_eq!(
            LlmProvider::from_env_token("GEMINI"),
            Some(LlmProvider::Google)
        );
        assert_eq!(
            parse_env_key("LLM_CRED_ANTHROPIC_FAMILY_2"),
            Some((LlmProvider::Anthropic, "FAMILY_2".into()))
        );
        assert_eq!(parse_env_key("LLM_CRED_OPENAI"), None);
    }

    #[tokio::test]
    async fn supported_keys_load_without_a_network_client() {
        let store = LlmCredentialStore::from_vars([
            (
                "LLM_CRED_OPENAI_API".into(),
                r#"{"api_key":"synthetic-openai"}"#.into(),
            ),
            (
                "LLM_CRED_GEMINI_API".into(),
                r#"{"api_key":"synthetic-gemini"}"#.into(),
            ),
            (
                "LLM_CRED_ANTHROPIC_API".into(),
                "synthetic-anthropic".into(),
            ),
            (
                "LLM_CRED_OPENROUTER_API".into(),
                "synthetic-openrouter".into(),
            ),
        ]);
        for (p, key) in [
            (LlmProvider::OpenAi, "synthetic-openai"),
            (LlmProvider::Google, "synthetic-gemini"),
            (LlmProvider::Anthropic, "synthetic-anthropic"),
            (LlmProvider::OpenRouter, "synthetic-openrouter"),
        ] {
            assert_eq!(store.labels(p), vec!["API"]);
            assert_eq!(store.api_key(p, "API").await.unwrap(), key);
            assert_eq!(store.health(p, "API").await, Some(Health::Healthy));
        }
        assert_eq!(store.status_snapshot().await.len(), 4);
    }

    #[test]
    fn subscription_configuration_errors_do_not_expose_values() {
        for provider in ["OPENAI", "GOOGLE", "ANTHROPIC"] {
            let result=LlmCredentialStore::try_from_vars([(format!("LLM_CRED_{provider}_OLD"),r#"{"tokens":{"access_token":"synthetic-private-access","refresh_token":"synthetic-private-refresh"}}"#.into())]);
            let error = match result {
                Err(e) => e,
                Ok(_) => panic!("subscription accepted"),
            };
            assert!(matches!(
                error,
                CredentialConfigError::SubscriptionUnsupported { .. }
            ));
            assert!(!format!("{error:?} {error}").contains("synthetic-private"));
        }
        let error = match LlmCredentialStore::try_from_vars([(
            "LLM_OAUTH_GOOGLE_CLIENT_SECRET".into(),
            "synthetic-private-setting".into(),
        )]) {
            Err(e) => e,
            Ok(_) => panic!("refresh setting accepted"),
        };
        assert!(matches!(
            error,
            CredentialConfigError::RemovedOAuthSetting { .. }
        ));
        assert!(!format!("{error:?} {error}").contains("synthetic-private-setting"));
    }

    #[test]
    fn invalid_keys_and_mixed_envelopes_fail_instead_of_disappearing() {
        for value in [
            "synthetic-bare-openai",
            r#"{"api_key":""}"#,
            r#"{"api_key":"synthetic","extra":"field"}"#,
            r#"{"api_key":"{token blob}"}"#,
            r#"{"api_key":"bad\nheader"}"#,
        ] {
            assert!(LlmCredentialStore::try_from_vars([(
                "LLM_CRED_OPENAI_BAD".into(),
                value.into()
            )])
            .is_err());
        }
    }

    #[tokio::test]
    async fn api_rotation_rejects_subscription_material_and_preserves_the_prior_key() {
        let store = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_API".into(),
            r#"{"api_key":"synthetic-first"}"#.into(),
        )]);
        assert!(matches!(store.reload(LlmProvider::OpenAi,"API",r#"{"tokens":{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}}"#).await,Err(ReloadError::SubscriptionUnsupported("openai"))));
        assert_eq!(
            store.api_key(LlmProvider::OpenAi, "API").await.unwrap(),
            "synthetic-first"
        );
        store
            .reload(
                LlmProvider::OpenAi,
                "API",
                r#"{"api_key":"synthetic-second"}"#,
            )
            .await
            .unwrap();
        assert_eq!(
            store.api_key(LlmProvider::OpenAi, "API").await.unwrap(),
            "synthetic-second"
        );
        assert!(matches!(
            store
                .reload(LlmProvider::OpenAi, "MISSING", r#"{"api_key":"synthetic"}"#)
                .await,
            Err(ReloadError::NotConfigured { .. })
        ));
    }
}
