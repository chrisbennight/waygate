//! One vocabulary for "is this admin surface wired?"
//!
//! Every optional store/service handle on [`crate::AdminState`] used to be a
//! bare `Option<T>`, and each of the ~107 handlers guarding on it hand-typed
//! its own `ApiError::ServiceUnavailable("… not configured")` literal. The
//! copies drifted ("audit store" vs "audit reader" for the same field), and
//! nothing tied the message to the field it described.
//!
//! [`Capability<T>`] replaces that: the field carries its canonical
//! operator-facing unavailable-message, set once where the field is declared
//! (`AdminState::new`), and every consumer goes through one of:
//!
//! - [`Capability::require`] — REST guards: `&T` or the canonical 503.
//! - [`Capability::get`] — dashboard "store not configured" cards and other
//!   render-degraded paths that don't want an error.
//! - [`Capability::enabled`] — bare feature checks (`store_configured` flags).
//! - [`Capability::unavailable_msg`] — surfaces with their own error shape
//!   (SCIM's protocol-mandated bodies, `resource_catalog::ReadError`) reuse
//!   the same message instead of minting another literal.
//!
//! `scripts/check-capability-guards.sh` enforces the vocabulary in CI: new
//! inline `ServiceUnavailable("…")` literals outside this module fail the
//! build unless allow-listed there.
//!
//! Feature *flags* whose meaning is "this surface is administratively off"
//! use the sibling [`Feature`] type: it carries the
//! operator-facing off-reason (shown read-only in the UI) plus a canonical
//! `&'static` unavailable-message for guard shapes that need one. The
//! api-keys runtime flag and policy editing are `Feature`s.
//!
//! Deliberately NOT here (they are not availability capabilities):
//! cache-invalidation side-channels (`rbac_enricher`, `scim_enricher`,
//! `tenant_enricher`, `api_key_validator`, `federated_peers_cache`), optional
//! notifiers (`change_notifier`), configuration directories (`servers_dir`,
//! `policies_dir`), and other config values (`trace_url_template`, locks).

use crate::error::ApiError;

/// An optionally-wired admin capability plus its canonical unavailable
/// message. See the module docs for the consumption vocabulary.
pub struct Capability<T> {
    inner: Option<T>,
    /// Canonical operator-facing message for the 503 / not-configured card,
    /// e.g. `"tenants store not configured"`. `&'static` on purpose: it flows
    /// into `ApiError::ServiceUnavailable(&'static str)` unchanged.
    unavailable: &'static str,
}

impl<T> Capability<T> {
    /// Wrap an already-resolved handle. `AdminState::new` uses this for the
    /// capabilities that arrive as positional `Option` args.
    pub fn new(unavailable: &'static str, inner: Option<T>) -> Self {
        Self { inner, unavailable }
    }

    /// An unwired capability. `AdminState::new` initializes every
    /// builder-populated capability this way so the message lives in exactly
    /// one place; the `with_*` builders then [`Capability::set`] the handle
    /// without touching the message.
    pub fn absent(unavailable: &'static str) -> Self {
        Self {
            inner: None,
            unavailable,
        }
    }

    /// Install (or clear) the handle, keeping the canonical message.
    pub fn set(&mut self, inner: Option<T>) {
        self.inner = inner;
    }

    /// The REST guard: the handle, or the canonical 503. Replaces the inline
    /// `.as_ref().ok_or(ApiError::ServiceUnavailable("…"))?` idiom.
    pub fn require(&self) -> Result<&T, ApiError> {
        self.inner
            .as_ref()
            .ok_or(ApiError::ServiceUnavailable(self.unavailable))
    }

    /// Render-degraded access: `Some(&T)` when wired, no error. Dashboard
    /// pages use this for their "store not configured" cards.
    pub fn get(&self) -> Option<&T> {
        self.inner.as_ref()
    }

    /// `true` when the capability is wired. Replaces `.is_some()`.
    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// The canonical message, for surfaces with their own error shape (SCIM
    /// bodies, `resource_catalog::ReadError::Unavailable`).
    pub fn unavailable_msg(&self) -> &'static str {
        self.unavailable
    }
}

/// An administratively-switchable feature: enabled, or disabled with an
/// operator-facing reason. The `Feature` analogue of [`Capability`] — a
/// capability answers "is the dependency wired?", a feature answers "did the
/// operator turn this surface on?". Both can gate the same endpoint (e.g.
/// API-key minting requires the feature ON and the store WIRED — the store
/// stays usable by cleanup paths when the feature is off).
pub struct Feature {
    /// `None` = enabled. `Some(reason)` = disabled, with the operator-facing
    /// why (rendered read-only in the dashboard, threaded into 403 bodies).
    off_reason: Option<String>,
    /// Canonical unavailable-message for guard shapes that need a `&'static`
    /// string (`ApiError::ServiceUnavailable`, `ReadError::Unavailable`) —
    /// intentionally less specific than `off_reason` when the reason is
    /// computed at boot.
    unavailable: &'static str,
}

impl Feature {
    /// An enabled feature. Builders flip it off via [`Feature::set_off_reason`].
    pub fn enabled_with(unavailable: &'static str) -> Self {
        Self {
            off_reason: None,
            unavailable,
        }
    }

    /// A disabled feature with its operator-facing reason.
    pub fn disabled(unavailable: &'static str, reason: impl Into<String>) -> Self {
        Self {
            off_reason: Some(reason.into()),
            unavailable,
        }
    }

    /// Install (or clear) the off-reason, keeping the canonical message.
    pub fn set_off_reason(&mut self, reason: Option<String>) {
        self.off_reason = reason;
    }

    /// `true` when the feature is on.
    pub fn enabled(&self) -> bool {
        self.off_reason.is_none()
    }

    /// The operator-facing reason the feature is off; `None` when enabled.
    pub fn off_reason(&self) -> Option<&str> {
        self.off_reason.as_deref()
    }

    /// The REST guard: `Ok(())` when enabled, the canonical 503 when off.
    pub fn require(&self) -> Result<(), ApiError> {
        if self.off_reason.is_none() {
            Ok(())
        } else {
            Err(ApiError::ServiceUnavailable(self.unavailable))
        }
    }

    /// The canonical message, for guard shapes with their own error type.
    pub fn unavailable_msg(&self) -> &'static str {
        self.unavailable
    }
}

#[cfg(test)]
mod feature_tests {
    use super::*;

    #[test]
    fn enabled_feature_passes_require() {
        let ft = Feature::enabled_with("x feature disabled");
        assert!(ft.enabled());
        assert!(ft.require().is_ok());
        assert_eq!(ft.off_reason(), None);
    }

    #[test]
    fn disabled_feature_503s_with_canonical_msg_and_keeps_reason() {
        let ft = Feature::disabled("x feature disabled", "flag off in env");
        assert!(!ft.enabled());
        assert_eq!(ft.off_reason(), Some("flag off in env"));
        assert!(matches!(
            ft.require().unwrap_err(),
            ApiError::ServiceUnavailable("x feature disabled")
        ));
    }

    #[test]
    fn set_off_reason_toggles_without_losing_message() {
        let mut ft = Feature::enabled_with("x feature disabled");
        ft.set_off_reason(Some("maintenance".into()));
        assert!(!ft.enabled());
        ft.set_off_reason(None);
        assert!(ft.enabled());
        assert_eq!(ft.unavailable_msg(), "x feature disabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn require_returns_handle_when_wired() {
        let cap = Capability::new("x store not configured", Some(7));
        assert_eq!(cap.require().copied().unwrap(), 7);
        assert!(cap.enabled());
        assert_eq!(cap.get(), Some(&7));
    }

    #[test]
    fn require_maps_absent_to_canonical_503() {
        let cap: Capability<u8> = Capability::absent("x store not configured");
        let err = cap.require().unwrap_err();
        assert!(matches!(
            err,
            ApiError::ServiceUnavailable("x store not configured")
        ));
        // The contract the 107 inline guards relied on: a 503 response.
        assert_eq!(
            err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(!cap.enabled());
        assert_eq!(cap.get(), None);
    }

    #[test]
    fn set_installs_and_clears_without_losing_message() {
        let mut cap: Capability<u8> = Capability::absent("x store not configured");
        cap.set(Some(1));
        assert!(cap.enabled());
        cap.set(None);
        assert!(!cap.enabled());
        assert_eq!(cap.unavailable_msg(), "x store not configured");
    }
}
