//! Shared store-layer error vocabulary.
//!
//! Two layers:
//!
//! 1. **Always available** — the Postgres SQLSTATE constants and code
//!    predicates. The class-23 literals used to be hand-written at ~46
//!    call sites across ten crates; the constants are now the single
//!    home (`scripts/check-shared-store-error.sh` enforces it), and a
//!    store maps them into its own domain error exactly as before.
//! 2. **Feature `store`** (optional `sqlx` — the `http`-feature pattern)
//!    — [`StoreError`], the ready-made enum + `From<sqlx::Error>` for
//!    stores without domain-specific variants. Adopt it in new stores;
//!    wholesale migration of the ~40 existing enums is deliberately out
//!    of scope (a shared `AdminResource` REST layer was evaluated and
//!    rejected; the per-resource handler modules own that surface).
//!
//! SQLSTATE class 23 (integrity constraint violation), per the Postgres
//! documentation. Only the codes the workspace actually matches on are
//! named; add here, not inline.

/// `unique_violation` — a UNIQUE / PRIMARY KEY collision. Stores map this
/// to their Conflict/Duplicate variant (HTTP 409 at the admin surface).
pub const UNIQUE_VIOLATION: &str = "23505";

/// `foreign_key_violation` — an INSERT/UPDATE/DELETE breaking an FK.
pub const FOREIGN_KEY_VIOLATION: &str = "23503";

/// `check_violation` — a CHECK constraint rejected the row.
pub const CHECK_VIOLATION: &str = "23514";

/// Predicate form for call sites that carry only the SQLSTATE code.
pub fn is_unique_violation_code(code: Option<&str>) -> bool {
    code == Some(UNIQUE_VIOLATION)
}

#[cfg(feature = "store")]
mod store_error {
    /// Ready-made store error for stores without domain-specific
    /// variants: the `23505` → [`StoreError::Conflict`] mapping lives in
    /// the `From<sqlx::Error>` impl, so a new store gets the workspace's
    /// conflict semantics with `?`.
    #[derive(Debug, thiserror::Error)]
    pub enum StoreError {
        /// UNIQUE / PRIMARY KEY collision (SQLSTATE `23505`).
        #[error("conflict: duplicate row")]
        Conflict,
        /// Row not found where one was required.
        #[error("not found")]
        NotFound,
        /// Any other database failure.
        #[error("database: {0}")]
        Database(#[source] sqlx::Error),
    }

    impl From<sqlx::Error> for StoreError {
        fn from(e: sqlx::Error) -> Self {
            match &e {
                sqlx::Error::RowNotFound => StoreError::NotFound,
                sqlx::Error::Database(db)
                    if db.code().as_deref() == Some(super::UNIQUE_VIOLATION) =>
                {
                    StoreError::Conflict
                }
                _ => StoreError::Database(e),
            }
        }
    }
}

#[cfg(feature = "store")]
pub use store_error::StoreError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_predicate_matches_only_unique_violation() {
        assert!(is_unique_violation_code(Some("23505")));
        assert!(!is_unique_violation_code(Some("23503")));
        assert!(!is_unique_violation_code(Some("23514")));
        assert!(!is_unique_violation_code(None));
    }

    #[test]
    fn sqlstate_constants_are_the_postgres_codes() {
        // The wire contract: these literals are what Postgres reports.
        assert_eq!(UNIQUE_VIOLATION, "23505");
        assert_eq!(FOREIGN_KEY_VIOLATION, "23503");
        assert_eq!(CHECK_VIOLATION, "23514");
    }

    #[cfg(feature = "store")]
    mod store_feature {
        use super::*;
        use std::borrow::Cow;

        #[test]
        fn row_not_found_maps_to_not_found() {
            assert!(matches!(
                StoreError::from(sqlx::Error::RowNotFound),
                StoreError::NotFound
            ));
        }

        /// Minimal [`sqlx::error::DatabaseError`] carrying only a SQLSTATE
        /// code, so the `From<sqlx::Error>` mapping can be pinned without a
        /// live database.
        #[derive(Debug)]
        struct CodeOnly(&'static str);

        impl std::fmt::Display for CodeOnly {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "sqlstate {}", self.0)
            }
        }

        impl std::error::Error for CodeOnly {}

        impl sqlx::error::DatabaseError for CodeOnly {
            fn message(&self) -> &str {
                "constraint violation"
            }
            fn code(&self) -> Option<Cow<'_, str>> {
                Some(Cow::Borrowed(self.0))
            }
            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::Other
            }
            fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
                self
            }
        }

        #[test]
        fn unique_violation_maps_to_conflict() {
            let e = sqlx::Error::Database(Box::new(CodeOnly(UNIQUE_VIOLATION)));
            assert!(matches!(StoreError::from(e), StoreError::Conflict));
        }

        #[test]
        fn other_constraint_codes_map_to_database() {
            let e = sqlx::Error::Database(Box::new(CodeOnly(FOREIGN_KEY_VIOLATION)));
            assert!(matches!(StoreError::from(e), StoreError::Database(_)));
        }
    }
}
