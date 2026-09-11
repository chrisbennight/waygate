//! Regression guard for the `anyhow` 1.0.103 security bump
//! (RUSTSEC-2026-0190).
//!
//! `anyhow` versions before 1.0.103 could violate Stacked Borrows and trigger
//! undefined behaviour when an `anyhow::Error` that has had context attached
//! via `Error::context` is later mutably downcast through
//! `Error::downcast_mut`. 1.0.103 fixes the unsound mutable-reference
//! construction (upstream issue #451).
//!
//! This test exercises exactly that surface: attach context to a concrete
//! error, then recover and mutate it through `downcast_mut`. It asserts the
//! *contract* the advisory is about — `downcast_mut::<T>()` on a
//! context-wrapped error returns the underlying `T`, and a mutation made
//! through that reference persists. Run under Miri
//! (`cargo +nightly miri test`) it fails on the affected versions and passes
//! on >= 1.0.103; under the normal `cargo test` runner it documents and
//! exercises the fixed path and guards against an accidental `anyhow`
//! downgrade that breaks the downcast-after-context contract. This crate does
//! not call `downcast_mut` in production, so this is the only place the fixed
//! surface is covered.

use anyhow::Error;

#[derive(Debug, PartialEq, Eq)]
struct Sentinel(u32);

impl std::fmt::Display for Sentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sentinel({})", self.0)
    }
}

impl std::error::Error for Sentinel {}

#[test]
fn downcast_mut_after_context_is_sound() {
    // Precondition of RUSTSEC-2026-0190: a concrete error wrapped by anyhow
    // with context layered on top — mirrors how the crate attaches
    // `.context(...)` to fallible operations at its binary boundary.
    let mut err: Error = Error::new(Sentinel(1)).context("while doing the operation");

    // The fixed surface: mutably downcast back to the concrete error through
    // the context layer and mutate it.
    let inner = err
        .downcast_mut::<Sentinel>()
        .expect("Sentinel must be recoverable through the context layer");
    assert_eq!(*inner, Sentinel(1));
    inner.0 = 2;

    // The mutation made through the downcast reference must be observable on a
    // subsequent read of the same error chain.
    assert_eq!(
        err.downcast_ref::<Sentinel>(),
        Some(&Sentinel(2)),
        "mutation through downcast_mut must persist on the context-wrapped error",
    );
}
