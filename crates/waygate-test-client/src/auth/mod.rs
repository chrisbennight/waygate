//! Authentication surface.
//!
//! A resolver turns `--auth` + cached tokens + discovery output into the
//! Authorization header (if any) each RPC call should carry.

pub mod bearer;
pub mod cache;
pub mod cimd;
pub mod login;
pub mod resolver;

pub use resolver::{resolve_bearer, ResolvedAuth};
