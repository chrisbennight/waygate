// This crate embeds the workspace migration set via `sqlx::migrate!`, which
// only registers the migration files that exist at compile time. Without a
// directory-level dependency, adding a new migration leaves this crate's
// previously built artifacts with a stale embedded set, and every runtime
// migration then fails with VersionMissing once any rebuilt crate has applied
// the new version.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
