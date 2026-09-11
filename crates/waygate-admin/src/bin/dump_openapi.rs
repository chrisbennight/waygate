//! Dump the gateway's `/api/v1` OpenAPI
//! spec to stdout, decoupled from a running server.
//!
//! ## Why a separate binary
//!
//! - Operators generating client SDKs in CI shouldn't have to
//!   boot Postgres, bind a port, or supply runtime config just
//!   to read the schema — utoipa builds the spec from
//!   compile-time annotations, no I/O needed.
//! - Pinning the spec to disk (`openapi.json`) makes diffs
//!   readable in code review when the surface changes, even
//!   though we don't (today) commit the file to git.
//! - `scripts/gen-clients.sh` consumes this output to feed
//!   `openapi-generator-cli`; the script's contract is "give
//!   me a JSON blob on stdout," so the binary stays
//!   dependency-light.
//!
//! ## Output
//!
//! - Stdout: the spec, pretty-printed JSON (newline at end of
//!   file).
//! - Exit 0 on success, non-zero if serialization fails (which
//!   would indicate a `ToSchema` derive misbehaviour and is
//!   itself a bug we want loud).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --bin dump-openapi -p waygate-admin > openapi.json
//! ```

use utoipa::OpenApi;
use waygate_admin::ApiDoc;

fn main() {
    let spec = ApiDoc::openapi();
    match serde_json::to_string_pretty(&spec) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("dump-openapi: failed to serialize ApiDoc::openapi(): {e}");
            std::process::exit(1);
        }
    }
}
