//! Conformance suite entry point.
//!
//! The suite is split into "light" and "heavy" tiers. `light` is meant to
//! run in ~5 seconds on a live gateway and gates PR merges; `heavy` adds
//! pagination, error-shape, and refresh-token round-trip checks useful
//! before cutting a release.

pub mod heavy;
pub mod light;
pub mod report;

use anyhow::Result;

use crate::cli::{ConformanceArgs, Context};
use crate::conformance::report::{Report, Status};

pub async fn run(ctx: &Context, args: ConformanceArgs) -> Result<()> {
    let mut report = Report::new();
    light::run(ctx, &mut report).await;

    if args.heavy {
        heavy::run(ctx, &mut report).await;
    }

    report.print(ctx.json);

    match report.overall() {
        Status::Pass => Ok(()),
        Status::Skip => Ok(()),
        Status::Fail => {
            // Bubble up as a non-zero exit without duplicating the already-
            // rendered report on stderr.
            std::process::exit(1)
        }
    }
}
