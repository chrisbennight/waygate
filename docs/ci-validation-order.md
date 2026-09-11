# CI validation order

The GitHub image workflow validates source before building or publishing an image:

1. Run source guards, install the checked-in Rust toolchain, and check formatting.
2. Install the pinned test runner and run Clippy.
3. Compile workspace tests and the tool-context projection example with
   `cargo nextest run --workspace --locked --profile ci --no-run`.
4. Run the compiled projection example through the tool-context budget reporter.
5. Start Postgres and run `cargo nextest run --workspace --locked --profile ci`.
6. Run workspace doctests and `cargo check --workspace`.
7. Clean up Postgres, including on failure.
8. Build the optimized image and run its smoke tests. Eligible push events then
   publish the verified image according to the [release contract](source-release.md).

Compilation and test execution use the same job and target directory. Postgres
starts after compilation and stays available through doctests. The database
suites and image smoke use the same pinned Postgres build.

Clippy checks do not replace executable code generation. Nextest does not run
doctests, and development test artifacts do not replace the optimized image
build. Preserve these validation boundaries when changing CI.

Compare compilation, test execution, image build, and total run durations
separately. Report skipped tests separately from passes.
