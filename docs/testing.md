# Test timing and CI

Required CI must not fail solely because the runner is heavily loaded.
Increasing timing thresholds or rerunning a flaky test is not a remedy.
Required CI checks correctness without assuming an idle host. Coordinate
concurrent operations with channels, notifications, or barriers, and assert
which operations finish before a blocked operation is released. Do not use a
short sleep or elapsed-time threshold to prove that ordering.

The nextest CI profile retains its five-minute watchdog to detect a hung test.
That limit is a test-runner safeguard, not a latency acceptance criterion.
A deliberately injected database lock timeout may force an error, but must not
put a performance deadline on the successful transaction.

## Explicit wall-clock checks

Tests marked `#[ignore = "wall-clock integration check; ..."]` are excluded
from ordinary Cargo and nextest runs, including required PR and image-build
CI. They remain available for explicit execution on an idle host:

```sh
cargo test --locked -p waygate-upstream --test suite \
  listen_fanin_http::listener_drives_rate_bounded_event_refreshes -- --ignored --exact \
  --test-threads=1
```

For a module-qualified test, use its full name as printed by
`cargo test -p waygate-upstream --test suite -- --list`, for example
`listen_fanin_http::listener_drives_rate_bounded_event_refreshes`.
Do not enable all ignored tests in a required CI workflow.

The checks moved out of CI currently exercise:

- JavaScript startup and execution within a short real-time budget.
- Killing a live runner after observing process CPU ticks, then recovering.
- Streaming file writes and retention measured against the host clock.
- HTTP listener rate-window coalescing.
- HTTP timeout placement during the pre-dispatch session contract read.
- Connection-refused races and process teardown latency.
- Live reconnect scheduling and process wait latency.

The post-dispatch timeout test remains in required CI. Its mock signals when
dispatch occurs and withholds the response; only then does the test advance
Tokio's clock to expire the call. It asserts unknown-outcome classification and
no replay without an elapsed-time threshold.

The boot-deadlock regression also remains required: a silent subprocess waits
indefinitely, and the test asserts the dial timeout and disconnected slot. It
has no separate completion deadline or elapsed-time assertion.

These are excluded checks, not passing checks. Existing deterministic error,
cancellation, retry, and transaction tests remain required. Convert an excluded
check to explicit synchronization or an injected clock before returning it to
required CI; preserving its name alone does not preserve its contract.

## Performance and context measurements

Run `cargo bench -p waygate-mcp --bench validator_cache --locked` to compare
schema compilation, cached validation, and hashing plus cached validation on
the same host and toolchain. The benchmark excludes network and database work;
it is not an end-to-end latency or capacity measurement.

Use [the tool-context report](tool-context-budget.md) to measure the catalog
presented to an authorized client. Record inputs and resource conditions so
comparisons remain reproducible.
