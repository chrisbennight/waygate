#!/usr/bin/env bash
# Application settings belong to server configuration; component-owned settings
# below are explicit exceptions for independently initialized subsystems.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
from pathlib import Path
import re

# Health checks, logging, reload identity, and component-specific parsers can
# initialize independently of the server's configuration object.
allowed = {
    'crates/waygate-admin/src/dashboard.rs': {'GATEWAY_STATIC_DIR'},
    'crates/waygate-server/src/healthcheck.rs': {'GATEWAY_LISTEN_ADDR'},
    'crates/waygate-server/src/llm.rs': {'GATEWAY_LLM_EGRESS_PROXY'},
    'crates/waygate-server/src/reload.rs': {'GATEWAY_REPLICA_ID'},
    'crates/waygate-telemetry/src/lib.rs': {'GATEWAY_LOG_LEVEL'},
    'crates/waygate-upstream/src/pool/mod.rs': {
        'GATEWAY_CATALOG_STRICT_PENDING_APPROVAL',
        'GATEWAY_QUARANTINE_ON_DRIFT_RISK', 'GATEWAY_UPSTREAM_POOL_SIZE',
    },
    # Composition owns inspector toggles, secret decoding, and adapter maps.
    'crates/waygate-server/src/main.rs': {
        'GATEWAY_CHANGE_SECRET_KEY', 'GATEWAY_PII_REDACT', 'GATEWAY_PII_MODE',
        'GATEWAY_SECRET_REDACT', 'GATEWAY_POISONING_REDACT',
        'GATEWAY_LLM_DISCOVERY', 'GATEWAY_LLM_CRED_RELOAD',
        'GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS',
    },
}
root = Path('crates')
if not root.is_dir():
    raise SystemExit('check-env-parsing: crates directory is missing')
pattern = re.compile(r'\benv::var(?:_os)?\s*\(\s*"(GATEWAY_[A-Z0-9_]+)"')
failures = []
for path in sorted(root.rglob('*.rs')):
    if 'tests' in path.parts or path.name == 'tests.rs':
        continue
    if (path.as_posix() in {'crates/waygate-server/src/config.rs',
                             'crates/waygate-server/src/retention_config.rs'}
            or path.as_posix().startswith('crates/waygate-server/src/config/')):
        continue
    source = path.read_text()
    for match in pattern.finditer(source):
        if match[1] not in allowed.get(path.as_posix(), set()):
            line = source.count('\n', 0, match.start()) + 1
            failures.append(f'{path}:{line}: route {match[1]} through server configuration')
if failures:
    raise SystemExit('\n'.join(failures))
print('check-env-parsing: OK (configuration ownership)')
PY
