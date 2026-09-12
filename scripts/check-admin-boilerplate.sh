#!/usr/bin/env bash
# Admin mutation recording uses the shared helper. Change requests have a
# distinct event shape, outcome, and error contract and own their recorder.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
from pathlib import Path
import re

root = Path('crates/waygate-admin/src')
if not root.is_dir():
    raise SystemExit('check-admin-boilerplate: admin source directory is missing')
allowed = {
    ('admin_mutation.rs', 'record_admin_mutation'),
    ('admin_mutation.rs', 'record_admin_mutation_logged'),
    ('change_requests.rs', 'record_mutation'),
}
pattern = re.compile(r'\basync\s+fn\s+(record_[a-z_]*mutation[a-z_]*)\s*\(')
failures = []
for path in sorted(root.rglob('*.rs')):
    for match in pattern.finditer(path.read_text()):
        if (path.relative_to(root).as_posix(), match[1]) not in allowed:
            failures.append(f'{path}: use the shared mutation recorder instead of {match[1]}')
if failures:
    raise SystemExit('\n'.join(failures))
print('check-admin-boilerplate: OK (recorder ownership)')
PY
