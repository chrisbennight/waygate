#!/usr/bin/env bash
# CI tripwire: documentation anchors must
# resolve. Two checks over every git-tracked file:
#   PATH — any repo file path referenced in a *.md file or a Rust doc
#          comment (//! or ///) must exist (glob suffixes, {a,b} brace
#          lists, and `migrations/NNNN` prefix references are understood).
#   LINK — any relative markdown link target must exist.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import os, re, subprocess, sys, glob as globmod

PATH_RE = re.compile(
    r'(?<![\w/-])((?:crates|docs|scripts|migrations|\.github)/'
    r'[A-Za-z0-9_.\-/]*(?:\{[^}]*\})?[A-Za-z0-9_.\-/]*)')
LINK_RE = re.compile(r'\[[^\]]*\]\(([^)#\s]+)(?:#[^)\s]*)?\)')

def tracked(pat):
    out = subprocess.run(['git', 'ls-files', pat], capture_output=True, text=True)
    return [f for f in out.stdout.split('\n') if f and os.path.exists(f)]

def norm(p):
    p = p.rstrip('.,;:)`\'"')
    p = re.sub(r':\d+(?:[-,]\d+)*$', '', p)
    p = re.sub(r'::[A-Za-z_][A-Za-z0-9_:]*$', '', p)
    return p

def expand(p):
    m = re.match(r'(.*)\{([^}]*)\}(.*)', p)
    if not m:
        return [p]
    return [m.group(1) + part.strip() + m.group(3) for part in m.group(2).split(',')]

fails = []

def check_path(src, ln, line, raw):
    if line[line.find(raw) + len(raw):][:1] == '*':
        if not globmod.glob(raw + '*'):
            fails.append(('PATH', src, ln, raw + '* (glob, no match)'))
        return
    if re.fullmatch(r'migrations/\d{4}', raw):
        if not globmod.glob(raw + '_*'):
            fails.append(('PATH', src, ln, raw + '_* (migration prefix, no match)'))
        return
    for p in expand(norm(raw)):
        if '*' in p:
            continue
        if p.endswith('/'):
            if not os.path.isdir(p.rstrip('/')):
                fails.append(('PATH', src, ln, p))
            continue
        if not os.path.exists(p):
            fails.append(('PATH', src, ln, p))

md_files = tracked('*.md')
for f in md_files:
    base = os.path.dirname(f)
    for i, line in enumerate(open(f, encoding='utf-8', errors='replace'), 1):
        for m in PATH_RE.finditer(line):
            check_path(f, i, line, m.group(1))
        for m in LINK_RE.finditer(line):
            tgt = m.group(1)
            if tgt.startswith(('http://', 'https://', 'mailto:')):
                continue
            resolved = os.path.normpath(os.path.join(base, tgt))
            if resolved.startswith('..'):
                continue  # escapes the repo; not checkable here
            if not os.path.exists(resolved):
                fails.append(('LINK', f, i, f'{tgt} -> {resolved}'))

for f in tracked('*.rs'):
    for i, line in enumerate(open(f, encoding='utf-8', errors='replace'), 1):
        ls = line.lstrip()
        if not (ls.startswith('//!') or ls.startswith('///')):
            continue
        for m in PATH_RE.finditer(line):
            check_path(f, i, line, m.group(1))

if fails:
    print('check-doc-anchors: FAIL —', file=sys.stderr)
    for kind, src, ln, detail in sorted(fails):
        print(f'  {kind}  {src}:{ln}  {detail}', file=sys.stderr)
    print('Update the reference to an existing path or remove the obsolete citation.', file=sys.stderr)
    sys.exit(1)
print(f'check-doc-anchors: OK ({len(md_files)} markdown files + Rust doc comments, all anchors resolve)')
PY
