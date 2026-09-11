#!/usr/bin/env bash
# CI guard: explicitly removed test containers must also remove anonymous
# volumes. The scanner is Python stdlib code so shell quoting and command
# boundaries are parsed without executing repository text.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "$@" <<'PY'
import json
import os
import re
import shlex
import sys
from pathlib import Path

CONTROL_CHARS = frozenset(";&|()")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
RUN_PREFIX = re.compile(r"^\s*(?:-\s*)?run:\s*(.*)$")
FLOW_STEP_START = re.compile(r"^\s*-\s*\{")
BLOCK_SCALAR = re.compile(r"^[>|](?:[1-9][+-]?|[+-][1-9]?)?$")
SHELLS = {"sh", "bash", "zsh"}
RESERVED_PREFIXES = {"!", "if", "then", "elif", "else", "do", "while", "until"}
SHELL_SOURCES = (Path("scripts/smoke-gateway-image.sh"),)
DOCKER_VALUE_OPTIONS = {
    "--config",
    "--context",
    "--host",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "-c",
    "-H",
    "-l",
}
DOCKER_FLAG_OPTIONS = {
    "--debug",
    "--help",
    "--tls",
    "--tlsverify",
    "--version",
    "-D",
    "-v",
}
DOCKER_ASSIGNED_FLAG_PREFIXES = tuple(f"{option}=" for option in DOCKER_FLAG_OPTIONS)
SUDO_VALUE_OPTIONS = {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u"}


def is_control(token):
    return bool(token) and set(token) <= CONTROL_CHARS


def tokenize(line):
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def segments(tokens):
    current = []
    for token in tokens:
        if is_control(token):
            if current:
                yield current
                current = []
        else:
            current.append(token)
    if current:
        yield current


def skip_options(tokens, index, value_options=()):
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        index += 1
        if option in value_options and index < len(tokens):
            index += 1
    return index


def executable_index(tokens):
    index = 0
    while index < len(tokens):
        token = tokens[index]
        base = os.path.basename(token)
        if ASSIGNMENT.match(token) or token in RESERVED_PREFIXES:
            index += 1
        elif base == "sudo":
            index = skip_options(tokens, index + 1, SUDO_VALUE_OPTIONS)
        elif base == "env":
            index = skip_options(tokens, index + 1)
            while index < len(tokens) and ASSIGNMENT.match(tokens[index]):
                index += 1
        elif base in {"command", "exec", "time"}:
            index = skip_options(tokens, index + 1)
        else:
            return index
    return None


def shell_command(tokens, index):
    for option_index in range(index + 1, len(tokens) - 1):
        option = tokens[option_index]
        if option == "--":
            continue
        if option.startswith("-") and not option.startswith("--") and "c" in option[1:]:
            return tokens[option_index + 1]
    return None


def docker_rm_args_start(tokens, index):
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token == "rm":
            return cursor + 1
        if token == "container" and tokens[cursor + 1 : cursor + 2] == ["rm"]:
            return cursor + 2
        if token in DOCKER_VALUE_OPTIONS:
            cursor += 2
            continue
        if token in DOCKER_FLAG_OPTIONS or token.startswith(
            DOCKER_ASSIGNED_FLAG_PREFIXES
            + (
                "--config=",
                "--context=",
                "--host=",
                "--log-level=",
                "--tlscacert=",
                "--tlscert=",
                "--tlskey=",
            )
        ):
            cursor += 1
            continue
        if len(token) > 2 and token[:2] in {"-c", "-H", "-l"}:
            cursor += 1
            continue
        return None
    return None


def removes_volumes(arguments):
    for argument in arguments:
        if argument == "--":
            break
        if argument == "--volumes":
            return True
        if argument.startswith("--volumes="):
            return argument.partition("=")[2].lower() in {"1", "t", "true"}
        if argument.startswith("-") and not argument.startswith("--"):
            flags, separator, value = argument[1:].partition("=")
            if "v" in flags:
                return not separator or value.lower() in {"1", "t", "true"}
    return False


def scan_command_line(line, source, line_number, depth=0):
    if depth > 8:
        return 0, [(source, line_number, line, "nested shell command limit exceeded")]
    try:
        parsed = tokenize(line)
    except ValueError as exc:
        if "docker" in line:
            return 0, [(source, line_number, line, f"unparseable shell command: {exc}")]
        return 0, []

    found = 0
    offenses = []
    for command in segments(parsed):
        index = executable_index(command)
        if index is None:
            continue
        executable = os.path.basename(command[index])
        if executable in {"echo", "printf"}:
            continue
        for command_index, token in enumerate(command):
            token_executable = os.path.basename(token)
            if token_executable in SHELLS:
                nested = shell_command(command, command_index)
                if nested is not None:
                    nested_found, nested_offenses = scan_command_line(
                        nested, source, line_number, depth + 1
                    )
                    found += nested_found
                    offenses.extend(nested_offenses)
                continue
            if token_executable != "docker":
                continue
            args_start = docker_rm_args_start(command, command_index)
            if args_start is None:
                continue
            found += 1
            if not removes_volumes(command[args_start:]):
                offenses.append(
                    (
                        source,
                        line_number,
                        " ".join(command[command_index:]),
                        "missing -v or --volumes",
                    )
                )
    return found, offenses


def decode_run_value(candidate):
    if len(candidate) >= 2 and candidate[0] == candidate[-1] == "'":
        return candidate[1:-1].replace("''", "'")
    if len(candidate) >= 2 and candidate[0] == candidate[-1] == '"':
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return candidate[1:-1].replace(r'\"', '"').replace(r"\\", "\\")
    return candidate


def run_candidate(logical):
    match = RUN_PREFIX.match(logical)
    return decode_run_value(match.group(1)) if match else logical


def yaml_structure(text):
    quote = None
    escaped = False
    depth = 0
    for character in text:
        if escaped:
            escaped = False
        elif quote == '"' and character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        yield character, depth, quote


def split_flow_fields(text):
    fields = []
    start = 0
    for index, (character, depth, quote) in enumerate(yaml_structure(text)):
        if character == "," and depth == 0 and quote is None:
            fields.append(text[start:index])
            start = index + 1
    fields.append(text[start:])
    return fields


def split_flow_pair(field):
    for index, (character, depth, quote) in enumerate(yaml_structure(field)):
        if character == ":" and depth == 0 and quote is None:
            return field[:index], field[index + 1 :]
    return None


def flow_run_value(flow_step):
    opening = flow_step.find("{")
    closing = flow_step.rfind("}")
    if opening < 0 or closing <= opening:
        return None
    for field in split_flow_fields(flow_step[opening + 1 : closing]):
        pair = split_flow_pair(field)
        if pair is None:
            continue
        key, value = pair
        if key.strip().strip("'\"") == "run":
            return decode_run_value(value.strip())
    return None


def strip_yaml_comment(line):
    quote = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif quote == '"' and character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line


def collect_flow_step(lines, start):
    parts = []
    line_index = start
    while line_index < len(lines):
        parts.append(strip_yaml_comment(lines[line_index]).strip())
        line_index += 1
        states = list(yaml_structure(" ".join(parts)))
        if states and states[-1][1] == 0:
            break
    return " ".join(parts), line_index


def block_content_indent(lines):
    nonempty_indents = [
        len(line) - len(line.lstrip(" ")) for line in lines if line.strip()
    ]
    return min(nonempty_indents) if nonempty_indents else 0


def dedent_block(lines):
    content_indent = block_content_indent(lines)
    return "\n".join(
        line[content_indent:] if line.strip() else "" for line in lines
    )


def folded_block_text(lines):
    content_indent = block_content_indent(lines)
    if not content_indent:
        return ""
    commands = []
    paragraph = []

    def flush():
        nonlocal paragraph
        if paragraph:
            commands.append(" ".join(paragraph))
            paragraph = []

    for line in lines:
        content = line[content_indent:] if line.strip() else ""
        if not content.strip():
            flush()
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent > content_indent:
            flush()
            commands.append(content.rstrip())
            continue
        paragraph.append(content.strip())
    flush()
    return "\n".join(commands)


def scan_text(text, source, line_offset=0):
    found = 0
    offenses = []
    logical = ""
    logical_start = 0
    lines = text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        line_number = line_offset + line_index + 1
        if not logical:
            logical_start = line_number
        if line.endswith("\\"):
            logical = f"{logical} {line[:-1]}".strip()
            line_index += 1
            continue
        logical = f"{logical} {line}".strip()
        candidate = run_candidate(logical)
        if candidate not in {"|", ">", "|-", ">-"}:
            line_found, line_offenses = scan_command_line(
                candidate, source, logical_start
            )
            found += line_found
            offenses.extend(line_offenses)
        logical = ""
        line_index += 1
    if logical:
        offenses.append((source, logical_start, logical, "unterminated shell continuation"))
    return found, offenses


def scan_workflow_text(text, source):
    found = 0
    offenses = []
    lines = text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        if FLOW_STEP_START.match(line):
            flow_step, flow_end = collect_flow_step(lines, line_index)
            command = flow_run_value(flow_step)
            if command is not None:
                command_found, command_offenses = scan_text(
                    command, source, line_offset=line_index
                )
                found += command_found
                offenses.extend(command_offenses)
            line_index = flow_end
            continue
        run_match = RUN_PREFIX.match(line)
        if not run_match:
            line_index += 1
            continue
        run_value = run_match.group(1).split("#", 1)[0].strip()
        if BLOCK_SCALAR.fullmatch(run_value):
            key_indent = len(line) - len(line.lstrip(" "))
            body_start = line_index + 1
            body_end = body_start
            while body_end < len(lines):
                body_line = lines[body_end]
                body_indent = len(body_line) - len(body_line.lstrip(" "))
                if body_line.strip() and body_indent <= key_indent:
                    break
                body_end += 1
            body = lines[body_start:body_end]
            if run_value.startswith(">"):
                body_found, body_offenses = scan_text(
                    folded_block_text(body), source, line_offset=body_start
                )
                found += body_found
                offenses.extend(body_offenses)
            else:
                body_found, body_offenses = scan_text(
                    dedent_block(body), source, line_offset=body_start
                )
                found += body_found
                offenses.extend(body_offenses)
            line_index = body_end
            continue
        command_found, command_offenses = scan_text(
            run_candidate(line), source, line_offset=line_index
        )
        found += command_found
        offenses.extend(command_offenses)
        line_index += 1
    return found, offenses


def self_test():
    unsafe = (
        "sudo docker rm -f test-db || true",
        "docker container rm --force test-db",
        "docker rm -f -v first-db && docker rm -f second-db",
        "docker rm -f leaked;docker rm -fv clean",
        "sh -c 'docker rm -f leaked'",
        "/usr/bin/docker rm -f leaked",
        "docker --context ci rm -f leaked",
        "run: docker --host=tcp://daemon rm -f leaked",
        'run: "docker rm -f leaked"',
        "{ docker rm -f leaked; }",
        "printf '%s\\n' leaked | xargs docker rm -f",
        "docker rm -f -- test-db -v",
        "docker rm -f --volumes=false test-db",
        "docker rm -f -v=false test-db",
        "docker --debug=true rm -f leaked",
    )
    safe = (
        ("sudo docker rm -f -v test-db || true", 1),
        ("docker rm -fv test-db", 1),
        ("docker container rm --force --volumes test-db", 1),
        ("docker --context ci rm -fv test-db", 1),
        ("docker rm -fv first-db;docker rm --volumes second-db", 2),
        ("docker rm -fv live # docker rm -f documentation-example", 1),
        ('echo "; docker rm -f documentation-example"', 0),
        ("bash -lc 'docker container rm --volumes clean'", 1),
        ("echo docker rm -f documentation-example", 0),
        ("docker rmi test-image", 0),
        ("run: /usr/local/bin/docker rm -fv clean", 1),
        ("run: 'docker container rm --volumes clean'", 1),
        ("{ docker rm -fv clean; }", 1),
        ("xargs docker rm -fv clean", 1),
        ("docker rm -fv -- test-db", 1),
        ("docker rm -f --volumes=true test-db", 1),
        ("docker rm -f -v=true test-db", 1),
        ("docker --tlsverify=false rm -fv test-db", 1),
    )
    for command in unsafe:
        found, offenses = scan_text(command, "self-test")
        if found == 0 or not offenses:
            raise AssertionError(f"unsafe command passed: {command}")
    for command, expected_found in safe:
        found, offenses = scan_text(command, "self-test")
        if found != expected_found or offenses:
            raise AssertionError(
                f"safe command failed: {command}: found={found}, offenses={offenses}"
            )
    flow_unsafe = "- {name: cleanup, run: docker rm -f leaked}"
    found, offenses = scan_workflow_text(flow_unsafe, "self-test.yml")
    if found != 1 or not offenses:
        raise AssertionError("unsafe flow-style step passed")
    flow_safe = """- {
  name: "cleanup ${{ github.run_id }}", # nested braces and a comment
  run: "docker container rm -fv clean"
}
"""
    found, offenses = scan_workflow_text(flow_safe, "self-test.yml")
    if found != 1 or offenses:
        raise AssertionError(
            f"safe flow-style step failed: found={found}, offenses={offenses}"
        )
    folded_unsafe = """run: >-
  docker
  rm -f leaked
"""
    found, offenses = scan_workflow_text(folded_unsafe, "self-test.yml")
    if found != 1 or not offenses:
        raise AssertionError("unsafe folded scalar passed")
    folded_safe = """run: >-
  docker container
  rm --force --volumes clean
"""
    found, offenses = scan_workflow_text(folded_safe, "self-test.yml")
    if found != 1 or offenses:
        raise AssertionError(f"safe folded scalar failed: {offenses}")
    folded_boundary = """run: >-
  docker rm -fv clean

  docker rm -f leaked
"""
    found, offenses = scan_workflow_text(folded_boundary, "self-test.yml")
    if found != 2 or len(offenses) != 1:
        raise AssertionError("folded scalar command boundary failed")
    folded_indented = """run: >-
  docker rm -fv first
    docker rm -f second
"""
    found, offenses = scan_workflow_text(folded_indented, "self-test.yml")
    if found != 2 or len(offenses) != 1:
        raise AssertionError("more-indented folded command boundary failed")
    folded_continuation = """run: >-
  docker rm -f \\
    -v clean
"""
    found, offenses = scan_workflow_text(folded_continuation, "self-test.yml")
    if found != 1 or offenses:
        raise AssertionError("more-indented folded continuation failed")
    metadata = """name: document docker rm -f behavior
on: push
jobs:
  test:
    name: docker container rm -f is documentation here
"""
    found, offenses = scan_workflow_text(metadata, "self-test.yml")
    if found != 0 or offenses:
        raise AssertionError("non-executable workflow metadata was scanned")
    found, offenses = scan_text("docker rm -f \\\n+  -v test-db", "self-test")
    if found != 1 or offenses:
        raise AssertionError("safe continuation failed")
    for source in SHELL_SOURCES:
        if not source.is_file():
            raise AssertionError(f"governed shell source is missing: {source}")
        found, offenses = scan_text(source.read_text(), source.as_posix())
        if found != 4 or offenses:
            raise AssertionError(
                f"governed shell source coverage drifted: {source}: "
                f"found={found}, offenses={offenses}"
            )
    print("check-docker-volume-cleanup self-test: OK")


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        self_test()
        return 0
    if args:
        print(f"usage: {sys.argv[0]} [--self-test]", file=sys.stderr)
        return 2

    workflows = sorted(Path(".github/workflows").glob("*.yml"))
    workflows += sorted(Path(".github/workflows").glob("*.yaml"))
    if not workflows:
        print("check-docker-volume-cleanup: no workflow files found", file=sys.stderr)
        return 2

    found = 0
    offenses = []
    for workflow in workflows:
        workflow_found, workflow_offenses = scan_workflow_text(
            workflow.read_text(), workflow.as_posix()
        )
        found += workflow_found
        offenses.extend(workflow_offenses)
    for source in SHELL_SOURCES:
        if not source.is_file():
            print(
                f"check-docker-volume-cleanup: governed shell source is missing: {source}",
                file=sys.stderr,
            )
            return 2
        source_found, source_offenses = scan_text(
            source.read_text(), source.as_posix()
        )
        found += source_found
        offenses.extend(source_offenses)
    if found == 0:
        print("check-docker-volume-cleanup: scanner found no docker rm commands", file=sys.stderr)
        return 2
    if offenses:
        for source, line_number, command, reason in offenses:
            print(
                f"{source}:{line_number}: docker container removal must include "
                f"-v or --volumes ({reason}): {command}",
                file=sys.stderr,
            )
        print("check-docker-volume-cleanup: FAIL", file=sys.stderr)
        return 1
    print(f"check-docker-volume-cleanup: OK ({found} docker rm commands checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
