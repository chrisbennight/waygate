#!/usr/bin/env python3
"""Generate optional native-menu entries from gateway-skills.search metadata."""

import argparse
import json
from pathlib import Path
import re


def generate(catalog: dict, destination: Path) -> None:
    """Create a new directory; never overwrite an installed skill or workflow."""
    skills = catalog["skills"]
    names = set()
    prepared = []
    for skill in skills:
        name, uri, description = (skill[key] for key in ("name", "uri", "description"))
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
            raise ValueError("Each skill needs a valid Agent Skills name")
        if name in names:
            raise ValueError("Duplicate skill names; select one source for each native menu entry")
        names.add(name)
        if not isinstance(uri, str) or not uri.startswith("skill://") or not uri.endswith("/SKILL.md"):
            raise ValueError("Each skill needs its exact skill:// URI from search")
        if not isinstance(description, str) or not description or len(description) > 1024 or "<" in description or ">" in description:
            raise ValueError("Each skill needs a valid Agent Skills description")
        locator = json.dumps({"uri": uri}, ensure_ascii=True).replace("`", "\\u0060")
        instructions = (
            f"---\nname: {name}\ndescription: {json.dumps(description)}\n---\n\n"
            "Find gateway-skills.search through the connected MCP gateway and search for "
            f"{name}. Select this exact skill URI from the results:\n\n```json\n{locator}\n```\n\n"
            "Load it with gateway-skills.load using the returned URI and revision. "
            "Follow those instructions within the user's existing task authorization. "
            "Use gateway-skills.read_file for supporting files and the same revision "
            "for called skills. Resolve relative paths against the returned inventory; "
            "deliver client-local helpers before running them with local tools. "
            "If the gateway or revision is unavailable, report that limitation; "
            "do not substitute instructions from another source.\n"
        )
        short = f"Load the centrally maintained {name} workflow"[:64]
        interface = "interface:\n" + "".join(
            f"  {key}: {json.dumps(value)}\n" for key, value in {
                "display_name": name,
                "short_description": short,
                "default_prompt": f"Use ${name} to complete the requested workflow.",
            }.items()
        )
        prepared.append((name, instructions, interface))
    destination.mkdir(parents=False, exist_ok=False)
    for name, instructions, interface in prepared:
        root = destination / name
        (root / "agents").mkdir(parents=True)
        (root / "SKILL.md").write_text(instructions, encoding="utf-8")
        (root / "agents" / "openai.yaml").write_text(interface, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path, help="JSON search result with a skills array; combine pages first")
    parser.add_argument("destination", type=Path, help="New output directory under an existing parent")
    args = parser.parse_args()
    try:
        generate(json.loads(args.catalog.read_text(encoding="utf-8")), args.destination)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Cannot generate skill shims: {error}\n")


if __name__ == "__main__":
    main()
