#!/usr/bin/env python3
"""Launch the workspace's synthetic SDK server and full schema validator."""

import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, help="Alternate presentation of the named fixture tools")
    parser.add_argument("--http", action="store_true", help="Serve on an ephemeral loopback HTTP port")
    parser.add_argument("--legacy", action="store_true", help="Offer only the legacy protocol")
    parser.add_argument("--adapt", action="store_true", help="Use Waygate's actual presentation adapter")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    command = ["cargo", "run", "--quiet", "--locked", "--manifest-path", str(repo / "Cargo.toml"),
               "-p", "waygate-mcp", "--example", "client_schema_fixture", "--"]
    for option in ("http", "legacy", "adapt"):
        if getattr(args, option):
            command.append("--" + option)
    if args.tools:
        command.extend(["--tools", str(args.tools.resolve())])
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
