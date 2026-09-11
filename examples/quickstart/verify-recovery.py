"""Verify a disposable tutorial database restore and optional image upgrade.

Requires Docker Compose and an already built gateway image. All containers,
networks, volumes, and copied configuration belong to a unique test project.
The only identity is the tutorial's disposable demo identity.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="mcp-gateway:local")
    parser.add_argument("--baseline-image", help="Optional prior image to test before and after the candidate")
    args = parser.parse_args()
    project = "gateway-recovery-" + uuid.uuid4().hex[:12]
    env = {**os.environ, "POSTGRES_PASSWORD": "dev", "GATEWAY_IMAGE": args.image}

    def run(command, **kwargs):
        return subprocess.run(command, env=env, check=True, **kwargs)

    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        root = Path(directory)
        config_path = root / "compose.json"
        rendered = run(
            ["docker", "compose", "-p", project, "-f", str(ROOT / "docker-compose.yml"),
             "config", "--format", "json"], capture_output=True, text=True,
        )
        config = json.loads(rendered.stdout)
        gateway = config["services"]["gateway"]
        gateway.pop("build", None)
        gateway["image"] = args.baseline_image or args.image
        for service in ("gateway", "demo-issuer"):
            for port in config["services"][service]["ports"]:
                port["published"] = "0"
                port["host_ip"] = "127.0.0.1"
        for folder in ("servers", "policies"):
            destination = root / folder
            shutil.copytree(ROOT / "examples" / "quickstart" / folder, destination)
            for volume in gateway["volumes"]:
                if volume["target"].endswith("/" + folder):
                    volume["source"] = str(destination)

        restored = copy.deepcopy(config["services"]["postgres"])
        restored["environment"]["POSTGRES_USER"] = "restore_admin"
        restored["healthcheck"]["test"] = ["CMD-SHELL", "pg_isready -U restore_admin -d gateway"]
        restored["volumes"][0]["source"] = "restore_db"
        config["services"]["postgres-restore"] = restored
        config["volumes"]["restore_db"] = {"name": project + "_restore_db"}
        config_path.write_text(json.dumps(config))
        compose = ["docker", "compose", "-p", project, "-f", str(config_path)]

        def check():
            gateway_address = run([*compose, "port", "gateway", "8080"],
                                  capture_output=True, text=True).stdout.strip()
            issuer_address = run([*compose, "port", "demo-issuer", "9000"],
                                 capture_output=True, text=True).stdout.strip()
            run(["python3", str(ROOT / "examples" / "quickstart" / "check.py"),
                 "--gateway", "http://" + gateway_address,
                 "--issuer", "http://" + issuer_address])

        def migration_rows(service):
            return run(
                [*compose, "exec", "-T", service, "psql", "-U", "gateway", "-d", "gateway",
                 "-At", "-c", "SELECT version, encode(checksum, 'hex') FROM _sqlx_migrations ORDER BY version"],
                capture_output=True,
            ).stdout

        def function_owners(service):
            return run(
                [*compose, "exec", "-T", service, "psql", "-U", "gateway", "-d", "gateway",
                 "-At", "-c", "SELECT oid::regprocedure::text, pg_get_userbyid(proowner) "
                 "FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND prosecdef ORDER BY 1"],
                capture_output=True,
            ).stdout

        try:
            run([*compose, "up", "-d", "--build", "--wait", "--wait-timeout", "180"])
            check()
            run([*compose, "stop", "gateway"])
            original_migrations = migration_rows("postgres")
            original_owners = function_owners("postgres")
            roles = root / "synthetic-roles.sql"
            with roles.open("wb") as output:
                run([*compose, "exec", "-T", "postgres", "pg_dumpall", "-U", "gateway",
                     "--roles-only", "--no-role-passwords"], stdout=output)
            with roles.open("rb") as source:
                run([*compose, "exec", "-T", "postgres-restore", "psql", "-U", "restore_admin",
                     "-d", "gateway", "--set", "ON_ERROR_STOP=on"], stdin=source)
            run([*compose, "exec", "-T", "postgres-restore", "psql", "-U", "restore_admin",
                 "-d", "gateway", "--set", "ON_ERROR_STOP=on", "-c",
                 "ALTER DATABASE gateway OWNER TO gateway; ALTER ROLE gateway PASSWORD 'dev'"])
            dump = root / "synthetic.dump"
            with dump.open("wb") as output:
                run([*compose, "exec", "-T", "postgres", "pg_dump", "-U", "gateway",
                     "-d", "gateway", "-Fc"], stdout=output)
            with dump.open("rb") as source:
                run([*compose, "exec", "-T", "postgres-restore", "pg_restore", "-U", "restore_admin",
                     "-d", "gateway", "--exit-on-error"], stdin=source)
            if migration_rows("postgres-restore") != original_migrations:
                raise RuntimeError("Restored migration versions/checksums differ from the backup")
            print("PASS: restored migration versions and checksums match", flush=True)
            if not original_owners or function_owners("postgres-restore") != original_owners:
                raise RuntimeError("Restored security-definer function ownership differs from the backup")
            print("PASS: restored security-definer function ownership matches", flush=True)
            gateway["environment"]["GATEWAY_DATABASE_URL"] = "postgres://gateway:dev@postgres-restore:5432/gateway"
            gateway["image"] = args.image
            config_path.write_text(json.dumps(config))
            run([*compose, "up", "-d", "--no-deps", "--force-recreate", "--wait",
                 "--wait-timeout", "180", "gateway"])
            check()
            print("PASS: candidate serves the restored database and copied configuration", flush=True)
            if args.baseline_image:
                gateway["image"] = args.baseline_image
                config_path.write_text(json.dumps(config))
                run([*compose, "up", "-d", "--no-deps", "--force-recreate", "--wait",
                     "--wait-timeout", "180", "gateway"])
                check()
                print("PASS: selected prior image serves this candidate's database state", flush=True)
        finally:
            run([*compose, "down", "--volumes", "--remove-orphans", "--rmi", "local"])


if __name__ == "__main__":
    main()
