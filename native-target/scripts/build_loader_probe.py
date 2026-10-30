#!/usr/bin/env python3
"""Compile only the non-executing native module-mapping diagnostic."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
from castlevania_policy import ROOT, PolicyError, digest, ensure_owned_directory, read_profile, source_hashes

def build(tables: Path, root: Path = ROOT) -> dict:
    profile, profile_path = read_profile(root)
    tables = tables.resolve(strict=True)
    if tables.is_symlink() or digest(tables) != profile["runtime_tables_sha256"]:
        raise PolicyError("runtime tables differ from the measured v1.1.0 checkpoint")
    out = root / "build"
    if out.is_symlink():
        raise PolicyError("build directory must not be a symlink")
    out.mkdir(mode=0o700, exist_ok=True)
    ensure_owned_directory(out)
    for name in ["castlevania-loader-probe", "loader-probe-build.json", "loader-probe-build.stdout", "loader-probe-build.stderr"]:
        if (out / name).is_symlink():
            raise PolicyError("refusing symlink build artifact destination")
    local_tables = out / "runtime_tables.h"
    if local_tables.is_symlink():
        raise PolicyError("refusing a symlink runtime table destination")
    local_tables.write_bytes(tables.read_bytes())
    if digest(local_tables) != profile["runtime_tables_sha256"]:
        raise PolicyError("runtime table copy readback failed")
    command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=c11", "-O2", "-g",
               "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1",
               "-Iruntime", "-Ibuild", "-Ithird_party/d2r_gfx/gfx/nvn/include",
               "runtime/castlevania_loader_probe.c", "-o", "build/castlevania-loader-probe"]
    inputs_before = source_hashes(root)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("DEVELOPER_DIR"):
        environment["DEVELOPER_DIR"] = os.environ["DEVELOPER_DIR"]
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True)
    (out / "loader-probe-build.stdout").write_text(result.stdout)
    (out / "loader-probe-build.stderr").write_text(result.stderr)
    if result.returncode:
        raise PolicyError("native loader probe compilation failed; see build/loader-probe-build.stderr")
    if source_hashes(root) != inputs_before:
        raise PolicyError("source changed during compilation")
    binary = out / "castlevania-loader-probe"
    receipt = {"schema": 1, "state": "native_loader_only_compiled", "guest_execution_capability": False,
               "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command,
               "source_hashes": inputs_before, "profile_sha256": digest(profile_path),
               "runtime_tables_sha256": digest(local_tables), "binary_sha256": digest(binary),
               "binary_bytes": binary.stat().st_size, "input_tables_read_only": str(tables),
               "full_host_built": False, "guest_instructions_executed": False}
    (out / "loader-probe-build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables", required=True, type=Path, help="Read-only authenticated runtime_tables.h")
    args = parser.parse_args()
    try:
        receipt = build(args.tables)
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"state": "blocked", "reason": str(error), "guest_instructions_executed": False}))
        return 2
    print(json.dumps(receipt, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
