#!/usr/bin/env python3
"""Run only the SHA-bound mapping probe in a new private scratch directory."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import struct
import subprocess
from castlevania_policy import (ROOT, PolicyError, child_environment, create_run,
                               digest, read_profile, source_hashes, verify_modules)

def preflight(modules: Path, root: Path = ROOT) -> dict:
    profile, profile_path = read_profile(root)
    build = root / "build"
    if build.is_symlink():
        raise PolicyError("build directory must not be a symlink")
    binary = build / "castlevania-loader-probe"
    table = build / "runtime_tables.h"
    receipt_path = build / "loader-probe-build.json"
    if any(p.is_symlink() for p in (binary, table, receipt_path)):
        raise PolicyError("build artifacts must not be symlinks")
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("state") != "native_loader_only_compiled" or receipt.get("guest_execution_capability") is not False:
        raise PolicyError("no authenticated loader-only build receipt")
    if receipt["source_hashes"] != source_hashes(root) or receipt["profile_sha256"] != digest(profile_path):
        raise PolicyError("stale source/profile binding; rebuild the loader-only probe")
    if receipt["runtime_tables_sha256"] != profile["runtime_tables_sha256"] or digest(table) != profile["runtime_tables_sha256"]:
        raise PolicyError("runtime table integrity mismatch")
    if digest(binary) != receipt["binary_sha256"] or binary.stat().st_size != receipt["binary_bytes"]:
        raise PolicyError("loader binary integrity mismatch")
    header = binary.read_bytes()[:8]
    if len(header) != 8 or struct.unpack("<II", header) != (0xFEEDFACF, 0x0100000C) or not os.access(binary, os.X_OK):
        raise PolicyError("loader probe is not an executable native ARM64 Mach-O")
    module_hashes = verify_modules(modules, profile)
    return {"state": "preflight_pass", "binary": str(binary.resolve()),
            "binary_sha256": receipt["binary_sha256"], "profile_sha256": digest(profile_path),
            "modules": str(modules.resolve()), "module_hashes": module_hashes,
            "expected_relocations": profile["relocations_readback"], "guest_instructions_executed": False}

def run_mapping(modules: Path, root: Path = ROOT) -> dict:
    checked = preflight(modules, root)
    paths = create_run(root)
    scratch = Path(paths["root"])
    command = [checked["binary"], checked["modules"]]
    # Fixed binary and one input-directory argument: no boot mode, callbacks,
    # arbitrary executable option, shell or inherited environment is exposed.
    try:
        result = subprocess.run(command, cwd=scratch, env=child_environment(paths),
                                capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        (scratch / "receipt.json").write_text(json.dumps({"state": "failed", "reason": "mapping probe timed out", "guest_instructions_executed": False}, indent=2) + "\n")
        raise PolicyError("mapping probe timed out") from error
    (scratch / "stdout.json").write_text(result.stdout)
    (scratch / "stderr.log").write_text(result.stderr)
    def failed(reason: str) -> None:
        (scratch / "receipt.json").write_text(json.dumps({
            "state": "failed", "reason": reason, "exit_code": result.returncode,
            "cwd": str(scratch), "binary_sha256": checked["binary_sha256"],
            "stdout": "stdout.json", "stderr": "stderr.log", "successful_mapping_claimed": False,
        }, indent=2) + "\n")
    if result.returncode:
        failed("mapping probe exited unsuccessfully")
        raise PolicyError(f"mapping probe failed, exit {result.returncode}; scratch={scratch}")
    try:
        observed = json.loads(result.stdout)
    except ValueError:
        failed("mapping probe did not emit a JSON result")
        raise PolicyError(f"mapping probe emitted an invalid result; scratch={scratch}")
    if observed.get("status") != "pass" or observed.get("phase") != "native_loader_mapping_only":
        failed("unexpected probe mode/result")
        raise PolicyError("unexpected probe mode/result")
    for key in ["guest_instructions_executed", "constructors_executed", "nnMain_executed", "GPU_used", "HLE_overrides_injected", "profiles_or_saves_opened"]:
        if observed.get(key) is not False:
            failed(f"probe scope changed: {key}")
            raise PolicyError(f"probe scope changed: {key}")
    if observed.get("relocations_readback") != checked["expected_relocations"]:
        failed("relocation coverage changed")
        raise PolicyError("relocation coverage changed")
    if verify_modules(modules, read_profile(root)[0]) != checked["module_hashes"]:
        failed("read-only inputs changed during mapping probe")
        raise PolicyError("read-only inputs changed during mapping probe")
    receipt = {"state": "native_loader_mapping_pass", "completed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "command": command, "cwd": str(scratch), "binary_sha256": checked["binary_sha256"],
               "input_modules_before_after": checked["module_hashes"], "input_modules_unchanged": True,
               "isolated_paths": {key: value for key, value in paths.items() if key != "token"},
               "inherited_environment": False, "existing_profiles_accessed": False,
               "host_or_guest_boot_attempted": False, "observed": observed}
    (scratch / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", required=True, type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        result = preflight(args.modules) if args.preflight_only else run_mapping(args.modules)
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"state": "blocked", "reason": str(error), "guest_instructions_executed": False}))
        return 2
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
