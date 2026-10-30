#!/usr/bin/env python3
"""Run one bounded native host diagnostic inside a new owned scratch directory."""
from __future__ import annotations

import argparse
import datetime as dt
import functools
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import secrets
import signal
import stat
import struct
import subprocess
import tempfile
import time

TITLE = "0100BA4026E94000"
ROOT = Path(__file__).resolve().parents[1]
PROOF_NAME = ".romfs-verified-v1"
RESOURCE_KEYS = ("romfs_image", "romfs_image_sha256", "romfs_image_size", "romfs_files",
                 "romfs_index_sha256", "romfs_config_sha256")
APP_NAME = "Castlevania Diagnostic.app"
APP_ID = "org.macnativegames.castlevania.diagnostic"
SHADER_TOOLS = ("shader-service/totk_xlate", "spirv-cross/spirv-cross")


def sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("diagnostic directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o777 != 0o700:
        raise ValueError("diagnostic directory must be owned and mode0700")


def owned_directory(path: Path) -> None:
    if path.resolve(strict=True) != path.absolute():
        raise ValueError("owned run path must be canonical without symlinks")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("owned run directory must be mode0700")


def owned_bytes(path: Path, *, private: bool = False, maximum: int = 2 << 20) -> bytes:
    """Read a bounded regular owned file through O_NOFOLLOW, never a hardlink."""
    if path.is_symlink():
        raise ValueError("owned file must not be a symlink: " + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or mode not in ((0o600,) if private else (0o600, 0o644))
                or before.st_size > maximum):
            raise ValueError("invalid owned file type/mode/size: " + path.name)
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if (len(data) != before.st_size or len(data) > maximum
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("owned file changed while reading: " + path.name)
        return data


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def romfs_verification(log: bytes, resources: dict) -> str:
    """Classify actual C output only after its matching ready line was reached."""
    ready = f'[castlevania] native read-only RomFS ready: {resources["romfs_files"]} files'
    fresh = f'[totk] verifying local RomFS SHA256 ({resources["romfs_image_size"]} bytes)'
    reused = f'[totk] RomFS unchanged; reused full SHA256 verification record ({resources["romfs_image_size"]} bytes)'
    mode = "not_reached_or_incomplete"
    for line in log.decode("utf-8", errors="replace").splitlines():
        if line in (fresh, fresh + " [forced]"):
            mode = "fresh_full_sha256"
        elif line == reused:
            mode = "reused_previous_C_full_hash_record"
        elif line == ready:
            return mode
    return "not_reached_or_incomplete"


def checked_resources(work: Path, build: dict) -> dict:
    resources = build["resources"]
    for key in RESOURCE_KEYS:
        if key not in resources:
            raise ValueError("build lacks expected RomFS resource binding")
    for key in ("romfs_image_sha256", "romfs_index_sha256", "romfs_config_sha256"):
        if not re.fullmatch("[0-9a-f]{64}", resources[key]):
            raise ValueError("invalid RomFS expected digest")
    image = Path(resources["romfs_image"])
    if (not image.is_absolute() or image.resolve(strict=True) != image or not image.is_file()
            or image.stat().st_size != resources["romfs_image_size"]):
        raise ValueError("RomFS canonical image path/size differs from build")
    staged = work/"extracted/v110/romfs"
    if ((staged/"romfs.bin").resolve(strict=True) != image
            or sha(staged/"runtime-index.bin") != resources["romfs_index_sha256"]
            or sha(work/"generated/romfs_config.h") != resources["romfs_config_sha256"]):
        raise ValueError("RomFS staged path/config/index differs from build")
    source = build["source_hashes"].get("runtime/romfs.c")
    if not source or source != sha(ROOT/"runtime/romfs.c"):
        raise ValueError("compiled RomFS C source differs from current source")
    return resources


def reuse_romfs_proof(work: Path, build: dict, prior: Path, destination: Path) -> dict:
    """Copy only a real completed run's C record; C fstat/proof_equal still decides."""
    owned_directory(work/"runs")
    prior = prior.absolute()
    if prior.parent != work/"runs" or not re.fullmatch(r"host-[A-Za-z0-9_-]+", prior.name):
        raise ValueError("proof source must be a direct prior run under this work/runs")
    for path in (prior, prior/"cache", prior/"logs"):
        owned_directory(path)
    marker = owned_bytes(prior/".castlevania-host-run", private=True, maximum=100)
    if not re.fullmatch((TITLE + r" [0-9a-f]{32}\n").encode(), marker):
        raise ValueError("prior run ownership marker differs")
    receipt_bytes = owned_bytes(prior/"receipt.json")
    receipt = json.loads(receipt_bytes)
    bundle = receipt.get("app_bundle", {})
    if not isinstance(bundle, dict) or bundle.get("requested", False) is not False:
        raise ValueError("bundled prior runs are not supported as proof sources")
    cleanup = receipt.get("owned_process_group_cleanup", {})
    if not isinstance(cleanup, dict):
        raise ValueError("prior cleanup evidence is malformed")
    log_path = prior/"logs/native-host.log"
    log = owned_bytes(log_path, private=True, maximum=64 << 20)
    if (receipt.get("state") != "bounded_experimental_host_run_finished" or receipt.get("title_id") != TITLE
            or receipt.get("run_root") != str(prior) or receipt.get("log") != str(log_path)
            or receipt.get("log_bytes") != len(log) or receipt.get("log_sha256") != hashlib.sha256(log).hexdigest()
            or receipt.get("remaining_owned_process_group_pids") != []
            or receipt.get("proof_reuse_eligible", True) is not True
            or cleanup.get("complete", True) is not True
            or receipt.get("command") != [str(work/"build/castlevania-native"), str(prior/"rewritten/v110"), "boot"]):
        raise ValueError("prior finished run/log/binary binding differs")
    compiled_bytes = owned_bytes(prior/"compiled-build-receipt.json", private=True)
    compiled_sha = hashlib.sha256(compiled_bytes).hexdigest()
    compiled = json.loads(compiled_bytes)
    if (compiled.get("state") != "actual_native_host_compiled_not_launched" or compiled.get("title_id") != TITLE
            or compiled.get("work") != str(work) or compiled.get("diagnostic_boot_compiled") is not True
            or compiled.get("binary") != str(work/"build/castlevania-native")
            or compiled.get("binary_sha256") != receipt.get("binary_sha256")
            or compiled["source_hashes"].get("runtime/romfs.c") != build["source_hashes"].get("runtime/romfs.c")):
        raise ValueError("prior compiled build/run/C source binding differs")
    for field, expected in (("run_marker_sha256", hashlib.sha256(marker).hexdigest()),
                            ("compiled_build_receipt_sha256", compiled_sha)):
        if field in receipt and receipt[field] != expected:
            raise ValueError("prior receipt recorded binding differs: " + field)
    resources = checked_resources(work, build)
    if any(compiled["resources"].get(key) != resources[key] for key in RESOURCE_KEYS):
        raise ValueError("prior/current RomFS resource bindings differ")
    mode = romfs_verification(log, resources)
    if mode == "not_reached_or_incomplete":
        raise ValueError("prior C RomFS verification never reached ready")
    proof_path = prior/"cache"/PROOF_NAME
    proof = owned_bytes(proof_path, private=True, maximum=160)
    proof_sha = hashlib.sha256(proof).hexdigest()
    if (len(proof) != 160 or proof[:16] != b"CAST-RFS-PROOF-1"
            or proof[16:81] != resources["romfs_image_sha256"].encode()+b"\0"
            or struct.unpack_from("<Q", proof, 104)[0] != resources["romfs_image_size"]):
        raise ValueError("prior C proof format/expected image binding differs")
    if "runtime_romfs_proof_sha256" in receipt and receipt["runtime_romfs_proof_sha256"] != proof_sha:
        raise ValueError("prior receipt proof SHA differs")
    owned_directory(destination.parent)
    if destination != destination.parent/PROOF_NAME or destination.parent.parent.parent != work/"runs":
        raise ValueError("proof destination must be a fresh run private cache")
    if destination.parent.parent == prior:
        raise ValueError("proof source and destination must be different runs")
    write_private(destination, proof)
    if owned_bytes(destination, private=True, maximum=160) != proof:
        raise ValueError("proof copy readback differs")
    return {"requested": True, "source_run": str(prior), "source_proof": str(proof_path),
            "proof_sha256": proof_sha, "proof_bytes": len(proof),
            "prior_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "prior_log_sha256": receipt["log_sha256"], "prior_C_verification_mode": mode,
            "prior_compiled_build_receipt_sha256": compiled_sha,
            "prior_marker_binding_recorded": "run_marker_sha256" in receipt,
            "prior_compiled_receipt_binding_recorded": "compiled_build_receipt_sha256" in receipt,
            "copied_byte_exact": True, "fresh_image_sha256_performed_by_runner": False,
            "final_authority": "unchanged C fstat/proof_equal; any mismatch requires full image SHA256"}


def child_limits(file_size_limit_mib: int = 64) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    size = file_size_limit_mib << 20
    resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))


def verify_code(path: Path) -> None:
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)],
                   check=True, capture_output=True)


def require_no_entitlements(path: Path) -> None:
    result = subprocess.run(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)],
                            check=True, capture_output=True)
    if result.stdout.strip():
        # The current trusted build has none. Future entitlement-bearing builds
        # require an explicit preservation policy, never silent removal.
        if plistlib.loads(result.stdout) != {}:
            raise ValueError("diagnostic bundle supports only the measured entitlement-free build")


def copy_executable(source: Path, destination: Path, expected_sha: str) -> dict:
    if not re.fullmatch("[0-9a-f]{64}", expected_sha) or source.resolve(strict=True) != source:
        raise ValueError("bundle executable source path/digest differs")
    verify_code(source)
    require_no_entitlements(source)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as original:
        before = os.fstat(original.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_size <= 0 or not before.st_mode & 0o111):
            raise ValueError("bundle source must be a regular owned executable")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as output:
            while chunk := original.read(1 << 20):
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(original.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or digest.hexdigest() != expected_sha or sha(destination) != expected_sha
            or sha(source) != expected_sha):
        raise ValueError("bundle executable copy/source readback differs")
    return {"source": str(source), "source_sha256": expected_sha,
            "pre_sign_copy_sha256": expected_sha, "bytes_before_signing": before.st_size}


def prepare_app_bundle(root: Path, work: Path, build: dict, build_bytes: bytes) -> dict:
    """Seal a fresh derived diagnostic app; never alter the compiled executable."""
    owned_directory(root)
    app = root/APP_NAME
    app.mkdir(mode=0o700)
    contents = app/"Contents"
    for path in (contents, contents/"MacOS", contents/"Resources", contents/"build",
                 contents/"build/shader-service", contents/"build/spirv-cross"):
        path.mkdir(mode=0o700)
    info = {"CFBundleIdentifier": APP_ID, "CFBundlePackageType": "APPL",
            "CFBundleExecutable": "castlevania-native", "CFBundleName": "Castlevania Diagnostic",
            "CFBundleDisplayName": "Castlevania Diagnostic", "CFBundleShortVersionString": "1.1.0",
            "CFBundleVersion": "1", "NSPrincipalClass": "NSApplication", "NSHighResolutionCapable": True}
    info_path = contents/"Info.plist"
    write_private(info_path, plistlib.dumps(info, sort_keys=True))
    executable = contents/"MacOS/castlevania-native"
    copies = {"Contents/MacOS/castlevania-native":
              copy_executable(work/"build/castlevania-native", executable, build["binary_sha256"])}
    tools = build.get("shader_tool_sha256", {})
    if not isinstance(tools, dict) or set(tools) != set(SHADER_TOOLS):
        raise ValueError("bundle requires exactly the two verified native shader tools")
    for relative in SHADER_TOOLS:
        copies["Contents/build/"+relative] = copy_executable(work/"build"/relative,
                                                          contents/"build"/relative, tools[relative])
    origin = {"schema": 1, "title_id": TITLE, "compiled_binary_sha256": build["binary_sha256"],
              "compiled_build_receipt_sha256": hashlib.sha256(build_bytes).hexdigest(),
              "shader_tool_sha256": tools, "diagnostic_only": True,
              "standalone_installable_game": False}
    origin_path = contents/"Resources/diagnostic-origin.json"
    write_private(origin_path, (json.dumps(origin, indent=2)+"\n").encode())
    # Contents/build is required by the frozen executable-relative shader code.
    # Sign each fixed helper explicitly; do not rely on --deep discovery there.
    for relative in SHADER_TOOLS:
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                        str(contents/"build"/relative)], check=True, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(app)],
                   check=True, capture_output=True)
    verify_code(app)
    for relative, entry in copies.items():
        destination = app/relative
        verify_code(destination)
        require_no_entitlements(destination)
        entry["signed_copy_sha256"] = sha(destination)
        entry["signed_copy_bytes"] = destination.stat().st_size
        if sha(Path(entry["source"])) != entry["source_sha256"]:
            raise ValueError("source executable changed during bundle signing")
    code_resources = contents/"_CodeSignature/CodeResources"
    report = {"schema": 1, "requested": True, "state": "sealed_derived_diagnostic_app",
              "bundle": str(app), "bundle_identifier": APP_ID, "executable": str(executable),
              "compiled_binary_sha256": build["binary_sha256"],
              "compiled_build_receipt_sha256": hashlib.sha256(build_bytes).hexdigest(),
              "signed_executable_sha256": sha(executable), "code_copies": copies,
              "info_plist_sha256": sha(info_path), "origin_sha256": sha(origin_path),
              "code_resources_sha256": sha(code_resources), "signing": "local ad-hoc; identity '-'",
              "source_entitlements": "none; entitlement-bearing builds rejected",
              "strict_bundle_and_each_executable_verified": True, "source_executables_unchanged": True,
              "outside_bundle_links": False, "standalone_installable_game": False,
              "runtime_data": "Existing staged read-only RomFS/AOT and compiled absolute verified font paths",
              "proof_source_reuse_supported": False, "UI_inspection_verified": False}
    write_private(root/"app-bundle-receipt.json", (json.dumps(report, indent=2)+"\n").encode())
    return report


def group_members(group: int) -> list[int]:
    result = []
    rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,pgid="], text=True, timeout=2)
    for row in rows.splitlines():
        pid, pgid = map(int, row.split())
        if pgid == group:
            result.append(pid)
    return result


def error_snapshot(error: Exception) -> dict:
    """Bounded diagnostic metadata, without arbitrary command output or paths."""
    return {"type": type(error).__name__, "errno": getattr(error, "errno", None)}


def cleanup_owned_group(process: subprocess.Popen, *, phase: str,
                        term_seconds: float = 3, kill_seconds: float = 1,
                        poll_seconds: float = 0.1) -> dict:
    """Inspect and drain only the PGID created by this runner's new session.

    A failed signal never proves absence. In particular, EPERM is resolved only
    by an independent successful empty ps snapshot; permission denial with live
    members stops escalation. Inspection failure is unknown, never an empty list.
    """
    group = process.pid
    report = {"process_group_id": group, "phase": phase, "complete": False,
              "snapshots": [], "signals": [], "wait_errors": [],
              "remaining_pids": None, "forced_kill_sent": False}
    if type(group) is not int or group <= 1 or group == os.getpgrp():
        report["reason"] = "invalid_or_runner_process_group"
        return report

    def observe(label: str) -> list[int] | None:
        # Reap the host when possible; otherwise ps can report its zombie as a
        # remaining member even though it has already stopped executing.
        try:
            process.poll()
        except OSError as error:
            report["wait_errors"].append({"phase": label, **error_snapshot(error)})
        snapshot = {"phase": label}
        try:
            members = group_members(group)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            snapshot.update({"inspection_ok": False, "pids": None,
                             "error": error_snapshot(error)})
            members = None
        else:
            snapshot.update({"inspection_ok": True, "pids": members})
        report["snapshots"].append(snapshot)
        report["remaining_pids"] = members
        return members

    def finish(members: list[int] | None) -> dict:
        report["complete"] = members == [] and process.returncode is not None and not report["wait_errors"]
        report["host_wait_completed"] = process.returncode is not None
        if not report["complete"]:
            report["reason"] = ("membership_inspection_failed" if members is None else
                                "host_wait_incomplete" if process.returncode is None else
                                "host_wait_error" if report["wait_errors"] else "group_members_remain")
        return report

    def signal_group(sig: signal.Signals, label: str) -> bool:
        attempt = {"phase": label, "signal": sig.name, "signal_number": int(sig)}
        try:
            os.killpg(group, sig)
        except OSError as error:
            attempt.update({"sent": False, "error": error_snapshot(error)})
            sent = False
        else:
            attempt["sent"] = sent = True
            if sig == signal.SIGKILL:
                report["forced_kill_sent"] = True
        report["signals"].append(attempt)
        return sent

    def poll_empty(label: str, seconds: float) -> list[int] | None:
        deadline = time.monotonic() + seconds
        while True:
            members = observe(label)
            if members is None or not members or time.monotonic() >= deadline:
                return members
            time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))

    members = observe(phase + ".initial")
    if members is None or not members:
        return finish(members)
    sent = signal_group(signal.SIGTERM, phase + ".term")
    members = poll_empty(phase + ".after_term", term_seconds)
    if members is None or not members or not sent:
        return finish(members)
    signal_group(signal.SIGKILL, phase + ".kill")
    members = poll_empty(phase + ".after_kill", kill_seconds)
    return finish(members)


def gpu_options(args: argparse.Namespace) -> tuple[bool, int]:
    allow = getattr(args, "allow_gpu_submit", False)
    budget = getattr(args, "gpu_budget_mib", 2048)
    if type(allow) is not bool:
        raise ValueError("GPU submit opt-in must be a boolean")
    if type(budget) is not int or not 256 <= budget <= 4096:
        raise ValueError("GPU diagnostic budget must be256..4096 integer MiB")
    if allow and getattr(args, "with_window", False) is not True:
        raise ValueError("--allow-gpu-submit requires --with-window")
    return allow, budget


def file_size_option(args: argparse.Namespace) -> int:
    limit = getattr(args, "file_size_limit_mib", 64)
    if type(limit) is not int or not 64 <= limit <= 2048:
        raise ValueError("file size limit must be64..2048 integer MiB")
    return limit


def app_bundle_option(args: argparse.Namespace) -> bool:
    bundle = getattr(args, "app_bundle", False)
    if type(bundle) is not bool:
        raise ValueError("app bundle option must be a boolean")
    if bundle and getattr(args, "with_window", False) is not True:
        raise ValueError("--app-bundle requires --with-window")
    return bundle


def file_trace_option(args: argparse.Namespace) -> bool:
    trace = getattr(args, "trace_files", False)
    if type(trace) is not bool:
        raise ValueError("file trace option must be a boolean")
    return trace


def run(args: argparse.Namespace) -> dict:
    allow_gpu, gpu_budget = gpu_options(args)
    file_limit = file_size_option(args)
    app_requested = app_bundle_option(args)
    trace_files = file_trace_option(args)
    work = args.work.resolve(strict=True)
    if (work/".castlevania-host-build").read_text() != TITLE+"\n":
        raise ValueError("wrong build-root ownership marker")
    build_bytes = owned_bytes(work/"host-build-receipt.json")
    build = json.loads(build_bytes)
    if (build.get("state") != "actual_native_host_compiled_not_launched" or build.get("title_id") != TITLE
            or build.get("diagnostic_boot_compiled") is not True):
        raise ValueError("a measured diagnostic-boot executable is required")
    binary = work/"build/castlevania-native"
    if binary.is_symlink() or str(binary) != build["binary"] or sha(binary) != build["binary_sha256"]:
        raise ValueError("native host binary differs from its build receipt")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], check=True, capture_output=True)
    for path in (work/"extracted/v110/romfs/runtime-index.bin", work/"rewritten/v110/main.patched.bin"):
        if not path.is_file():
            raise ValueError("staged verified game inputs are missing")
    parent = work/"runs"
    private_directory(parent)
    root = Path(tempfile.mkdtemp(prefix="host-", dir=parent)).resolve()
    for name in ("home", "tmp", "config", "cache", "profile", "saves", "logs"):
        private_directory(root/name)
    token = secrets.token_hex(16)
    marker = root/".castlevania-host-run"
    fd = os.open(marker, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(TITLE+" "+token+"\n")
    for name in ("extracted", "rewritten", "build"):
        (root/name).symlink_to(work/name, target_is_directory=True)
    # Preserve the exact build receipt even after the shared work binary is
    # replaced by a later source iteration. Never reconstruct it from fields.
    write_private(root/"compiled-build-receipt.json", build_bytes)
    bundle = prepare_app_bundle(root, work, build, build_bytes) if app_requested else {"requested": False}
    reuse = {"requested": False}
    if getattr(args, "reuse_romfs_proof_from", None) is not None:
        reuse = reuse_romfs_proof(work, build, args.reuse_romfs_proof_from, root/"cache"/PROOF_NAME)
    slot = work/"state/game-slot"
    private_directory(slot)
    log = root/"logs/native-host.log"
    logfd = os.open(log, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
           "HOME": str(root/"home"), "TMPDIR": str(root/"tmp"),
           "XDG_CONFIG_HOME": str(root/"config"), "XDG_CACHE_HOME": str(root/"cache"),
           "CASTLEVANIA_RUN_ROOT": str(root), "CASTLEVANIA_RUN_TOKEN": token,
           "CASTLEVANIA_PROFILE_DIR": str(root/"profile"), "CASTLEVANIA_SAVE_DIR": str(root/"saves"),
           "CASTLEVANIA_LOG_DIR": str(root/"logs"), "CASTLEVANIA_LOG_FILE": str(log),
           "CASTLEVANIA_GAME_SLOT_DIR": str(slot), "CASTLEVANIA_LANG": "en-US",
           "CASTLEVANIA_APP_POOL": str(args.app_pool)}
    if not args.with_window:
        env["TOTK_HEADLESS"] = "1"
    if allow_gpu:
        env["TOTK_GPU_ALLOW_SUBMIT"] = "1"
        env["TOTK_GPU_BUDGET_MB"] = str(gpu_budget)
        env["TOTK_GPU_KEEPALIVE"] = "0"
    if trace_files:
        env["CASTLEVANIA_FS_LOG"] = "1"
        env["CASTLEVANIA_FS_TIMING"] = "1"
    launch_binary = Path(bundle["executable"]) if app_requested else binary
    command = [str(launch_binary), str(root/"rewritten/v110"), "boot"]
    started = time.monotonic()
    timed_out = False
    with os.fdopen(logfd, "wb") as output:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True,
                                   preexec_fn=functools.partial(child_limits, file_limit))
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        # Shader services inherit the diagnostic process group. Stop remaining
        # children only after inspecting this exact owned group. An error is
        # evidence in the receipt, never permission for broader process kills.
        cleanup = cleanup_owned_group(process, phase="timeout" if timed_out else "post_wait")
        returncode = process.returncode
    log_error = None
    try:
        log_bytes = owned_bytes(log, private=True, maximum=64 << 20)
    except (OSError, ValueError) as error:
        log_bytes = b""
        log_error = error_snapshot(error)
    tail = log_bytes[-131072:].decode("utf-8", errors="replace")
    verification = romfs_verification(log_bytes, build["resources"])
    proof_sha = None
    proof_error = None
    if verification != "not_reached_or_incomplete" and (root/"cache"/PROOF_NAME).exists():
        try:
            proof_sha = hashlib.sha256(owned_bytes(root/"cache"/PROOF_NAME, private=True, maximum=160)).hexdigest()
        except (OSError, ValueError) as error:
            proof_error = error_snapshot(error)
    diagnostics = [line[:700] for line in tail.splitlines()
                   if re.search(r"FAIL:|unimplemented|unsupported|missing symbol|signal=|ENTER |RETURN |unknown.*(?:IPC|svc|nvn)",
                                line, flags=re.I)]
    finished = cleanup["complete"] and log_error is None and proof_error is None
    receipt = {"schema": 1, "state": ("bounded_experimental_host_run_finished" if finished else
                                     "bounded_experimental_host_run_incomplete"), "title_id": TITLE,
               "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command,
               "run_root": str(root), "log": str(log),
               "log_sha256": hashlib.sha256(log_bytes).hexdigest() if log_error is None else None,
               "log_bytes": len(log_bytes) if log_error is None else None, "log_snapshot_error": log_error,
               "binary_sha256": build["binary_sha256"], "exit_code": returncode,
               "launched_binary_sha256": bundle["signed_executable_sha256"] if app_requested else build["binary_sha256"],
               "app_bundle": bundle,
               "seconds": round(time.monotonic()-started, 3), "timeout_seconds": args.timeout,
               "timed_out": timed_out, "forced_kill_of_owned_group": cleanup["forced_kill_sent"],
               "owned_process_group_cleanup": cleanup,
               "remaining_owned_process_group_pids": cleanup["remaining_pids"],
               "proof_reuse_eligible": finished and not app_requested and proof_sha is not None and verification != "not_reached_or_incomplete",
               "diagnostic_window_requested": args.with_window, "guest_entry_attempted": True,
               "gpu_submit_requested": allow_gpu, "gpu_execution_verified": False,
               "diagnostic_gpu_budget_mib": gpu_budget, "gpu_budget_applied_to_child": allow_gpu,
               "gpu_budget_is_measured_title_contract": False,
               "gpu_keepalive_disabled_by_runner": allow_gpu,
               "first_frame_verified": False, "gameplay_compatibility_verified": False,
               "project_slot_scope": "Castlevania diagnostic runs sharing this build root",
               "diagnostic_app_pool_bytes": args.app_pool,
               "app_pool_is_measured_title_contract": False,
               "diagnostic_file_size_limit_mib": file_limit,
               "child_rlimit_fsize_bytes": file_limit << 20,
               "file_size_limit_is_measured_title_contract": False,
               "file_trace_requested": trace_files,
               "file_trace_flags_applied_to_child": trace_files,
               "file_trace_log_scope": "existing owned mode0600 native-host.log in this private run",
               "source_inputs_and_existing_game_profiles_modified_by_runner": False,
               "run_marker_sha256": sha(marker),
               "compiled_build_receipt_sha256": hashlib.sha256(build_bytes).hexdigest(),
               "runtime_romfs_verification_mode": verification,
               "runtime_romfs_proof_sha256": proof_sha,
               "runtime_romfs_proof_snapshot_error": proof_error,
               "runtime_romfs_proof_reuse": reuse,
               "diagnostic_tail": diagnostics[-30:], "runner_sha256": sha(Path(__file__))}
    write_private(root/"receipt.json", (json.dumps(receipt, indent=2)+"\n").encode())
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=30, metavar="SECONDS")
    parser.add_argument("--app-pool", type=lambda value: int(value, 0), default=0xce000000,
                        help="Explicit diagnostic memory budget (default3296MiB); not a measured title contract")
    parser.add_argument("--with-window", action="store_true", help="Request the actual native frontend during the bounded diagnostic")
    parser.add_argument("--allow-gpu-submit", action="store_true",
                        help="Explicitly permit real GPU submission; requires --with-window")
    parser.add_argument("--gpu-budget-mib", type=int, default=2048,
                        help="Diagnostic GPU budget256..4096MiB (default2048), not a measured title contract")
    parser.add_argument("--file-size-limit-mib", type=int, default=64,
                        help="Child-only per-file limit64..2048MiB (default64), not a measured title contract")
    parser.add_argument("--app-bundle", action="store_true",
                        help="Launch a fresh sealed derived diagnostic .app; requires --with-window")
    parser.add_argument("--trace-files", action="store_true",
                        help="Enable existing RomFS open/read timing logs only in this private child run")
    parser.add_argument("--reuse-romfs-proof-from", type=Path, metavar="PRIOR_RUN",
                        help="Explicitly copy an owned completed run's C full-hash record; C metadata checks remain final authority")
    args = parser.parse_args()
    if not 5 <= args.timeout <= 180 or not 256 << 20 <= args.app_pool <= 8 << 30 or args.app_pool % (2 << 20):
        parser.error("timeout must be5..180 seconds and app pool256MiB..8GiB aligned to2MiB")
    try:
        gpu_options(args)
        file_size_option(args)
        app_bundle_option(args)
        file_trace_option(args)
    except ValueError as error:
        parser.error(str(error))
    try:
        receipt = run(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "diagnostic_not_started_or_incomplete", "reason": str(error)}))
        return 2
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["state"] == "bounded_experimental_host_run_finished" else 2


if __name__ == "__main__":
    raise SystemExit(main())
