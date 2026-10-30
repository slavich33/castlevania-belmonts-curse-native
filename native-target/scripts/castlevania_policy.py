"""Identity, file integrity and owned run paths for the Castlevania diagnostics."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
TITLE_ID = "0100BA4026E94000"
VERSION = "1.1.0"
LOAD_ORDER = ["main", "subsdk0", "sdk"]
SOURCE_INPUTS = [
    "runtime/castlevania_loader_probe.c", "runtime/castlevania_policy.h",
    "runtime/castlevania_paths.h", "runtime/runtime.h",
    "third_party/d2r_gfx/gfx/nvn/include/mach_vm_compat.h",
]

class PolicyError(ValueError):
    pass

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def read_profile(root: Path = ROOT) -> tuple[dict, Path]:
    path = root / "profiles/loader-v110.json"
    profile = json.loads(path.read_text())
    if (profile.get("title_id"), profile.get("display_version"), profile.get("load_order"), profile.get("mode")) != (TITLE_ID, VERSION, LOAD_ORDER, "native_loader_mapping_only"):
        raise PolicyError("unsupported title, version, load order or execution mode")
    if profile.get("guest_instructions_authorized") is not False:
        raise PolicyError("this runner cannot authorize guest instructions")
    return profile, path

def source_hashes(root: Path = ROOT) -> dict[str, str]:
    return {name: digest(root / name) for name in SOURCE_INPUTS}

def verify_modules(directory: Path, profile: dict) -> dict[str, str]:
    directory = directory.resolve(strict=True)
    checked = {}
    for name in LOAD_ORDER:
        path = directory / f"{name}.patched.bin"
        if not path.is_file() or path.is_symlink():
            raise PolicyError(f"missing or symlink AOT module: {name}")
        expected = profile["modules"][name]
        value = digest(path)
        if path.stat().st_size != expected["bytes"] or value != expected["sha256"]:
            raise PolicyError(f"AOT module integrity mismatch: {name}")
        checked[name] = value
    return checked

def host_path_plan(home: Path) -> dict[str, str]:
    """Pure planning only: never inspect or create the user's profile folders."""
    support = home / "Library/Application Support/MacNativeGames/CastlevaniaBelmont"
    return {"profile": str(support / "profile"), "saves": str(support / "profile/save"),
            "cache": str(support / "cache"), "config": str(support / "config"),
            "log": str(home / "Library/Logs/MacNativeGames/castlevania-belmont.log"),
            "display_suite": "org.macnativegames.castlevania-belmont.display"}

def ensure_owned_directory(path: Path) -> None:
    if path.is_symlink():
        raise PolicyError("run directory must not be a symlink")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PolicyError("run directory must be owned by this user with mode 0700")

def create_run(root: Path = ROOT) -> dict[str, str]:
    parent = root / "analysis/loader-runs"
    # Reject symlink aliases before creating or resolving any path.
    for part in [root, root / "analysis", parent]:
        if part.is_symlink():
            raise PolicyError("run parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.stat().st_uid != os.getuid():
        raise PolicyError("foreign run parent owner")
    run = Path(tempfile.mkdtemp(prefix="mapping-", dir=parent)).resolve()
    ensure_owned_directory(run)
    paths = {"root": str(run), "token": uuid.uuid4().hex}
    for name in ["home", "tmp", "profile", "saves", "config", "cache", "logs"]:
        path = run / name
        path.mkdir(mode=0o700)
        ensure_owned_directory(path)
        paths[name] = str(path)
    marker = run / ".castlevania-loader-run"
    with marker.open("x") as out:
        out.write(f"{TITLE_ID} {paths['token']}\n")
    marker.chmod(0o600)
    return paths

def child_environment(paths: dict[str, str]) -> dict[str, str]:
    """No inherited TOTK/Ori/LM3, DYLD, user preferences or input scripts."""
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
            "HOME": paths["home"], "TMPDIR": paths["tmp"],
            "XDG_CONFIG_HOME": paths["config"], "XDG_CACHE_HOME": paths["cache"],
            "CASTLEVANIA_RUN_ROOT": paths["root"], "CASTLEVANIA_RUN_TOKEN": paths["token"],
            "CASTLEVANIA_PROFILE_DIR": paths["profile"], "CASTLEVANIA_SAVE_DIR": paths["saves"],
            "CASTLEVANIA_LOG_DIR": paths["logs"],
            "CASTLEVANIA_LOG_FILE": str(Path(paths["logs"]) / "native-loader.log")}
