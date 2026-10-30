#!/usr/bin/env python3
"""Build the real Castlevania host from measured local inputs; never launch it.

--reuse-romfs-digest is for source-only iterations in an already successful work
directory. It inherits the expected image digest from that build's saved receipt;
it does NOT verify the current image bytes. The runtime's mandatory full image
SHA check remains required before RomFS use. All other input hashes stay fresh.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TITLE = "0100BA4026E94000"
MARKER = ".castlevania-host-build"
FRAMEWORKS = ("Metal", "MetalFX", "Foundation", "QuartzCore", "ImageIO", "CoreGraphics", "CoreText",
              "UniformTypeIdentifiers", "Cocoa", "CoreVideo", "CoreFoundation", "AudioToolbox",
              "GameController", "CoreHaptics", "IOKit", "Security")


def sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def owned_work(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("build root must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = path.resolve(strict=True)
    if path.stat().st_uid != os.getuid():
        raise ValueError("build root must belong to the current user")
    marker = path / MARKER
    if marker.is_symlink():
        raise ValueError("refusing a symlink ownership marker")
    if marker.exists():
        if marker.read_text() != TITLE + "\n":
            raise ValueError("build directory belongs to a different title")
    else:
        if any(path.iterdir()):
            raise ValueError("existing nonempty build directory lacks the Castlevania marker")
        marker.write_text(TITLE + "\n")
    return path


def checked_copy(source: Path, destination: Path, digest: str) -> None:
    if sha(source) != digest:
        raise ValueError("input SHA mismatch: " + source.name)
    if destination.is_symlink():
        raise ValueError("refusing a symlink output: " + destination.name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if sha(destination) != digest or sha(source) != digest:
        raise ValueError("copy readback/source preservation failed: " + source.name)


def input_link(source: Path, destination: Path, digest: str, *, verify_sha: bool = True) -> None:
    source = source.resolve(strict=True)
    if verify_sha and sha(source) != digest:
        raise ValueError("read-only input differs from its measured profile: " + source.name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        if destination.resolve(strict=True) != source:
            raise ValueError("existing input link points to a different file")
    elif destination.exists():
        raise ValueError("refusing to replace an existing staged input")
    else:
        destination.symlink_to(source)


def module_inputs(work: Path, exefs: Path, aot: Path) -> dict:
    candidate = json.loads((ROOT.parent/"probe/candidate-v110/profile.json").read_text())
    if candidate["title_id"].upper() != TITLE or candidate["display_version"] != "1.1.0":
        raise ValueError("unsupported game profile")
    for name, entry in candidate["source_modules"].items():
        if name not in {"main", "subsdk0", "sdk", "rtld"}:
            raise ValueError("unexpected executable module")
        input_link(exefs/name, work/"extracted/v110/exefs"/name, entry["sha256"])
    receipt = json.loads((ROOT.parent/"probe/rewritten-v110/rewrite-receipt.json").read_text())
    if receipt["state"] != "static_AOT_rewrite_complete" or receipt["ruleset"] != "native":
        raise ValueError("completed native rewrite proof missing")
    if sha(ROOT/"third_party/d2r/patch_nso.py") != receipt["rewriter_sha256"]:
        raise ValueError("rewriter source differs from the measured AOT checkpoint")
    for module in receipt["modules"]:
        if module["module"] not in {"main", "subsdk0", "sdk"} or module["exit_code"]:
            raise ValueError("unverified rewritten module")
        for entry in module["outputs"]:
            name = entry["name"]
            if Path(name).name != name:
                raise ValueError("invalid rewrite artifact name")
            input_link(aot/name, work/"rewritten/v110"/name, entry["sha256"])
    return {"version": "1.1.0", "source_modules": candidate["source_modules"],
            "rewriter_sha256": receipt["rewriter_sha256"], "read_only_inputs": True}


def inherited_romfs_digest(work: Path, image: Path, manifest: dict, index_sha: str,
                           config: bytes) -> dict:
    """Bind an expected digest to a successful prior build, without reading image bytes."""
    prior_path = work / "host-build-receipt.json"
    if prior_path.is_symlink() or not prior_path.is_file():
        raise ValueError("RomFS digest reuse requires a prior successful build receipt")
    prior_bytes = prior_path.read_bytes()
    prior = json.loads(prior_bytes)
    binary = work / "build/castlevania-native"
    if (not isinstance(prior, dict) or prior.get("schema") != 1
            or prior.get("state") != "actual_native_host_compiled_not_launched"
            or prior.get("title_id") != TITLE or prior.get("work") != str(work)
            or prior.get("binary") != str(binary) or binary.is_symlink()
            or sha(binary) != prior.get("binary_sha256")):
        raise ValueError("RomFS digest reuse requires this title's successful build in the same work directory")
    old = prior["resources"]
    if not isinstance(old, dict):
        raise ValueError("prior RomFS resource receipt must be an object")
    old_proof = old.get("romfs_digest_provenance")
    if old_proof is not None and (
            not isinstance(old_proof, dict)
            or old_proof.get("mode") not in {"fresh_full_image_sha256", "inherited_expected_digest"}
            or old_proof.get("image_sha256_verified_in_this_build") is not (old_proof.get("mode") == "fresh_full_image_sha256")
            or old_proof.get("runtime_full_image_sha256_required_before_use") is not True):
        raise ValueError("prior RomFS digest provenance is inconsistent")
    config_sha = hashlib.sha256(config).hexdigest()
    if (old.get("romfs_image") != str(image) or old.get("romfs_image_sha256") != manifest["romfs_sha256"]
            or old.get("romfs_index_sha256") != index_sha or old.get("romfs_files") != len(manifest["files"])):
        raise ValueError("RomFS metadata differs from the prior successful build")
    # Older successful receipts did not record size/config SHA. Their existing
    # generated header below supplies the old size; never invent an old stat baseline.
    if "romfs_digest_provenance" in old or "romfs_image_size" in old or "romfs_config_sha256" in old:
        if old.get("romfs_image_size") != manifest["romfs_size"] or old.get("romfs_config_sha256") != config_sha:
            raise ValueError("RomFS size/config differs from the prior successful build")
    old_config = work / "generated/romfs_config.h"
    old_index = work / "extracted/v110/romfs/runtime-index.bin"
    if (old_config.is_symlink() or old_index.is_symlink() or old_config.read_bytes() != config
            or sha(old_index) != index_sha):
        raise ValueError("prior generated RomFS config/index must match exactly for digest reuse")
    prior_sha = hashlib.sha256(prior_bytes).hexdigest()
    history = work / "romfs-digest-receipts"
    if history.is_symlink():
        raise ValueError("RomFS receipt history must not be a symlink")
    history.mkdir(mode=0o700, exist_ok=True)
    saved = history / (prior_sha + ".json")
    if saved.is_symlink():
        raise ValueError("saved RomFS receipt must not be a symlink")
    if saved.exists():
        if saved.read_bytes() != prior_bytes:
            raise ValueError("saved RomFS receipt differs from its content hash")
    else:
        with saved.open("xb") as handle:
            handle.write(prior_bytes)
        saved.chmod(0o600)
    return {"mode": "inherited_expected_digest", "image_sha256_verified_in_this_build": False,
            "runtime_full_image_sha256_required_before_use": True,
            "prior_host_build_receipt": str(saved), "prior_host_build_receipt_sha256": prior_sha}


def romfs_headers(work: Path, romfs: Path, *, reuse_romfs_digest: bool = False) -> dict:
    generated = work / "generated"
    generated.mkdir(exist_ok=True)
    manifest = json.loads((romfs / "index.json").read_text())
    if manifest.get("status") != "pass":
        raise ValueError("RomFS index is not verified")
    if not re.fullmatch("[0-9a-f]{64}", manifest["romfs_sha256"]):
        raise ValueError("invalid RomFS SHA-256")
    image = (romfs / "romfs.bin").resolve(strict=True)
    if not image.is_file() or image.stat().st_size != manifest["romfs_size"]:
        raise ValueError("RomFS image size mismatch")
    names, rows, previous = bytearray(), bytearray(), None
    for entry in manifest["files"]:
        name = entry["path"]
        if (not isinstance(name, str) or "\0" in name or name.startswith("/") or
                ".." in name.split("/") or (previous is not None and name <= previous)):
            raise ValueError("RomFS names must be bounded sorted relative paths")
        offset, size = entry["offset"], entry["size"]
        if offset < 0 or size < 0 or offset > manifest["romfs_size"] or size > manifest["romfs_size"]-offset:
            raise ValueError("RomFS entry is outside the verified image")
        encoded = name.encode("utf-8") + b"\0"
        rows.extend(struct.pack("<QQII", offset, size, len(names), len(encoded)))
        names.extend(encoded)
        previous = name
    index = struct.pack("<8sQQ", b"TOTKRFS1", len(manifest["files"]), 24+len(rows)) + rows + names
    index_sha = hashlib.sha256(index).hexdigest()
    config = (f'#define ROMFS_IMAGE_SIZE {manifest["romfs_size"]}ULL\n'
              f'#define ROMFS_IMAGE_SHA256 "{manifest["romfs_sha256"]}"\n'
              f'#define ROMFS_INDEX_SHA256 "{index_sha}"\n').encode("utf-8")
    proof = (inherited_romfs_digest(work, image, manifest, index_sha, config) if reuse_romfs_digest else
             {"mode": "fresh_full_image_sha256", "image_sha256_verified_in_this_build": True,
              "runtime_full_image_sha256_required_before_use": True})
    staged_romfs = work / "extracted/v110/romfs"
    staged_romfs.mkdir(parents=True, exist_ok=True)
    input_link(image, staged_romfs/"romfs.bin", manifest["romfs_sha256"], verify_sha=not reuse_romfs_digest)
    runtime_index = staged_romfs / "runtime-index.bin"
    if runtime_index.is_symlink():
        raise ValueError("runtime index must not be a symlink")
    if runtime_index.exists() and runtime_index.read_bytes() != index:
        raise ValueError("existing runtime index differs; retain and inspect it first")
    if not runtime_index.exists():
        runtime_index.write_bytes(index)
    (generated / "romfs_config.h").write_bytes(config)
    return {"romfs_image": str(image), "romfs_image_sha256": manifest["romfs_sha256"],
            "romfs_image_size": manifest["romfs_size"], "romfs_files": len(manifest["files"]),
            "romfs_index_sha256": index_sha, "romfs_config_sha256": hashlib.sha256(config).hexdigest(),
            "romfs_digest_provenance": proof}


def resource_headers(work: Path, tables: Path, romfs: Path, fonts: Path, *, reuse_romfs_digest: bool = False) -> dict:
    generated = work / "generated"
    generated.mkdir(exist_ok=True)
    profile = json.loads((ROOT / "profiles/loader-v110.json").read_text())
    if profile.get("title_id", TITLE).upper() != TITLE:
        raise ValueError("wrong loader title")
    checked_copy(tables, generated / "runtime_tables.h", profile["runtime_tables_sha256"])
    resources = romfs_headers(work, romfs, reuse_romfs_digest=reuse_romfs_digest)
    font_manifest = json.loads((fonts / "manifest.json").read_text())
    if font_manifest.get("status") != "pass" or [f["type"] for f in font_manifest["fonts"]] != list(range(6)):
        raise ValueError("six verified local system fonts are required")
    font_rows = []
    for font in font_manifest["fonts"]:
        if not re.fullmatch("[a-z][a-z0-9-]*", font["name"]) or not re.fullmatch("[0-9a-f]{64}", font["sha256"]):
            raise ValueError("invalid shared font metadata")
        filename = f'{font["type"]}-{font["name"]}.bfttf'
        original = fonts / filename
        if original.stat().st_size != font["bfttf_bytes"] or font["font_bytes"]+8 != font["bfttf_bytes"]:
            raise ValueError("shared font size mismatch")
        copied = work / "firmware/shared-fonts" / filename
        checked_copy(original, copied, font["sha256"])
        font_rows.append(f'{{{json.dumps(str(copied))},{font["bfttf_bytes"]}ULL,{font["font_bytes"]}ULL,"{font["sha256"]}"}}')
    (generated / "shared_fonts_config.h").write_text(
        "#define SHARED_FONT_COUNT 6\n#define SHARED_FONT_ROWS " + ",".join(font_rows) + "\n")
    return {**resources, "runtime_tables_sha256": sha(generated / "runtime_tables.h"), "shared_font_files": 6}


def source_hashes() -> dict:
    result = {}
    for directory in (ROOT / "runtime", ROOT / "third_party/d2r_gfx"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.suffix in {".c", ".m", ".S", ".h", ".inc"}:
                result[str(path.relative_to(ROOT))] = sha(path)
    return result


def build(args: argparse.Namespace) -> dict:
    work = owned_work(args.work)
    modules = module_inputs(work, args.exefs.resolve(strict=True), args.aot.resolve(strict=True))
    resources = resource_headers(work, args.tables.resolve(strict=True), args.romfs.resolve(strict=True),
                                 args.fonts.resolve(strict=True), reuse_romfs_digest=args.reuse_romfs_digest)
    tools = args.shader_tools.resolve(strict=True)
    tool_receipt = json.loads((tools/"receipt.json").read_text())
    if (tool_receipt.get("status") != "ready_real_ARM64_shader_tools" or
            tool_receipt.get("SPIRV_source_commit") != "aa217aeb6c9f0ace7a0ab233b28807edf45eb165"):
        raise ValueError("verified pinned shader-tool receipt is missing")
    verified_tools = {str(Path(x["path"]).resolve(strict=True)): x for x in tool_receipt["tools"]}
    shader_hashes = {}
    for relative in ("shader-service/totk_xlate", "spirv-cross/spirv-cross"):
        source = tools / relative
        if not source.is_file() or not os.access(source, os.X_OK):
            raise ValueError("verified shader tool missing: " + relative)
        verified = verified_tools.get(str(source.resolve(strict=True)))
        if not verified or source.stat().st_size != verified["bytes"]:
            raise ValueError("shader executable is not the recorded verified tool")
        checked_copy(source, work / "build" / relative, verified["SHA256"])
        shader_hashes[relative] = verified["SHA256"]
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("DEVELOPER_DIR"):
        env["DEVELOPER_DIR"] = os.environ["DEVELOPER_DIR"]
    target_defines = ["-DGAME_CASTLEVANIA=1"]
    if args.diagnostic_boot:
        target_defines.append("-DCASTLEVANIA_DIAGNOSTIC_BOOT=1")
    macros = subprocess.check_output(
        ["/usr/bin/xcrun", "clang", "-E", "-dM", "-x", "c", *target_defines,
         "-include", str(ROOT/"runtime/castlevania_policy.h"), "/dev/null"], env=env, text=True)
    expected_entry = "1" if args.diagnostic_boot else "0"
    if not re.search(r"^#define CASTLEVANIA_DIAGNOSTIC_BOOT " + expected_entry + r"$", macros, re.M):
        raise ValueError("source policy does not implement the requested diagnostic entry scope")
    includes = ["-I"+str(ROOT/"runtime"), "-I"+str(work/"generated"),
                "-I"+str(ROOT/"third_party/d2r_gfx/gfx/nvn/include"),
                "-I/opt/homebrew/opt/opus/include/opus", "-I/opt/homebrew/opt/libvpx/include"]
    runtime = [p for p in (ROOT/"runtime").iterdir() if p.suffix in {".c", ".m", ".S"}
               and p.name not in {"frontend_ios.m", "castlevania_loader_probe.c"}]
    graphics = [p for folder in ("third_party/d2r_gfx/gfx/nvn", "third_party/d2r_gfx/gfx/tex")
                for p in (ROOT/folder).iterdir() if p.suffix in {".c", ".m", ".S"}]
    before = source_hashes()
    logdir = work/"compile-logs"
    logdir.mkdir(exist_ok=True)
    jobs = []
    for path in sorted(runtime+graphics):
        relative = str(path.relative_to(ROOT))
        obj = work/"objects"/(relative+".o")
        obj.parent.mkdir(parents=True, exist_ok=True)
        flags = ["-arch", "arm64", "-O2", "-g", *target_defines, *includes]
        if path.suffix != ".S":
            flags += ["-std=gnu11", "-Wall", "-Wextra", "-Wno-deprecated-declarations"]
            flags += ["-Werror"] if path in runtime else ["-Wno-error", "-Wno-unused-function", "-Wno-unused-parameter"]
        if path.suffix == ".m":
            flags += ["-fobjc-arc"]
        jobs.append((relative, ["/usr/bin/xcrun", "clang", *flags, "-c", str(path), "-o", str(obj)], obj))

    def compile_one(job):
        relative, command, obj = job
        completed = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True)
        log = logdir/(relative.replace("/", "_")+".log")
        log.write_text(completed.stdout+completed.stderr)
        return {"source": relative, "exit_code": completed.returncode, "log": str(log),
                "object": str(obj), "command": command}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(compile_one, jobs))
    (work/"compile-results.json").write_text(json.dumps(results, indent=2)+"\n")
    failures = [x for x in results if x["exit_code"]]
    if failures:
        raise ValueError("host source compilation failed: " + ", ".join(x["source"] for x in failures))
    if source_hashes() != before:
        raise ValueError("source changed during compilation; do not use these objects")
    binary = work/"build/castlevania-native"
    libraries = [Path("/opt/homebrew/opt/opus/lib/libopus.a"), Path("/opt/homebrew/opt/libvpx/lib/libvpx.a")]
    for lib in libraries:
        if not lib.is_file():
            raise ValueError("native dependency missing: " + lib.name)
    command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-O2", "-g",
               *(str(x[2]) for x in jobs), *(str(p) for p in libraries)]
    for framework in FRAMEWORKS:
        command += ["-framework", framework]
    command += ["-o", str(binary)]
    completed = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True)
    (logdir/"link.log").write_text(completed.stdout+completed.stderr)
    if completed.returncode:
        raise ValueError("host linking failed; inspect compile-logs/link.log")
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(binary)],
                   check=True, env=env, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], check=True, env=env, capture_output=True)
    architecture = subprocess.check_output(["/usr/bin/file", str(binary)], text=True).strip()
    if "Mach-O 64-bit executable arm64" not in architecture:
        raise ValueError("unexpected native executable architecture")
    dependencies = subprocess.check_output(["/usr/bin/otool", "-L", str(binary)], text=True)
    receipt = {"schema": 1, "state": "actual_native_host_compiled_not_launched", "title_id": TITLE,
               "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "work": str(work),
               "binary": str(binary), "binary_sha256": sha(binary), "architecture": architecture,
               "builder_sha256": sha(Path(__file__)),
               "dependencies": dependencies, "source_hashes": before, "resources": resources, "modules": modules,
               "shader_tool_sha256": shader_hashes,
               "compiled_objects": len(jobs), "guest_code_executed": False, "app_installed": False,
               "diagnostic_boot_compiled": args.diagnostic_boot,
               "compatible_gameplay_verified": False, "link_command": command}
    (work/"host-build-receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--tables", required=True, type=Path)
    parser.add_argument("--exefs", required=True, type=Path)
    parser.add_argument("--aot", required=True, type=Path)
    parser.add_argument("--romfs", required=True, type=Path)
    parser.add_argument("--fonts", required=True, type=Path)
    parser.add_argument("--shader-tools", required=True, type=Path)
    parser.add_argument("--reuse-romfs-digest", action="store_true",
                        help="Source-only rebuild: inherit the prior successful build's expected RomFS digest; current image bytes remain unverified until runtime")
    parser.add_argument("--jobs", type=int, default=2, choices=(1, 2))
    parser.add_argument("--diagnostic-boot", action="store_true", help="Compile the explicit guarded diagnostic boot entry")
    args = parser.parse_args()
    try:
        receipt = build(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "build_failed", "reason": str(error), "guest_code_executed": False}))
        return 2
    print(json.dumps({k: receipt[k] for k in ("state", "binary", "binary_sha256", "compiled_objects")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
