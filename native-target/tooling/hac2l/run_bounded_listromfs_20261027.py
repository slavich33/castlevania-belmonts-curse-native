#!/usr/bin/env python3
"""RAM-only hac2l metadata probe; persist only an allowlisted receipt.

The executable must be built from the audited secret-output/export-disabled
source. This wrapper neither copies keys nor exports any game file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import subprocess
import time

ROOT = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
MAX_OUTPUT = 8 << 20
MAX_SECONDS = 180


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))


def limited_run(command):
    # Separate streams avoid stderr markers splitting stdout filenames mid-line.
    stdout_data, stderr_data = bytearray(), bytearray()
    reason = None
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=child_limits, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, stdout_data)
    selector.register(process.stderr, selectors.EVENT_READ, stderr_data)
    try:
        while selector.get_map():
            if time.monotonic() - started > MAX_SECONDS:
                reason = 'wall_time_limit'
                break
            for key, _ in selector.select(0.25):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(stdout_data) + len(stderr_data) + len(chunk) + 1 > MAX_OUTPUT:
                    reason = 'RAM_output_limit'
                    break
                key.data.extend(chunk)
            if reason:
                break
        if reason:
            process.terminate()
        try:
            code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=3)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    output = stdout_data + b'\n' + stderr_data
    stdout_data[:] = b'\0' * len(stdout_data)
    stderr_data[:] = b'\0' * len(stderr_data)
    return code, output, reason, round(time.monotonic() - started, 3)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--update', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-tool-sha256', required=True)
    a = parser.parse_args()
    if a.output.exists():
        raise ValueError('Refusing existing receipt')
    actual_sha = hashlib.sha256(a.tool.read_bytes()).hexdigest()
    if actual_sha != a.expected_tool_sha256:
        raise ValueError('Tool binary differs from audited build receipt')
    before = {p: p.stat() for p in (a.base, a.update)}
    # No implicit default console/title key files. NSP tickets are imported by
    # the tool into its in-memory manager; only the explicit protected keyset is read.
    command = [str(a.tool), '--intype', 'nsp', '--verify', '--enablehash', '--disablekeywarns',
               '--keyset', str(a.keys), '--titlekeys', '/dev/null',
               '--consolekeys', '/dev/null', '--basensp', str(a.base),
               '--listromfs', str(a.update)]
    code, captured, reason, seconds = limited_run(command)
    lines = captured.decode('utf-8', errors='replace').splitlines()
    # Accept only known RomFS pathname syntax, never arbitrary stdout/stderr.
    files = sorted({line for line in lines
                    if re.fullmatch(r'rom:/[A-Za-z0-9 _./()\[\]+@,#%&!;=~\-]+', line)
                    and '..' not in line.split('/') and '[probe]' not in line})
    counts = [int(match.group(1)) for line in lines
              if (match := re.fullmatch(r'\[probe\] physical_input_bytes=(\d+)', line))]
    header1 = [int(match.group(1)) for line in lines
               if (match := re.fullmatch(r'\[probe\] nca_header1_valid=([01])', line))]
    base_program_readers = [int(match.group(1)) for line in lines
                            if (match := re.fullmatch(r'\[probe\] base_program_reader_attached=([01])', line))]
    romfs_views = [{'sparse_base': int(match.group(1)) == 1,
                   'BKTR': int(match.group(2)) == 1,
                   'IVFC': int(match.group(3)) == 1,
                   'storage_bytes': int(match.group(4))}
                  for line in lines
                  if (match := re.fullmatch(r'\[probe\] romfs_views sparse=([01]) indirect=([01]) integrity=([01]) size=(\d+)', line))]
    base_candidate_counts = [int(match.group(1)) for line in lines
                             if (match := re.fullmatch(r'\[probe\] base_candidate_count=(\d+)', line))]
    signature_counts = {}
    for line in lines:
        match = re.fullmatch(r'\[probe\] verification field=(HeaderSign1|HeaderSign2|Signature) passed=([01])', line)
        if match:
            key = match.group(1) + ('_passed' if match.group(2) == '1' else '_unverified')
            signature_counts[key] = signature_counts.get(key, 0) + 1
    error_codes = sorted(set(re.findall(r'(?<![0-9])2[0-9]{3}-[0-9]{4}(?![0-9])', '\n'.join(lines))))
    budget_denied = any(line == '[probe] physical_read_budget_exceeded' for line in lines)
    warnings = sum('[Warning]' in line for line in lines)
    known_failures = {
        'section_open': any('Failed to open NCA section' in line or 'Failed to open raw NCA section' in line or 'Failed to mount NCA section' in line for line in lines),
        'base_open': any('Failed to process base' in line or 'Failed to open base' in line for line in lines),
        'romfs_listing': any('Failed to print directory' in line for line in lines),
        'base_identity_mismatch': any(line == '[probe] base_identity_match=0' for line in lines),
        'base_ambiguous': any(count != 1 for count in base_candidate_counts),
        'tool_failed': any('tool failed to process input' in line for line in lines),
        'assertion_or_abort': any('Assertion' in line or 'Abort' in line or 'Panic' in line for line in lines),
    }
    # Raw text and the subprocess command are intentionally absent from receipts.
    captured[:] = b'\x00' * len(captured)
    del captured, lines, command
    inputs = []
    for path, old in before.items():
        now = path.stat()
        if (old.st_size, old.st_mtime_ns, old.st_ino) != (now.st_size, now.st_mtime_ns, now.st_ino):
            raise ValueError('Source package changed during bounded metadata probe')
        inputs.append({'path': str(path), 'bytes': now.st_size,
                       'mtime_ns': now.st_mtime_ns, 'source_unchanged': True})
    success = (code == 0 and bool(files) and bool(header1) and all(header1) and not reason and not budget_denied
               and any(base_program_readers) and bool(romfs_views)
               and all(view['sparse_base'] and view['BKTR'] and view['IVFC'] for view in romfs_views)
               and not any(known_failures.values()))
    receipt = {'state': 'bounded_merged_RomFS_listing_complete' if success else 'bounded_merged_RomFS_probe_incomplete',
               'tool_sha256': actual_sha, 'exit_code': code, 'seconds': seconds,
               'termination_reason': reason, 'source_packages': inputs,
               'physical_input_read_budget_bytes': 128 << 20,
               'admitted_physical_read_upper_bound_bytes': max(counts) if counts else None,
               'read_budget_denied': budget_denied, 'safe_error_codes': error_codes,
               'NCA_header1_checks': len(header1), 'NCA_header1_checks_passed': sum(header1),
               'signature_boolean_counts': signature_counts,
               'warning_count': warnings, 'known_failure_categories': known_failures,
               'base_Program_reader_attached': any(base_program_readers),
               'base_candidate_counts': base_candidate_counts, 'RomFS_storage_views': romfs_views,
               'RomFS_file_count': len(files), 'RomFS_file_paths': files,
               'full_RomFS_extracted': False, 'any_game_file_exported': False,
               'key_values_or_key_paths_saved': False, 'raw_tool_output_saved': False,
               'game_executed': False, 'GPU_executed': False,
               'verification_scope': 'NCA HeaderSign1 booleans are counted explicitly. Metadata paths traverse the stock sparse/BKTR/IVFC views; whole-payload IVFC is not claimed. HeaderSign2 may be unavailable for sparse base ExeFS.'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(receipt, indent=2)+'\n')
    a.output.chmod(0o600)
    if json.loads(a.output.read_text()) != receipt:
        raise ValueError('Receipt readback mismatch')
    print(json.dumps({k: v for k, v in receipt.items() if k not in ('RomFS_file_paths', 'source_packages')}, indent=2))
    return 0 if success else 2


if __name__ == '__main__':
    raise SystemExit(main())
