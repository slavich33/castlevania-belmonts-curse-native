#!/usr/bin/env python3
"""Single fixed-image export wrapper; RAM-only diagnostics, full source/hash readback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import struct
import sys
import time
import run_bounded_listromfs_20261027 as bounded

ROOT = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
DESTINATION = Path('/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/prepared-v110/romfs')
EXPECTED_BYTES = 3600101664
READ_CAP = 7348649984


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def stat_identity(path):
    value = path.stat()
    return value.st_size, value.st_mtime_ns, value.st_ino


def read_at(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('Truncated image')
    return data


def index_romfs(path):
    # Nintendo RomFS10Q header and32/24-byte entries; same schema as TOTK index_romfs.
    with path.open('rb') as stream:
        header = struct.unpack('<10Q', read_at(stream, 0, 80))
        length = path.stat().st_size
        if header[0] != 80 or header[9] > length:
            raise ValueError('RomFS header mismatch')
        for off, size in ((header[1],header[2]), (header[3],header[4]),
                          (header[5],header[6]), (header[7],header[8])):
            if off + size > length or size > 32 << 20:
                raise ValueError('RomFS metadata bounds')
        dirs = read_at(stream, header[3], header[4])
        entries = read_at(stream, header[7], header[8])
        files = []
        seen_dirs, seen_files, paths = set(), set(), set()
        def name(table, offset, size):
            if offset + size > len(table):
                raise ValueError('Name bounds')
            value = table[offset:offset+size].decode('utf-8')
            if value in ('.','..') or any(c in value for c in ('/','\\','\0')):
                raise ValueError('Unsafe path')
            return value
        todo = [(0, '')]
        while todo:
            off, parent = todo.pop()
            if off in seen_dirs or off + 24 > len(dirs):
                raise ValueError('Invalid/cyclic directory')
            seen_dirs.add(off)
            previous, sibling, child, file, hash_next, size = struct.unpack_from('<6I', dirs, off)
            part = name(dirs, off+24, size)
            prefix = parent + part + '/' if part else parent
            if sibling != 0xffffffff:
                todo.append((sibling, parent))
            if child != 0xffffffff:
                todo.append((child, prefix))
            while file != 0xffffffff:
                if file in seen_files or file + 32 > len(entries):
                    raise ValueError('Invalid/cyclic file')
                seen_files.add(file)
                previous, next_file, data, size, hash_next, name_size = struct.unpack_from('<IIQQII', entries, file)
                part = name(entries, file+32, name_size)
                filename = prefix + part
                if not part or filename in paths or header[9] + data + size > length:
                    raise ValueError('Duplicate/out-of-bounds file')
                paths.add(filename)
                files.append({'path': filename, 'offset': header[9]+data, 'size': size})
                file = next_file
    return sorted(files, key=lambda row: row['path'])


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (EXPECTED_BYTES,EXPECTED_BYTES))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--expected-tool-sha256', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    if args.receipt.exists() or DESTINATION.exists():
        raise ValueError('Refusing existing receipt/destination')
    if DESTINATION.parent.resolve() != Path('/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/prepared-v110'):
        raise ValueError('Destination parent differs from fixed allowlist')
    tool = ROOT/'tooling/Atmosphere-6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8/tools/hac2l/out/generic_macos_arm64/release/hac2l'
    if digest(tool) != args.expected_tool_sha256:
        raise ValueError('Binary SHA mismatch')
    listing = json.loads((ROOT/'hac2l-bounded-merged-listromfs-20261027-r3.json').read_text())
    if listing['state'] != 'bounded_merged_RomFS_listing_complete' or listing['RomFS_file_count'] != 3101:
        raise ValueError('Verified metadata gate absent')
    source_root = Path("/Volumes/YOUR_WORKSPACE/Castlevania Belmont's Curse [NSP]")
    base = source_root/'Castlevania Belmonts Curse [0100BA4026E94000][v0].nsp'
    update = source_root/'Castlevania Belmonts Curse [0100BA4026E94800][v65536].nsp'
    before = {path: stat_identity(path) for path in (base,update)}
    before_hashes = {path: digest(path) for path in (base,update)}
    if any(stat_identity(path) != before[path] for path in before):
        raise ValueError('Source changed while hashing')
    with (ROOT/'hac2l-export-source-before-20261027.json').open('x') as saved:
        json.dump([{'path':str(path),'bytes':before[path][0],'sha256_before':before_hashes[path]} for path in before],saved,indent=2)
        saved.write('\n')
    print('Both encrypted source package SHA256 values recorded; starting fixed-image export.', flush=True)
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.mkdir(mode=0o700)
    if DESTINATION.resolve() != DESTINATION:
        raise ValueError('Destination resolves outside fixed allowlist')
    if os.statvfs(DESTINATION).f_bavail * os.statvfs(DESTINATION).f_frsize < EXPECTED_BYTES + (2 << 30):
        raise ValueError('Insufficient reserved free space')
    command = [str(tool), '--intype','nsp','--verify','--enablehash','--disablekeywarns',
               '--keyset',str(args.keys),'--titlekeys','/dev/null','--consolekeys','/dev/null',
               '--basensp',str(base),'--listromfs','--probe-romfs-image',str(update)]
    bounded.MAX_SECONDS = 900
    bounded.child_limits = child_limits
    code, captured, reason, seconds = bounded.limited_run(command)
    lines = captured.decode('utf-8', errors='replace').splitlines()
    header_checks = [int(m.group(1)) for line in lines if (m := re.fullmatch(r'\[probe\] nca_header1_valid=([01])',line))]
    signatures = {field: [int(m.group(1)) for line in lines if (m := re.fullmatch(r'\[probe\] verification field='+field+r' passed=([01])',line))] for field in ('HeaderSign1','HeaderSign2','Signature')}
    counts = [int(m.group(1)) for line in lines if (m := re.fullmatch(r'\[probe\] physical_input_bytes=(\d+)',line))]
    export_counts = [int(m.group(1)) for line in lines if (m := re.fullmatch(r'\[probe\] romfs_export_bytes=(\d+)',line))]
    error_codes = sorted(set(re.findall(r'(?<![0-9])2[0-9]{3}-[0-9]{4}(?![0-9])','\n'.join(lines))))
    all_warnings = [line for line in lines if '[Warning]' in line]
    suppressed_key_warning_count = sum(line == '[Warning]: key loading detail suppressed by bounded probe' for line in all_warnings)
    unexpected_warning_count = len(all_warnings)-suppressed_key_warning_count
    facts = {'exit_code':code,'seconds':seconds,'termination_reason':reason,
             'NCA_header1_checks':len(header_checks),'NCA_header1_passed':sum(header_checks),
             'signature_boolean_checks':signatures,'safe_error_codes':error_codes,
             'admitted_input_read_upper_bound_bytes':max(counts) if counts else None,
             'admitted_input_read_cap_bytes':READ_CAP,'file_write_cap_bytes':EXPECTED_BYTES,
             'last_exported_byte':max(export_counts) if export_counts else None,
             'suppressed_key_loading_warning_count':suppressed_key_warning_count,
             'unexpected_warning_count':unexpected_warning_count,
             'eligible':'[probe] romfs_export_eligible=1' in lines,
             'complete':'[probe] romfs_export_complete=1' in lines,
             'base_unique':'[probe] base_candidate_count=1' in lines,
             'base_identity':'[probe] base_identity_match=1' in lines,
             'budget_denied':'[probe] physical_read_budget_exceeded' in lines}
    success = (code == 0 and not reason and len(header_checks) == 4 and all(header_checks)
               and all(signatures[field] and all(signatures[field]) for field in signatures)
               and not error_codes and not unexpected_warning_count and facts['eligible'] and facts['complete']
               and facts['base_unique'] and facts['base_identity'] and not facts['budget_denied']
               and facts['last_exported_byte'] == EXPECTED_BYTES and counts and max(counts) <= READ_CAP)
    captured[:] = b'\0' * len(captured)
    del captured, lines, command, all_warnings
    scalar_path = ROOT/'hac2l-export-scalars-20261027.json'
    with scalar_path.open('x') as output:
        json.dump(facts, output, indent=2)
        output.write('\n')
    partial = DESTINATION/'romfs.bin.partial'
    sources = []
    for path in before:
        after_hash = digest(path)
        unchanged = before[path] == stat_identity(path) and before_hashes[path] == after_hash
        sources.append({'path':str(path),'bytes':before[path][0],
                        'sha256_before':before_hashes[path],'sha256_after':after_hash,'unchanged':unchanged})
        success = success and unchanged
    with (ROOT/'hac2l-export-source-after-20261027.json').open('x') as saved:
        json.dump(sources,saved,indent=2)
        saved.write('\n')
    if success and partial.is_file() and partial.stat().st_size == EXPECTED_BYTES:
        image_hash = digest(partial)
        with (ROOT/'hac2l-export-image-SHA-20261027.json').open('x') as saved:
            json.dump({'image_bytes':EXPECTED_BYTES,'image_sha256':image_hash},saved,indent=2)
            saved.write('\n')
        files = index_romfs(partial)
        if len(files) != 3101 or {'rom:/'+row['path'] for row in files} != set(listing['RomFS_file_paths']):
            raise ValueError('Independent image index differs from verified metadata listing')
        report = {'status':'pass','romfs_size':EXPECTED_BYTES,'romfs_sha256':image_hash,'files':files,
                  'integrity':'Stock sparse+BKTR merge and IVFC for every image byte; NCA HeaderSign1, Program HeaderSign2 and NPDM signature checks passed'}
        # Same-directory hard link prevents overwrite; only our partial name is removed.
        image = DESTINATION/'romfs.bin'
        os.link(partial,image,follow_symlinks=False)
        partial.unlink()
        index_path = DESTINATION/'index.json'
        with index_path.open('x') as output:
            json.dump(report,output,indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        index_path.chmod(0o600)
        if json.loads(index_path.read_text()) != report or digest(image) != image_hash:
            raise ValueError('Independent final image/index readback differs')
        facts.update({'RomFS_bytes':EXPECTED_BYTES,'RomFS_sha256':image_hash,'RomFS_files':len(files),
                      'image':str(image),'index':str(index_path),'index_sha256':digest(index_path)})
    else:
        success = False
    receipt = {'state':'verified_single_RomFS_image_complete' if success else 'single_RomFS_image_incomplete',
               'tool_sha256':args.expected_tool_sha256,'facts':facts,'source_packages':sources,
               'all_26_standard_export_destinations_rejected':True,'key_export_disabled':True,
               'raw_tool_output_saved':False,'key_values_or_paths_saved':False,'asset_file_tree_exported':False,
               'game_executed':False,'GPU_executed':False}
    args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    args.receipt.chmod(0o600)
    if json.loads(args.receipt.read_text()) != receipt:
        raise ValueError('Receipt readback mismatch')
    print(json.dumps({'state':receipt['state'],'facts':facts},indent=2),flush=True)
    return 0 if success else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Fixed-image export stopped: exception type='+type(error).__name__,flush=True)
        raise SystemExit(3)
