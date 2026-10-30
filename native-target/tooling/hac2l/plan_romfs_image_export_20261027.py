#!/usr/bin/env python3
"""Bounded header-only export plan. Key material stays in RAM and is never emitted."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/Users/your-user/Games/TOTK_build/totk/scripts')
from extract_exefs import container_entries, decrypt, load_keys, read_at
from cryptography.hazmat.primitives.ciphers import modes


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--keys', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        raise ValueError('Refusing existing receipt')
    keys = load_keys(args.keys)
    root = Path("/Volumes/YOUR_WORKSPACE/Castlevania Belmont's Curse [NSP]")
    rows = []
    for kind, name in [('base', 'Castlevania Belmonts Curse [0100BA4026E94000][v0].nsp'),
                       ('update', 'Castlevania Belmonts Curse [0100BA4026E94800][v65536].nsp')]:
        package = root/name
        before = package.stat()
        with package.open('rb') as stream:
            _, entries = container_entries(stream, before.st_size)
            programs = [entry for entry in entries if entry[0].endswith('.nca') and entry[2] > 100 << 20]
            if len(programs) != 1:
                raise ValueError('Ambiguous Program NCA entry')
            entry_name, offset, physical_size = programs[0]
            raw = read_at(stream, offset, 0xc00)
            header = b''.join(decrypt(keys['header_key'], modes.XTS(i.to_bytes(16, 'big')), raw[512*i:512*(i+1)]) for i in range(6))
            if header[0x200:0x204] != b'NCA3' or header[0x205] != 0:
                raise ValueError('Expected NCA3 Program')
            sections = []
            for index in range(4):
                fs = header[0x400+512*index:0x600+512*index]
                start, end = struct.unpack_from('<II', header, 0x240+16*index)
                if start == end:
                    continue
                if hashlib.sha256(fs).digest() != header[0x280+32*index:0x2a0+32*index]:
                    raise ValueError('FS header hash mismatch')
                if fs[2] != 0 or fs[3] != 3:
                    continue
                if fs[8:12] != b'IVFC':
                    raise ValueError('IVFC signature mismatch')
                layers = struct.unpack_from('<I', fs, 0x14)[0]
                if not 2 <= layers <= 7:
                    raise ValueError('IVFC layer count out of range')
                levels = []
                for level in range(layers-1):
                    layer_offset, size, order, reserved = struct.unpack_from('<QQII', fs, 0x18+24*level)
                    if not 5 <= order <= 24 or reserved != 0:
                        raise ValueError('Unexpected IVFC layer fields')
                    block = 1 << order
                    levels.append({'offset': layer_offset, 'size': size, 'block_order': order,
                                   'aligned_size': (size+block-1)//block*block})
                compression_offset, compression_size = struct.unpack_from('<qq', fs, 0x178)
                sections.append({'section': index, 'section_virtual_bytes': (end-start)*512,
                                 'FS_header_hash_verified': True, 'IVFC_levels': levels,
                                 'decoded_RomFS_bytes': levels[-1]['size'],
                                 'compression_bucket_bytes': compression_size})
            rows.append({'kind': kind, 'Program_NCA': entry_name,
                         'physical_NCA_bytes': physical_size, 'RomFS_sections': sections})
        after = package.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError('Source package changed')
    update = rows[1]['RomFS_sections']
    if len(update) != 1 or update[0]['decoded_RomFS_bytes'] != 3600101664 or update[0]['compression_bucket_bytes'] != 0:
        raise ValueError('Measured update RomFS differs from verified metadata')
    total_aligned = sum(level['aligned_size'] for level in update[0]['IVFC_levels'])
    budget = 2*total_aligned + (128 << 20)
    receipt = {'state': 'header_derived_single_RomFS_image_export_plan_not_executed',
               'header_views': rows, 'expected_RomFS_bytes': 3600101664,
               'IVFC_aligned_data_and_hash_levels_bytes': total_aligned,
               'input_wrapper_charges_per_NCA_read': 2,
               'metadata_and_cache_margin_bytes': 128 << 20,
               'proposed_admitted_read_cap_bytes': budget,
               'cap_basis': 'Two nested read-budget wrappers (Program NCA then NSP) charge each physical input read. Add all aligned IVFC data/hash levels and retain128MiB metadata/cache margin. This is an enforced cap; a cache overrun fails closed and requires review, not an integrity bypass.',
               'output_image': '/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/prepared-v110/romfs/romfs.bin.partial',
               'output_open': 'O_CREAT|O_EXCL|O_NOFOLLOW mode0600 under new owned0700 directory',
               'required_checks': ['exact ProgramId0100BA4026E94000', 'unique base Application Program exact title/index/version/storage', 'sparse+BKTR+IVFC views true', 'all NCA HeaderSign1 + Program HeaderSign2 + NPDM signature', 'every sequential image read through stock IVFC storage', 'expected byte count', 'fsync', 'independent readback SHA256 and RomFS index bounds'],
               'remaining_26_standard_export_destinations': 'all permanently rejected; proposed export uses a separate single hardcoded destination mode',
               'full_RomFS_exported': False, 'key_values_or_key_paths_saved': False,
               'raw_tool_output_saved': False, 'game_executed': False}
    args.output.write_text(json.dumps(receipt, indent=2)+'\n')
    args.output.chmod(0o600)
    assert json.loads(args.output.read_text()) == receipt
    print(json.dumps({k: v for k, v in receipt.items() if k != 'header_views'}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Header-only planning stopped: exception type='+type(error).__name__)
        raise SystemExit(2)
