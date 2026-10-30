#!/usr/bin/env python3
"""Prepare a private NRO derivative; this neither installs nor executes it.

Default: write/read back the synthetic NSO candidate only. --rewrite invokes
the pinned, unchanged generic engine after source review. Original NRO/NRR and
RomFS remain authoritative; the derivative is not NRR-authenticated. Dynamic
mapping, RO APIs, relocations, constructors, exports and gameplay are unproven.
All output must be in a fresh directory outside Git. Never point it at RomFS.
"""
import argparse
import ast
import datetime
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from nro_to_nso import MAX_IMAGE, make_nso, require, sha256

ENGINE_DIR = Path(__file__).resolve().parents[1] / 'third_party/d2r'
ENGINE_PINS = {
    'patch_nso.py': '1239f34af30030c942d8c4147ead6c1531101da08c7efd958b83f37c5d032c32',
    'call_window.py': 'a51c5350eeef1ae27934d4732f001b9d217db8495c0d97e44cd9ce2c2f191a4f',
    'relr.py': 'afa0b371c494af7814ba0aa34c40f6376381269cd70895f24e61426e35129f44',
}
OUTPUT_SUFFIXES = ('patched.bin', 'fixups.tsv', 'gates.tsv', 'sites.tsv',
                   'cuts.tsv', 'obs.tsv', 'params.tsv')


def snapshot(st):
    return {k: getattr(st, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def engine_environment():
    # No inherited DM/D2R/PYTHON/DYLD variables, HOME, search paths or user site.
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'DM_RULESET': 'native', 'DM_PRIVATE_GATES': '0',
            'PYTHONDONTWRITEBYTECODE': '1'}


def verify_engine(build_id):
    sources = {}
    for name, expected in ENGINE_PINS.items():
        path = ENGINE_DIR / name
        require(not path.is_symlink() and path.is_file(), 'Missing/linked engine source')
        sources[name] = path.read_bytes()
        require(sha256(sources[name]) == expected, 'Pinned engine/dependency SHA256 mismatch')
    # Inspect literals, never import the executable top-level engine.
    tree = ast.parse(sources['patch_nso.py'])
    rule_ids = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if names & {'CUTS', 'OBS', 'PARAMS', 'SIGNED_TABLES'}:
            require(isinstance(node.value, ast.Dict), 'Engine rule table shape changed')
            for key in node.value.keys:
                require(isinstance(key, ast.Constant) and isinstance(key.value, str), 'Nonliteral engine rule ID')
                rule_ids.add(key.value)
        if 'RULE_BUILD' in names:
            require(isinstance(node.value, ast.Constant), 'Nonliteral engine rule build')
            rule_ids.add(node.value.value)
    require(build_id not in rule_ids, 'Input build ID selects donor-specific engine rules')
    return dict(ENGINE_PINS)


def private_output_path(path):
    path = path.expanduser().absolute()
    require(not path.exists() and not path.is_symlink(), 'Output directory already exists')
    parent = path.parent.resolve(strict=True)
    require(all(not (p / '.git').exists() for p in (parent, *parent.parents)), 'Private output must be outside Git')
    # Canonical parent eliminates a symlink route into an unrelated directory.
    return parent / path.name


def write_private(path, data):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == data, 'Private output readback mismatch')


def verify_engine_outputs(directory, module):
    expected = {f'{module}.{s}' for s in OUTPUT_SUFFIXES} | {'build_src.sha256'}
    require({p.name for p in directory.iterdir()} == expected, 'Unexpected/missing engine output')
    artifacts = []
    for path in sorted(directory.iterdir()):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_IMAGE * 2,
                'Invalid engine output file')
        os.chmod(path, 0o600)
        raw = path.read_bytes()
        if path.suffix == '.tsv' and path.name.endswith(('.cuts.tsv', '.obs.tsv', '.params.tsv')):
            require(not any(line.strip() and not line.startswith(b'#') for line in raw.splitlines()),
                    'Donor cut/observation/parameter output is forbidden')
        if path.name == 'build_src.sha256':
            require(raw.decode().split() == [ENGINE_PINS['patch_nso.py'], 'patch_nso.py'], 'Engine source receipt mismatch')
        if path.name.endswith('.patched.bin'):
            require(len(raw) > 0, 'Empty native derivative')
        artifacts.append({'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw),
                          'independent_readback_sha256': sha256(path.read_bytes())})
    return artifacts


def verify_native_flat_image(directory, module, original, metadata):
    """Reject header/metadata/data/BSS edits; never repair engine output."""
    headers = {}
    for line in (directory / f'{module}.fixups.tsv').read_text().splitlines():
        fields = line.split('\t')
        require(len(fields) == 2 and fields[0].startswith('# '), 'Unexpected engine fixup metadata')
        key = fields[0][2:]
        require(key not in headers, 'Duplicate engine layout field')
        headers[key] = int(fields[1], 0)
    require({'PATCH_OFF', 'KEY_PAGE_OFF', 'KEY_PAGE_SIZE', 'TEXT_END', 'RO_OFF', 'DATA_OFF'}.issubset(headers),
            'Missing engine layout fields')
    text_end = metadata['segments'][0]['size']
    memory_end = len(original) + metadata['bss_size']
    require(headers['TEXT_END'] == text_end and headers['RO_OFF'] == text_end and
            headers['DATA_OFF'] == metadata['segments'][2]['offset'] and
            headers['KEY_PAGE_OFF'] == (memory_end + 0x3FFF) & ~0x3FFF and
            headers['KEY_PAGE_SIZE'] == 0x4000, 'Engine layout differs from original NRO')
    patch = headers['PATCH_OFF']
    image_offset = -patch if patch < 0 else 0
    native = (directory / f'{module}.patched.bin').read_bytes()
    require(image_offset + memory_end <= len(native), 'Truncated native flat image')
    flat = native[image_offset:image_offset + memory_end]
    require(flat[:0x80] == original[:0x80], 'Engine modified embedded NRO header')
    require(flat[text_end:len(original)] == original[text_end:], 'Engine modified original RO/data/MOD0 metadata')
    require(flat[len(original):] == bytes(metadata['bss_size']), 'Engine modified original BSS')
    allowed = set()
    for line in (directory / f'{module}.sites.tsv').read_text().splitlines():
        fields = line.split('\t')
        require(2 <= len(fields) <= 4, 'Malformed engine site inventory')
        start, kind = int(fields[0], 0), fields[1]
        require(kind in {'x18', 'svc', 'tpidr_r', 'tpidr_w', 'tpidrro_r', 'cntpct', 'cntvct', 'W', 'C', 'J'},
                'Unknown engine site kind')
        require(len(fields) == (3 if kind in {'W', 'C'} else 4 if kind == 'J' else 2),
                'Invalid engine site field count')
        end = int(fields[2], 0) if kind in {'W', 'C'} else start + 4
        require(0x80 <= start < end <= text_end and start % 4 == end % 4 == 0,
                'Engine site intersects NRO header/outside text')
        allowed.update(range(start, end, 4))
    changed = [off for off in range(0x80, text_end, 4) if flat[off:off + 4] != original[off:off + 4]]
    require(set(changed).issubset(allowed), 'Native text changes outside declared engine sites')
    return {'NRO_header_unchanged': True, 'original_RO_data_MOD0_unchanged': True,
            'original_BSS_zero_unchanged': True, 'site_inventory_excludes_NRO_header': True,
            'all_text_changes_inside_declared_site_ranges': True,
            'changed_text_word_count': len(changed), 'flat_image_file_offset': image_offset}


def prepare(input_path, expected_sha256, output_path, module, rewrite=False):
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is not None, 'Expected SHA256 must be lowercase hex')
    require(re.fullmatch(r'[a-z][a-z0-9_]{0,39}', module) is not None and
            module not in {'main', 'sdk', 'subsdk0', 'rtld'}, 'Unsafe/reserved module name')
    source = input_path.expanduser().resolve(strict=True)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0x80 <= before.st_size <= MAX_IMAGE, 'Invalid source file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            original = stream.read(MAX_IMAGE + 1)
        require(sha256(original) == expected_sha256, 'Original NRO SHA256 mismatch')
        container, metadata = make_nso(original)
        pins = verify_engine(metadata['module_id'][:32])
        destination = private_output_path(output_path)
        destination.mkdir(mode=0o700)
        container_path = destination / f'{module}.synthetic.nso'
        write_private(container_path, container)
        outputs = []
        flat_readback = None
        engine_command = None
        if rewrite:
            native = destination / 'native'
            native.mkdir(mode=0o700)
            engine_command = [sys.executable, '-B', '-E', '-s', str(ENGINE_DIR / 'patch_nso.py'),
                              str(container_path), str(native), module]
            # The private log may contain engine assertion bytes; never echo it or add it to Git.
            with (destination / 'engine-private.log').open('xb') as log:
                os.chmod(log.name, 0o600)
                result = subprocess.run(engine_command, cwd=destination, env=engine_environment(),
                                        stdout=log, stderr=subprocess.STDOUT, timeout=600, check=False)
            require(result.returncode == 0, 'Pinned engine failed; see private log (no ready receipt)')
            outputs = verify_engine_outputs(native, module)
            flat_readback = verify_native_flat_image(native, module, original, metadata)
            require(verify_engine(metadata['module_id'][:32]) == pins, 'Engine changed during preparation')
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            source_readback_sha = sha256(stream.read(MAX_IMAGE + 1))
        after = os.fstat(fd)
        require(snapshot(before) == snapshot(after) == snapshot(source.stat()) and
                source_readback_sha == expected_sha256, 'Original source changed during preparation')
        receipt = {
            'schema': 1, 'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status': 'native_derivative_prepared_not_executed' if rewrite else 'container_candidate_readback_verified',
            'module': module, 'original': {'path': str(source), **metadata,
                'expected_sha256': expected_sha256, 'source_before': snapshot(before),
                'source_after': snapshot(after), 'independent_readback_sha256': source_readback_sha},
            'container': {'path': str(container_path), 'sha256': sha256(container),
                'bytes': len(container), 'independent_readback_sha256': sha256(container_path.read_bytes()),
                'flat_initialized_image_bytes_preserved': container[0x100:] == original},
            'engine': {'source_directory': str(ENGINE_DIR), 'sha256_pins': pins,
                'command': engine_command, 'environment': engine_environment(),
                'donor_build_rules_rejected': True, 'cuts_observations_parameters_forbidden': True},
            'preparer_source_sha256': {p.name: sha256(p.read_bytes()) for p in
                (Path(__file__).resolve(), Path(__file__).resolve().with_name('nro_to_nso.py'))},
            'artifacts': outputs, 'native_flat_image_readback': flat_readback,
            'limits': {'original_NRR_binding_does_not_authenticate_derivative': True,
                'RomFS_original_modified': False, 'original_engine_modified': False,
                'guest_or_SDK_executed': False, 'runtime_mapping_implemented': False,
                'RO_API_integration_verified': False, 'runtime_or_gameplay_verified': False},
        }
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
        write_private(destination / 'PREPARATION-RECEIPT.json', encoded)
        require(json.loads((destination / 'PREPARATION-RECEIPT.json').read_bytes()) == receipt, 'Receipt readback mismatch')
        checksums = [(sha256(encoded), 'PREPARATION-RECEIPT.json'), (sha256(container), container_path.name)]
        checksums += [(a['sha256'], 'native/' + Path(a['path']).name) for a in outputs]
        write_private(destination / 'SHA256SUMS', ''.join(f'{h}  {p}\n' for h, p in checksums).encode())
        return receipt
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--module', required=True)
    parser.add_argument('--rewrite', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    receipt = prepare(args.input, args.expected_sha256, args.output_directory, args.module, args.rewrite)
    print(json.dumps({'status': receipt['status'], 'output': str(args.output_directory),
                      'original_sha256': receipt['original']['sha256'], 'runtime_verified': False}))


if __name__ == '__main__':
    main()
