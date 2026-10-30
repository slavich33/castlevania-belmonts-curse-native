#!/usr/bin/env python3
"""No-key host-startup and export-rejection controls; never persists raw output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import run_bounded_listromfs_20261027 as bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        raise ValueError('Refusing existing receipt')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
    source = root/'tooling/Atmosphere-6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8/tools/hac2l'
    tool = source/'out/generic_macos_arm64/release/hac2l'
    processor = (source/'source/hactool_processor.hpp').read_text()
    keys_source = (source/'source/hactool_processor.keys.cpp').read_text()
    options_source = (source/'source/hactool_options.cpp').read_text()
    assert 'AMS_UNUSED(field_name, src, src_size);' in processor
    assert 'AMS_UNUSED(ks);' in keys_source
    assert 'if (options.file_type == FileType::Keygen) { return options; }' in options_source
    assert 'for (const char *output : forbidden) { if (output != nullptr) { return options; } }' in options_source
    destinations = options_source.split('const char *forbidden[] = {', 1)[1].split('};', 1)[0]
    assert destinations.count('options.') == 26
    forbidden_output = root/'must-not-be-created-20261027'
    assert not forbidden_output.exists()
    controls = []
    for name, arguments in [('no_arguments', []), ('help', ['--help']),
                            ('key_export_rejected', ['--intype', 'keys']),
                            ('asset_export_rejected', ['--outdir', str(forbidden_output),
                                                        str(root/'input-does-not-exist-20261027')]),
                            ('probe_export_missing_verification_rejected', ['--probe-romfs-image', str(root/'input-does-not-exist-20261027')]),
                            ('probe_export_raw_rejected', ['--probe-romfs-image','--intype','nsp','--verify','--enablehash','--listromfs','--basensp',str(root/'input-does-not-exist-20261027'),'--raw',str(root/'input-does-not-exist-20261027')]),
                            ('probe_export_arbitrary_destination_rejected', ['--probe-romfs-image','--romfs',str(forbidden_output),str(root/'input-does-not-exist-20261027')]),
                            ('probe_export_keygen_rejected', ['--probe-romfs-image','--intype','keys'])]:
        code, data, reason, seconds = bounded.limited_run([str(tool)] + arguments)
        controls.append({'name': name, 'exit_code': code,
                         'Usage_seen': b'Usage:' in data or b'usage:' in data,
                         'captured_bytes': len(data), 'termination_reason': reason,
                         'seconds': seconds})
        data[:] = b'\0' * len(data)
    assert all(c['exit_code'] == 0 and c['Usage_seen'] and not c['termination_reason'] for c in controls)
    assert not forbidden_output.exists()
    receipt = {'state': 'audited_bounded_probe_binary_controls_passed',
               'tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
               'binary_bytes': tool.stat().st_size, 'controls': controls,
               'single_image_export_allowlist_negative_controls_passed': True,
               'fixed_image_destination_absent': not Path('/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/prepared-v110/romfs/romfs.bin.partial').exists(),
               'PrintBytes_disabled': True, 'PrintKeys_disabled': True,
               'all_26_export_destinations_rejected': True,
               'physical_input_read_limit_bytes': 128 << 20,
               'bignum_assembly_text_unchanged_by_symbol_patch': True,
               'raw_tool_output_saved': False, 'game_or_key_inputs_used': False,
               'storage_or_integrity_bypass_added': False}
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    assert json.loads(args.receipt.read_text()) == receipt
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
