#!/usr/bin/env python3
"""Independent tiny binary fixtures; no owned input or rewriter execution."""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import nro_to_nso as frontend
import prepare_native_nro as wrapper


def fixture():
    # Independently authored flat image with one undefined ordinary import.
    raw = bytearray((i * 17 + 3) & 255 for i in range(0x3000))
    raw[:0x80] = bytes(0x80)
    raw[0x10:0x14] = b'NRO0'
    struct.pack_into('<I', raw, 4, 0x1020)
    struct.pack_into('<II', raw, 0x18, len(raw), 0)
    for i in range(3):
        struct.pack_into('<II', raw, 0x20 + 8 * i, i * 0x1000, 0x1000)
    struct.pack_into('<I', raw, 0x38, 0x1000)
    raw[0x40:0x60] = bytes(range(32))
    struct.pack_into('<I', raw, 0x60, 0x2800)
    struct.pack_into('<IIII', raw, 0x70, 0x180, 8, 0x140, 48)
    raw[0x1020:0x103C] = b'MOD0' + struct.pack('<6i', *(v - 0x1020 for v in
        (0x2000, 0x2F00, 0x3F00, 0x11C0, 0x11CC, 0x3000)))
    struct.pack_into('<5I', raw, 0x1100, 1, 2, 1, 0, 0)
    raw[0x1140:0x1170] = bytes(48)
    struct.pack_into('<IBBHQQ', raw, 0x1158, 1, 0x12, 0, 0, 0, 0)
    raw[0x1180:0x1188] = b'\0printf\0'
    raw[0x11C0:0x11CC] = bytes((1, 0x1B, 3, 0x3B)) + struct.pack('<iI', -4, 0)
    entries = [(4, 0x1100), (5, 0x1180), (6, 0x1140), (10, 8), (11, 24),
               (7, 0x1200), (8, 24), (9, 24), (12, 0x80), (0, 0)]
    for i, pair in enumerate(entries):
        struct.pack_into('<qQ', raw, 0x2000 + i * 16, *pair)
    struct.pack_into('<QQq', raw, 0x1200, 0x2800, 1027, 0x80)
    return raw


class FrontendTests(unittest.TestCase):
    def test_standalone_cli_private_readback_sha_and_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'tiny.nro'; source.write_bytes(fixture())
            output = root / 'tiny.synthetic.nso'
            command = [sys.executable, '-B', str(SCRIPTS / 'nro_to_nso.py'), str(source), str(output),
                       '--expected-sha256', frontend.sha256(source.read_bytes())]
            before = source.read_bytes()
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
            result = json.loads(completed.stdout)
            self.assertEqual(output.read_bytes()[0x100:], before)
            self.assertEqual(result['container_sha256'], frontend.sha256(output.read_bytes()))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(source.read_bytes(), before)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes()[0x100:], before)
            other = root / 'wrong-sha.nso'; bad = command.copy(); bad[4] = str(other); bad[-1] = '0' * 64
            self.assertNotEqual(subprocess.run(bad, capture_output=True, check=False).returncode, 0)
            self.assertFalse(other.exists())

    def reject(self, raw, text=None):
        with self.assertRaisesRegex(ValueError, text or '.'):
            frontend.make_nso(raw)

    def test_complete_flat_image_preserved(self):
        raw = fixture()
        nso, meta = frontend.make_nso(raw)
        self.assertEqual(nso[0x100:], raw)
        self.assertEqual(nso[:4], b'NSO0')
        self.assertEqual(struct.unpack_from('<I', nso, 0xC)[0], 0x38)
        self.assertEqual(nso[0x40:0x60], raw[0x40:0x60])
        self.assertEqual(meta['bss_size'], 0x1000)
        self.assertEqual(struct.unpack_from('<I', nso, 0x3C)[0], 0x1000)
        self.assertEqual(meta['mod0']['bss_start'], 0x2F00)  # legitimate initialized tail
        self.assertEqual(nso[0x88:0x98], raw[0x70:0x80])
        for i in range(3):
            fo, mo, length = struct.unpack_from('<III', nso, 0x10 + 16 * i)
            self.assertEqual((fo, mo, length), (0x100 + 0x1000 * i, 0x1000 * i, 0x1000))
            self.assertEqual(nso[fo:fo + length], raw[mo:mo + length])
            self.assertEqual(nso[0xA0 + 32 * i:0xC0 + 32 * i],
                             bytes.fromhex(frontend.sha256(raw[mo:mo + length])))

    def test_short_trailing_wrong_magic_version_and_compression(self):
        self.reject(b'NRO0')
        self.reject(fixture() + b'X')
        for off, value in ((0x10, 0), (0x14, 1), (0x1C, 1), (0x1C, 2), (0x3C, 1), (0x68, 4)):
            with self.subTest(off=off, value=value):
                raw = fixture(); struct.pack_into('<I', raw, off, value); self.reject(raw)

    def test_segment_overlap_gap_zero_unaligned_and_huge_bss(self):
        for off, value in ((0x28, 0), (0x28, 0x1800), (0x2C, 0), (0x24, 0x1001), (0x38, 0x80000000)):
            with self.subTest(off=off):
                raw = fixture(); struct.pack_into('<I', raw, off, value); self.reject(raw)

    def test_mod0_ranges_and_dynamic_termination(self):
        for off, value in ((4, 0xFFFFFFF0), (0x1024, 0x100000), (0x1030, 0x5000), (0x1034, -0x1000)):
            with self.subTest(off=off):
                raw = fixture(); struct.pack_into('<i' if value < 0 else '<I', raw, off, value); self.reject(raw)
        raw = fixture(); struct.pack_into('<qQ', raw, 0x2090, 30, 0); self.reject(raw)
        for runtime in (0x3FFF, 0x3001, 0x3E38, 0x2EF8):
            raw = fixture(); struct.pack_into('<i', raw, 0x1038, runtime - 0x1020)
            self.reject(raw, 'descriptor span')

    def test_unknown_dynamic_tls_relr_and_needed(self):
        for tag in (1, 0x6FFFFEF6, 0x6FFFFEF7, 35, 36, 37, 0x12345678):
            raw = fixture(); struct.pack_into('<q', raw, 0x2080, tag); self.reject(raw, 'Unsupported dynamic')
        raw = fixture(); struct.pack_into('<qQ', raw, 0x2080, 30, 16); self.reject(raw, 'static TLS')

    def test_symbol_header_hash_bounds_and_tls(self):
        for off, value in ((0x78, 0x141), (0x1104, 100000), (0x1108, 2), (0x1158, 1000)):
            raw = fixture(); struct.pack_into('<I', raw, off, value); self.reject(raw)
        raw = fixture(); raw[0x115C] = 0x16; self.reject(raw, 'TLS')
        for info in (0x1A, 0x32, 0x15):
            raw = fixture(); raw[0x115C] = info; self.reject(raw, 'symbol kind/binding')
        raw = fixture(); raw[0x1180:0x1190] = b'\0__tls_get_addr\0'; struct.pack_into('<I', raw, 0x74, 16)
        struct.pack_into('<Q', raw, 0x2038, 16); self.reject(raw, 'TLS')
        for tag, value in ((3, 0xFFFFFFF8), (14, 8), (0x6FFFFFF9, 2)):
            raw = fixture(); struct.pack_into('<qQ', raw, 0x2080, tag, value); self.reject(raw)
        raw = fixture(); struct.pack_into('<qQ', raw, 0x2080, 0x6FFFFEF5, 0x1300)
        struct.pack_into('<4IQII', raw, 0x1300, 1, 1, 1, 5, 0, 1, 1)
        frontend.parse_nro(raw)
        for off, value in ((0x1300, 100000), (0x1304, 3), (0x1308, 3), (0x1318, 2)):
            modified = bytearray(raw); struct.pack_into('<I', modified, off, value); self.reject(modified)

    def test_tls_unknown_and_invalid_relocations(self):
        for kind in (1028, 1029, 1030, 1031, 9999):
            raw = fixture(); struct.pack_into('<Q', raw, 0x1208, kind); self.reject(raw, 'relocation kind')
        for target, info in ((0xFFFFFFF8, 1027), (0x800, 1027), (0x2800, (2 << 32) | 1026),
                             (0x2800, (1 << 32) | 1027)):
            raw = fixture(); struct.pack_into('<QQ', raw, 0x1200, target, info); self.reject(raw)

    def test_eh_and_ctor_array_invalid_metadata(self):
        raw = fixture(); raw[0x11C1] = 0xFF; self.reject(raw, 'EH')
        raw = fixture(); struct.pack_into('<I', raw, 0x11C8, 100); self.reject(raw, 'EH')
        raw = fixture(); struct.pack_into('<Q', raw, 0x2088, 0x1000); self.reject(raw, 'DT_INIT')


class WrapperTests(unittest.TestCase):
    def test_native_flat_readback_protects_header_ro_data_bss_and_site_inventory(self):
        original = bytes(fixture()); metadata = frontend.parse_nro(original)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tiny.fixups.tsv').write_text(
                '# PATCH_OFF\t0x10000\n# KEY_PAGE_OFF\t0x4000\n# KEY_PAGE_SIZE\t0x4000\n'
                '# TEXT_END\t0x1000\n# RO_OFF\t0x1000\n# DATA_OFF\t0x2000\n')
            sites = root / 'tiny.sites.tsv'; sites.write_text('0x80\tx18\n')
            raw = bytearray(original + bytes(0x1000)); raw[0x80] ^= 1
            path = root / 'tiny.patched.bin'; path.write_bytes(raw)
            proof = wrapper.verify_native_flat_image(root, 'tiny', original, metadata)
            self.assertEqual(proof['changed_text_word_count'], 1)
            for off, expected in ((0x40, 'header'), (0x1020, 'RO/data'), (0x2800, 'RO/data'), (0x3000, 'BSS')):
                modified = bytearray(raw); modified[off] ^= 1; path.write_bytes(modified)
                with self.subTest(off=off), self.assertRaisesRegex(ValueError, expected):
                    wrapper.verify_native_flat_image(root, 'tiny', original, metadata)
            path.write_bytes(raw)
            for line in ('0x40\tx18\n', '0x7c\tW\t0x84\n', '0xffc\tC\t0x1004\n', '0x1000\tx18\n'):
                sites.write_text(line)
                with self.assertRaisesRegex(ValueError, 'header/outside'):
                    wrapper.verify_native_flat_image(root, 'tiny', original, metadata)
            sites.write_text('0x84\tx18\n')
            with self.assertRaisesRegex(ValueError, 'outside declared'):
                wrapper.verify_native_flat_image(root, 'tiny', original, metadata)

    def test_environment_has_no_inherited_switches(self):
        with mock.patch.dict(os.environ, {'D2R_PRE': '1', 'DM_RULESET': 'touch-run-v4',
                                         'PYTHONPATH': '/bad', 'DYLD_INSERT_LIBRARIES': '/bad'}):
            env = wrapper.engine_environment()
        self.assertEqual(env['DM_RULESET'], 'native')
        self.assertEqual(env['DM_PRIVATE_GATES'], '0')
        self.assertNotIn('D2R_PRE', env)
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('DYLD_INSERT_LIBRARIES', env)

    def test_real_pins_and_donor_build_rejected_without_import(self):
        self.assertEqual(wrapper.verify_engine('000102030405060708090a0b0c0d0e0f'), wrapper.ENGINE_PINS)
        # Obtain literal rule keys without copying donor IDs into test source.
        tree = __import__('ast').parse((wrapper.ENGINE_DIR / 'patch_nso.py').read_bytes())
        table = next(n.value for n in tree.body if isinstance(n, __import__('ast').Assign) and
                     any(getattr(t, 'id', '') == 'CUTS' for t in n.targets))
        with self.assertRaisesRegex(ValueError, 'donor'):
            wrapper.verify_engine(table.keys[0].value)
        with mock.patch.dict(wrapper.ENGINE_PINS, {'patch_nso.py': '0' * 64}):
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                wrapper.verify_engine('000102030405060708090a0b0c0d0e0f')

    def test_candidate_readback_source_unchanged_private_no_engine(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(wrapper.subprocess, 'run') as engine:
            root = Path(tmp); source = root / 'fixture.nro'; source.write_bytes(fixture())
            before = source.stat(); output = root / 'fresh'
            receipt = wrapper.prepare(source, frontend.sha256(source.read_bytes()), output, 'tiny')
            engine.assert_not_called()
            self.assertEqual(receipt['status'], 'container_candidate_readback_verified')
            self.assertEqual((output / 'tiny.synthetic.nso').read_bytes()[0x100:], source.read_bytes())
            self.assertEqual(wrapper.snapshot(before), wrapper.snapshot(source.stat()))
            self.assertEqual(json.loads((output / 'PREPARATION-RECEIPT.json').read_bytes()), receipt)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / 'tiny.synthetic.nso').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                wrapper.prepare(source, receipt['original']['sha256'], output, 'tiny')

    def test_wrong_hash_reserved_names_and_git_output_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'fixture.nro'; source.write_bytes(fixture())
            digest = frontend.sha256(source.read_bytes())
            for name, sha in (('tiny', '0' * 64), ('main', digest), ('../tiny', digest), ('sdk', digest)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    wrapper.prepare(source, sha, root / 'fresh', name)
                self.assertFalse((root / 'fresh').exists())
            (root / '.git').mkdir()
            with self.assertRaisesRegex(ValueError, 'outside Git'):
                wrapper.prepare(source, digest, root / 'fresh', 'tiny')

    def test_donor_outputs_unexpected_files_and_missing_outputs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for suffix in wrapper.OUTPUT_SUFFIXES:
                (root / ('tiny.' + suffix)).write_bytes(b'content' if suffix == 'patched.bin' else b'# comment\n')
            (root / 'build_src.sha256').write_text(wrapper.ENGINE_PINS['patch_nso.py'] + '  patch_nso.py\n')
            self.assertEqual(len(wrapper.verify_engine_outputs(root, 'tiny')), 8)
            for suffix in ('cuts.tsv', 'obs.tsv', 'params.tsv'):
                path = root / ('tiny.' + suffix); path.write_bytes(b'0x100\tforbidden\n')
                with self.assertRaisesRegex(ValueError, 'Donor'):
                    wrapper.verify_engine_outputs(root, 'tiny')
                path.write_bytes(b'# comment\n')
            (root / 'tiny.rules.tsv').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'Unexpected'):
                wrapper.verify_engine_outputs(root, 'tiny')


if __name__ == '__main__':
    unittest.main()
