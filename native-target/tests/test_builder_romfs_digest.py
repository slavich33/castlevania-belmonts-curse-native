"""Tiny offline fixtures for the builder's explicit expected-digest reuse mode.

No compiler, guest, GPU or real game input is used. Same-size image corruption is
deliberately accepted ONLY as unverified input in reuse mode; the unchanged
runtime must verify its bytes before RomFS use.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_experimental_host as builder


class RomfsDigestReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="castlevania-builder-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.work = builder.owned_work(self.root / "work")
        self.romfs = self.root / "tiny-romfs"
        self.romfs.mkdir()
        self.image = self.romfs / "romfs.bin"
        self.image.write_bytes(b"original fixture\n")
        self.manifest = {"status": "pass", "romfs_size": self.image.stat().st_size,
                         "romfs_sha256": builder.sha(self.image),
                         "files": [{"path": "fixture.txt", "offset": 0, "size": self.image.stat().st_size}]}
        self.write_manifest()
        self.resources = builder.romfs_headers(self.work, self.romfs)
        self.binary = self.work / "build/castlevania-native"
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"prior successful build fixture, never executed")
        self.receipt = {"schema": 1, "state": "actual_native_host_compiled_not_launched",
                        "title_id": builder.TITLE, "work": str(self.work),
                        "binary": str(self.binary), "binary_sha256": builder.sha(self.binary),
                        "resources": self.resources}
        self.write_receipt()

    def write_manifest(self):
        (self.romfs / "index.json").write_text(json.dumps(self.manifest))

    def write_receipt(self):
        (self.work / "host-build-receipt.json").write_text(json.dumps(self.receipt))

    def reuse(self):
        # Any unintended whole-image read fails the test, even for this tiny fixture.
        real_sha = builder.sha
        def guarded_sha(path):
            if Path(path).resolve() == self.image:
                raise AssertionError("reuse tried to read image bytes")
            return real_sha(path)
        with mock.patch.object(builder, "sha", side_effect=guarded_sha):
            return builder.romfs_headers(self.work, self.romfs, reuse_romfs_digest=True)

    def test_reuse_records_exact_prior_receipt_and_unverified_image(self):
        prior = (self.work / "host-build-receipt.json").read_bytes()
        result = self.reuse()
        proof = result["romfs_digest_provenance"]
        self.assertEqual(proof["mode"], "inherited_expected_digest")
        self.assertIs(proof["image_sha256_verified_in_this_build"], False)
        self.assertIs(proof["runtime_full_image_sha256_required_before_use"], True)
        self.assertEqual(proof["prior_host_build_receipt_sha256"], hashlib.sha256(prior).hexdigest())
        self.assertEqual(Path(proof["prior_host_build_receipt"]).read_bytes(), prior)
        self.assertEqual(result["romfs_image_sha256"], self.manifest["romfs_sha256"])
        self.assertEqual(result["romfs_image_size"], self.image.stat().st_size)

    def test_default_rehashes_and_rejects_same_size_content_change(self):
        self.image.write_bytes(b"X" * self.image.stat().st_size)
        with self.assertRaisesRegex(ValueError, "differs from its measured profile"):
            builder.romfs_headers(self.work, self.romfs)

    def test_reuse_does_not_claim_same_size_content_was_verified(self):
        self.image.write_bytes(b"X" * self.image.stat().st_size)
        result = self.reuse()
        self.assertIs(result["romfs_digest_provenance"]["image_sha256_verified_in_this_build"], False)
        self.assertEqual(result["romfs_image_sha256"], self.manifest["romfs_sha256"])

    def test_legacy_receipt_uses_exact_existing_generated_header(self):
        for key in ("romfs_image_size", "romfs_config_sha256", "romfs_digest_provenance"):
            self.receipt["resources"].pop(key)
        self.write_receipt()
        self.assertEqual(self.reuse()["romfs_image_size"], self.manifest["romfs_size"])

    def test_legacy_receipt_rejects_changed_size_even_with_matching_current_stat(self):
        for key in ("romfs_image_size", "romfs_config_sha256", "romfs_digest_provenance"):
            self.receipt["resources"].pop(key)
        self.write_receipt()
        self.image.write_bytes(self.image.read_bytes() + b"extra")
        self.manifest["romfs_size"] = self.image.stat().st_size
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "config/index"):
            self.reuse()

    def test_rejects_missing_receipt(self):
        (self.work / "host-build-receipt.json").unlink()
        with self.assertRaisesRegex(ValueError, "prior successful build receipt"):
            self.reuse()

    def test_rejects_failed_other_title_or_other_work_receipt(self):
        for field, value in (("state", "build_failed"), ("title_id", "0100000000000000"),
                             ("work", str(self.root / "other")), ("schema", 2),
                             ("binary", str(self.root / "other-binary"))):
            with self.subTest(field=field):
                previous = self.receipt[field]
                self.receipt[field] = value
                self.write_receipt()
                with self.assertRaises(ValueError):
                    self.reuse()
                self.receipt[field] = previous

    def test_rejects_prior_binary_substitution(self):
        self.binary.write_bytes(b"different prior binary")
        with self.assertRaises(ValueError):
            self.reuse()

    def test_rejects_receipt_resource_substitutions(self):
        for field, value in (("romfs_image", str(self.root / "other.bin")),
                             ("romfs_image_sha256", "0" * 64),
                             ("romfs_index_sha256", "0" * 64), ("romfs_files", 99),
                             ("romfs_image_size", 999), ("romfs_config_sha256", "0" * 64)):
            with self.subTest(field=field):
                previous = self.receipt["resources"][field]
                self.receipt["resources"][field] = value
                self.write_receipt()
                with self.assertRaises(ValueError):
                    self.reuse()
                self.receipt["resources"][field] = previous

    def test_rejects_different_canonical_image_with_identical_bytes(self):
        other = self.root / "other-romfs"
        other.mkdir()
        (other / "romfs.bin").write_bytes(self.image.read_bytes())
        (other / "index.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            builder.romfs_headers(self.work, other, reuse_romfs_digest=True)

    def test_rejects_manifest_digest_file_count_size_and_index_substitutions(self):
        for change in ("digest", "file_count", "size", "entry"):
            with self.subTest(change=change):
                original = json.loads(json.dumps(self.manifest))
                if change == "digest":
                    self.manifest["romfs_sha256"] = "0" * 64
                elif change == "file_count":
                    self.manifest["files"].append({"path": "z.txt", "offset": 0, "size": 1})
                elif change == "size":
                    self.manifest["romfs_size"] += 1
                else:
                    self.manifest["files"][0]["path"] = "other.txt"
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.reuse()
                self.manifest = original

    def test_rejects_modified_generated_config_and_index(self):
        for relative in ("generated/romfs_config.h", "extracted/v110/romfs/runtime-index.bin"):
            with self.subTest(relative=relative):
                path = self.work / relative
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaisesRegex(ValueError, "config/index"):
                    self.reuse()
                path.write_bytes(original)

    def test_rejects_untruthful_prior_provenance(self):
        self.receipt["resources"]["romfs_digest_provenance"]["mode"] = "unverified_other_source"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.reuse()

    def test_rejects_non_object_receipt_resources_or_provenance(self):
        original = self.receipt
        for malformed in ([], {**original, "resources": []},
                          {**original, "resources": {**self.resources, "romfs_digest_provenance": []}}):
            with self.subTest(malformed=malformed):
                self.receipt = malformed
                self.write_receipt()
                with self.assertRaises(ValueError):
                    self.reuse()
        self.receipt = original

    def test_reuse_can_follow_an_explicit_inherited_receipt(self):
        self.receipt["resources"] = self.reuse()
        self.write_receipt()
        self.assertEqual(self.reuse()["romfs_digest_provenance"]["mode"], "inherited_expected_digest")

    def test_regular_input_links_still_hash_the_input(self):
        source = self.root / "tiny-aot-fixture"
        source.write_bytes(b"still freshly checked")
        with self.assertRaisesRegex(ValueError, "differs from its measured profile"):
            builder.input_link(source, self.work / "aot-fixture", "0" * 64)


if __name__ == "__main__":
    unittest.main()
