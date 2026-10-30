"""Offline policy tests and native scratch-guard negatives; no guest execution."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy
import run_loader_probe as runner

class PathPolicyTests(unittest.TestCase):
    def test_runs_are_private_and_disjoint(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = policy.create_run(Path(directory)), policy.create_run(Path(directory))
            self.assertNotEqual(first["root"], second["root"])
            for run in (first, second):
                for name in ["root", "home", "tmp", "profile", "saves", "config", "cache", "logs"]:
                    policy.ensure_owned_directory(Path(run[name]))
                    self.assertTrue(Path(run[name]).is_relative_to(Path(run["root"])))

    def test_environment_drops_other_games_and_dyld(self):
        with tempfile.TemporaryDirectory() as directory:
            run = policy.create_run(Path(directory))
            with patch.dict(os.environ, {"TOTK_PROFILE_DIR": "/foreign", "ORI_SAVE": "/foreign", "DYLD_INSERT_LIBRARIES": "/foreign"}):
                env = policy.child_environment(run)
            self.assertFalse(any(key.startswith(("TOTK_", "ORI_", "LM3_", "DM_", "DYLD_")) for key in env))
            self.assertEqual(env["HOME"], run["home"])
            self.assertEqual(env["CASTLEVANIA_SAVE_DIR"], run["saves"])

    def test_symlink_parent_rejected_without_foreign_writes(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as foreign:
            root = Path(directory)
            (root / "analysis").symlink_to(foreign, target_is_directory=True)
            with self.assertRaises(policy.PolicyError):
                policy.create_run(root)
            self.assertEqual(list(Path(foreign).iterdir()), [])

    def test_host_path_plan_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = policy.host_path_plan(Path(directory))
            self.assertIn("CastlevaniaBelmont/profile", paths["profile"])
            self.assertIn("castlevania-belmont.log", paths["log"])
            self.assertNotIn("totk", paths["display_suite"])
            self.assertEqual(list(Path(directory).iterdir()), [])

class IntegrityPolicyTests(unittest.TestCase):
    def test_profile_cannot_authorize_guest_or_other_title(self):
        original, _ = policy.read_profile()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "profiles").mkdir()
            for change in [{"mode": "boot"}, {"guest_instructions_authorized": True}, {"title_id": "010061D00DB74000"}]:
                profile = dict(original); profile.update(change)
                (root / "profiles/loader-v110.json").write_text(json.dumps(profile))
                with self.assertRaises(policy.PolicyError):
                    policy.read_profile(root)

    def test_wrong_module_bytes_rejected_before_process(self):
        profile, _ = policy.read_profile()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "main.patched.bin").write_bytes(b"wrong fixture")
            with patch.object(runner.subprocess, "run") as process:
                with self.assertRaises(policy.PolicyError): policy.verify_modules(root, profile)
                process.assert_not_called()

    def test_missing_receipt_creates_no_run_and_executes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "profiles").mkdir()
            (root / "profiles/loader-v110.json").write_bytes((policy.ROOT / "profiles/loader-v110.json").read_bytes())
            with patch.object(runner.subprocess, "run") as process:
                with self.assertRaises(OSError): runner.run_mapping(root / "missing", root)
                process.assert_not_called()
            self.assertFalse((root / "analysis").exists())

class NativeScratchGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = policy.ROOT / "build/castlevania-loader-probe"
        if not cls.binary.is_file(): raise unittest.SkipTest("loader-only binary not built")

    def test_no_run_root_refuses_before_module_access(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(self.binary), "/never-open-input"], cwd=directory,
                                    env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("run root", result.stderr)
            self.assertNotIn("open completed AOT", result.stderr)

    def test_wrong_home_refuses_with_valid_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            run = policy.create_run(Path(directory)); env = policy.child_environment(run)
            env["HOME"] = directory
            result = subprocess.run([str(self.binary), "/never-open-input"], cwd=run["root"], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside its isolated run", result.stderr)

    def test_wrong_cwd_refuses_with_valid_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            run = policy.create_run(Path(directory))
            result = subprocess.run([str(self.binary), "/never-open-input"], cwd=directory,
                                    env=policy.child_environment(run), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cwd must equal", result.stderr)

if __name__ == "__main__": unittest.main()
