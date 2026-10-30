"""Runner GPU opt-in environment/receipts; only the existing tiny C RomFS fixture runs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_host_runner_proof as proof_fixture

runner = proof_fixture.runner


class HostRunnerGpuPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): proof_fixture.HostRunnerProofTests.setUpClass()

    @classmethod
    def tearDownClass(cls): proof_fixture.HostRunnerProofTests.tearDownClass()

    def setUp(self):
        self.fixture = proof_fixture.HostRunnerProofTests("test_default_performs_full_C_hash_and_saves_exact_build_receipt")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def invoke(self, **options):
        args = argparse.Namespace(work=self.fixture.work, timeout=5, app_pool=0xce000000,
                                  with_window=False, reuse_romfs_proof_from=self.fixture.prior)
        for name, value in options.items(): setattr(args, name, value)
        environments = []
        original_popen = subprocess.Popen
        def capture(command, *positional, **keywords):
            if command[0] == str(self.fixture.binary): environments.append(dict(keywords["env"]))
            return original_popen(command, *positional, **keywords)
        with mock.patch.object(runner.subprocess, "Popen", side_effect=capture):
            result = runner.run(args)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(len(environments), 1)
        self.assertEqual(result["runtime_romfs_verification_mode"], "reused_previous_C_full_hash_record")
        self.assertFalse(result["gpu_execution_verified"])
        self.assertFalse(result["first_frame_verified"])
        self.assertFalse(result["gpu_budget_is_measured_title_contract"])
        return result, environments[0]

    def test_old_api_namespace_defaults_gpu_off_even_with_hostile_parent_env(self):
        with mock.patch.dict(os.environ, {"TOTK_GPU_ALLOW_SUBMIT":"1","TOTK_GPU_BUDGET_MB":"99999",
                                         "TOTK_GPU_KEEPALIVE":"1","TOTK_PROBE_GPU":"1"}):
            receipt, env = self.invoke()
        self.assertFalse(receipt["gpu_submit_requested"])
        self.assertEqual(receipt["diagnostic_gpu_budget_mib"], 2048)
        self.assertFalse(receipt["gpu_budget_applied_to_child"])
        for key in ("TOTK_GPU_ALLOW_SUBMIT","TOTK_GPU_BUDGET_MB","TOTK_GPU_KEEPALIVE","TOTK_PROBE_GPU"):
            self.assertNotIn(key, env)
        self.assertEqual(env["TOTK_HEADLESS"], "1")

    def test_window_alone_does_not_enable_gpu(self):
        receipt, env = self.invoke(with_window=True)
        self.assertFalse(receipt["gpu_submit_requested"])
        self.assertNotIn("TOTK_HEADLESS", env)
        self.assertNotIn("TOTK_GPU_ALLOW_SUBMIT", env)

    def test_explicit_window_gpu_opt_in_sets_bounded_budget_and_disables_keepalive(self):
        receipt, env = self.invoke(with_window=True, allow_gpu_submit=True)
        self.assertTrue(receipt["gpu_submit_requested"])
        self.assertTrue(receipt["gpu_budget_applied_to_child"])
        self.assertTrue(receipt["gpu_keepalive_disabled_by_runner"])
        self.assertEqual(env["TOTK_GPU_ALLOW_SUBMIT"], "1")
        self.assertEqual(env["TOTK_GPU_BUDGET_MB"], "2048")
        self.assertEqual(env["TOTK_GPU_KEEPALIVE"], "0")
        self.assertNotIn("TOTK_PROBE_GPU", env)
        self.assertNotIn("TOTK_HEADLESS", env)
        self.assertEqual(env["CASTLEVANIA_PROFILE_DIR"], str(Path(receipt["run_root"])/"profile"))
        self.assertEqual(list((Path(receipt["run_root"])/"saves").iterdir()), [])

    def test_valid_budget_boundaries_are_reported_and_applied_exactly(self):
        for budget in (256, 4096):
            with self.subTest(budget=budget):
                receipt, env = self.invoke(with_window=True, allow_gpu_submit=True, gpu_budget_mib=budget)
                self.assertEqual(receipt["diagnostic_gpu_budget_mib"], budget)
                self.assertEqual(env["TOTK_GPU_BUDGET_MB"], str(budget))

    def test_custom_budget_without_opt_in_remains_unapplied(self):
        receipt, env = self.invoke(gpu_budget_mib=1024)
        self.assertEqual(receipt["diagnostic_gpu_budget_mib"], 1024)
        self.assertFalse(receipt["gpu_budget_applied_to_child"])
        self.assertNotIn("TOTK_GPU_BUDGET_MB", env)

    def test_direct_api_rejects_invalid_combinations_before_any_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            absent = Path(temporary)/"must-not-be-created"
            variants = [{"allow_gpu_submit":True,"with_window":False},
                        {"allow_gpu_submit":True,"with_window":"true"},
                        {"allow_gpu_submit":"true","with_window":True}]
            variants += [{"gpu_budget_mib":b} for b in (0,255,4097,-1,256.5,"2048",None)]
            for options in variants:
                with self.subTest(options=options):
                    args=argparse.Namespace(work=absent,with_window=False)
                    for key,value in options.items():setattr(args,key,value)
                    with self.assertRaisesRegex(ValueError,"GPU|requires"):runner.run(args)
                    self.assertFalse(absent.exists())

    def test_cli_rejects_headless_opt_in_and_out_of_range_budgets(self):
        for options in (["--allow-gpu-submit"],["--gpu-budget-mib","255"],
                        ["--with-window","--allow-gpu-submit","--gpu-budget-mib","4097"]):
            with self.subTest(options=options):
                result=subprocess.run([sys.executable,str(Path(runner.__file__)),"--work",str(self.fixture.work),*options],
                                      capture_output=True,text=True,env={"PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"})
                self.assertEqual(result.returncode,2)
                self.assertRegex(result.stderr,"requires --with-window|GPU diagnostic budget")


if __name__=="__main__":unittest.main()
