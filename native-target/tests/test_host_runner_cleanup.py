"""Owned-group cleanup evidence; tiny native RomFS fixture only, no game/GPU."""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest import mock

import test_host_runner_proof as proof_fixture

runner = proof_fixture.runner


class FakeProcess:
    pid = 987654
    returncode = 23

    def poll(self):
        return self.returncode


class OwnedGroupCleanupTests(unittest.TestCase):
    def invoke(self, observations, signals=(), process=None):
        process = process or FakeProcess()
        with mock.patch.object(runner, "group_members", side_effect=observations) as inspect, \
                mock.patch.object(runner.os, "killpg", side_effect=signals or None) as kill:
            report = runner.cleanup_owned_group(process, phase="post_wait", term_seconds=0, kill_seconds=0)
        self.assertTrue(all(call.args == (process.pid,) for call in inspect.call_args_list))
        self.assertTrue(all(call.args[0] == process.pid for call in kill.call_args_list))
        return report, kill

    def test_successful_empty_snapshot_skips_every_signal(self):
        report, kill = self.invoke([[]])
        self.assertTrue(report["complete"])
        self.assertEqual(report["remaining_pids"], [])
        kill.assert_not_called()

    def test_term_permission_error_requires_independent_empty_snapshot(self):
        report, kill = self.invoke([[987654], []], [PermissionError(errno.EPERM, "denied")])
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["snapshots"]), 2)
        self.assertEqual(report["signals"][0]["error"]["errno"], errno.EPERM)
        self.assertFalse(report["signals"][0]["sent"])
        self.assertFalse(report["forced_kill_sent"])
        self.assertEqual(kill.call_count, 1)

    def test_permission_denial_with_members_is_incomplete_without_escalation(self):
        report, kill = self.invoke([[987654], [987654]], [PermissionError(errno.EPERM, "denied")])
        self.assertFalse(report["complete"])
        self.assertEqual(report["remaining_pids"], [987654])
        self.assertEqual(report["reason"], "group_members_remain")
        self.assertEqual(kill.call_count, 1)
        self.assertEqual(kill.call_args.args[1], signal.SIGTERM)

    def test_permission_error_can_drain_during_bounded_poll(self):
        with mock.patch.object(runner, "group_members", side_effect=[[987654], [987654], []]), \
                mock.patch.object(runner.os, "killpg", side_effect=PermissionError(errno.EPERM, "denied")), \
                mock.patch.object(runner.time, "sleep"):
            report = runner.cleanup_owned_group(FakeProcess(), phase="timeout", term_seconds=1)
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["snapshots"]), 3)
        self.assertEqual(len(report["signals"]), 1)

    def test_initial_inspection_failure_is_unknown_and_never_signals(self):
        for error in (PermissionError(errno.EPERM, "denied"), ValueError("malformed ps"),
                      subprocess.TimeoutExpired("ps", 2)):
            with self.subTest(error=type(error).__name__):
                report, kill = self.invoke([error])
                self.assertFalse(report["complete"])
                self.assertIsNone(report["remaining_pids"])
                self.assertFalse(report["snapshots"][0]["inspection_ok"])
                kill.assert_not_called()

    def test_inspection_failure_after_signal_does_not_become_empty(self):
        report, kill = self.invoke([[987654], OSError(errno.EIO, "ps failure")])
        self.assertFalse(report["complete"])
        self.assertIsNone(report["remaining_pids"])
        self.assertEqual(kill.call_count, 1)

    def test_term_esrch_race_requires_successful_empty_reinspection(self):
        report, _ = self.invoke([[987654], []], [ProcessLookupError(errno.ESRCH, "gone")])
        self.assertTrue(report["complete"])
        self.assertEqual(report["signals"][0]["error"]["errno"], errno.ESRCH)

    def test_successful_term_then_kill_esrch_preserves_actual_exit_status(self):
        process = FakeProcess()
        report, kill = self.invoke([[987654], [987654], []],
                                   [None, ProcessLookupError(errno.ESRCH, "gone")], process)
        self.assertTrue(report["complete"])
        self.assertEqual(process.returncode, 23)
        self.assertFalse(report["forced_kill_sent"])
        self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_forced_kill_means_signal_was_successfully_sent(self):
        report, _ = self.invoke([[987654], [987654], []])
        self.assertTrue(report["complete"])
        self.assertTrue(report["forced_kill_sent"])

    def test_kill_permission_denied_with_members_is_incomplete(self):
        report, _ = self.invoke([[987654], [987654], [987654]],
                                [None, PermissionError(errno.EPERM, "denied")])
        self.assertFalse(report["complete"])
        self.assertFalse(report["forced_kill_sent"])
        self.assertEqual(report["signals"][-1]["signal"], "SIGKILL")

    def test_empty_group_does_not_fabricate_exit_for_unreaped_host(self):
        process = FakeProcess(); process.returncode = None
        report, _ = self.invoke([[]], process=process)
        self.assertFalse(report["complete"])
        self.assertFalse(report["host_wait_completed"])
        self.assertIsNone(process.returncode)

    def test_invalid_group_and_runner_group_never_inspected_or_signalled(self):
        for group in (0, 1, -4, os.getpgrp(), "1"):
            with self.subTest(group=group):
                process = FakeProcess(); process.pid = group
                report, kill = self.invoke([], process=process)
                self.assertFalse(report["complete"])
                kill.assert_not_called()

    def test_group_member_ps_call_is_bounded_and_malformed_rows_fail(self):
        with mock.patch.object(runner.subprocess, "check_output", return_value="12 6\n13 7\n14 6\n") as ps:
            self.assertEqual(runner.group_members(6), [12, 14])
        ps.assert_called_once_with(["/bin/ps", "-axo", "pid=,pgid="], text=True, timeout=2)
        with mock.patch.object(runner.subprocess, "check_output", return_value="12 invalid\n"):
            with self.assertRaises(ValueError): runner.group_members(6)

    def test_real_host_process_timeout_termination_and_reap(self):
        # An original Python sleeper, not guest code. The helper must really send
        # TERM to the newly owned session and collect the actual wait status.
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                   start_new_session=True, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaises(subprocess.TimeoutExpired): process.wait(timeout=0.05)
            report = runner.cleanup_owned_group(process, phase="timeout")
            self.assertTrue(report["complete"])
            self.assertEqual(process.returncode, -signal.SIGTERM)
            self.assertEqual(report["remaining_pids"], [])
            self.assertFalse(report["forced_kill_sent"])
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3)


class RunnerCleanupReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): proof_fixture.HostRunnerProofTests.setUpClass()

    @classmethod
    def tearDownClass(cls): proof_fixture.HostRunnerProofTests.tearDownClass()

    def setUp(self):
        self.fixture = proof_fixture.HostRunnerProofTests("test_default_performs_full_C_hash_and_saves_exact_build_receipt")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def invoke(self, observations, signal_error=None):
        args = argparse.Namespace(work=self.fixture.work, timeout=5, app_pool=0xce000000,
                                  with_window=False, reuse_romfs_proof_from=self.fixture.prior)
        cleanup = runner.cleanup_owned_group
        def quick(process, *, phase):
            return cleanup(process, phase=phase, term_seconds=0, kill_seconds=0)
        with mock.patch.object(runner, "group_members", side_effect=observations), \
                mock.patch.object(runner.os, "killpg", side_effect=signal_error) as kill, \
                mock.patch.object(runner, "cleanup_owned_group", side_effect=quick):
            receipt = runner.run(args)
        saved = json.loads((Path(receipt["run_root"])/"receipt.json").read_text())
        self.assertEqual(saved, receipt)
        return receipt, kill

    def test_actual_tiny_C_exit_and_log_preserved_after_eperm_then_empty(self):
        receipt, kill = self.invoke([[987654], []], PermissionError(errno.EPERM, "denied"))
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_finished")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["log_sha256"], runner.sha(Path(receipt["log"])))
        self.assertTrue(receipt["proof_reuse_eligible"])
        self.assertEqual(receipt["runtime_romfs_verification_mode"], "reused_previous_C_full_hash_record")
        self.assertFalse(receipt["forced_kill_of_owned_group"])
        self.assertEqual(kill.call_count, 1)

    def test_partial_receipt_retains_real_exit_log_and_rejects_proof_reuse(self):
        receipt, kill = self.invoke([[987654], [987654]], PermissionError(errno.EPERM, "denied"))
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_incomplete")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["log_sha256"], runner.sha(Path(receipt["log"])))
        self.assertFalse(receipt["proof_reuse_eligible"])
        self.assertEqual(receipt["remaining_owned_process_group_pids"], [987654])
        self.assertEqual(kill.call_count, 1)
        with self.assertRaisesRegex(ValueError, "finished run"):
            self.fixture.reuse(Path(receipt["run_root"]))

    def test_inspection_failure_receipt_preserves_unknown_distinct_from_empty(self):
        receipt, kill = self.invoke([OSError(errno.EIO, "ps failed")])
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_incomplete")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertIsNone(receipt["remaining_owned_process_group_pids"])
        self.assertIsNotNone(receipt["log_sha256"])
        kill.assert_not_called()

    def test_partial_status_cannot_be_relabelled_finished_to_reuse_proof(self):
        receipt, _ = self.invoke([OSError(errno.EIO, "ps failed")])
        receipt["state"] = "bounded_experimental_host_run_finished"
        receipt["remaining_owned_process_group_pids"] = []
        self.fixture.write_json(Path(receipt["run_root"])/"receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "finished run"):
            self.fixture.reuse(Path(receipt["run_root"]))

    def test_complete_cleanup_preserves_actual_C_failure_without_proof_credit(self):
        self.fixture.data.write_bytes(b"X" * len(self.fixture.image))
        receipt, _ = self.invoke([[987654], []], PermissionError(errno.EPERM, "denied"))
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_finished")
        self.assertEqual(receipt["exit_code"], 2)
        self.assertIn("RomFS integrity mismatch", Path(receipt["log"]).read_text())
        self.assertFalse(receipt["proof_reuse_eligible"])
        self.assertEqual(receipt["runtime_romfs_verification_mode"], "not_reached_or_incomplete")

    def test_unstable_log_read_still_saves_partial_cleanup_evidence(self):
        original = runner.owned_bytes
        def read(path, **options):
            if Path(path).name == "native-host.log" and Path(path).parent.parent != self.fixture.prior:
                raise ValueError("log changed while reading")
            return original(path, **options)
        with mock.patch.object(runner, "owned_bytes", side_effect=read):
            receipt, _ = self.invoke([[]])
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_incomplete")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertTrue(receipt["owned_process_group_cleanup"]["complete"])
        self.assertIsNone(receipt["log_sha256"])
        self.assertIsNone(receipt["log_bytes"])
        self.assertEqual(receipt["log_snapshot_error"]["type"], "ValueError")
        self.assertFalse(receipt["proof_reuse_eligible"])


if __name__ == "__main__": unittest.main()
