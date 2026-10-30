"""Actual child-only RLIMIT_FSIZE plus runner binding; no game/GPU/cache use."""
import argparse
import functools
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_host_runner_proof as proof_fixture

runner = proof_fixture.runner


class NativeFileLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-file-limit-native-")
        cls.directory = Path(cls.temporary.name)
        source = cls.directory/"sparse_growth.c"
        source.write_text(r'''
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc!=2)return 2;
    signal(SIGXFSZ,SIG_DFL);
    struct rlimit f,c;
    if(getrlimit(RLIMIT_FSIZE,&f)||getrlimit(RLIMIT_CORE,&c))return 3;
    printf("fsize=%llu,%llu core=%llu,%llu\n",(unsigned long long)f.rlim_cur,
           (unsigned long long)f.rlim_max,(unsigned long long)c.rlim_cur,(unsigned long long)c.rlim_max);
    fflush(stdout);
    int fd=open(argv[1],O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0)return 4;
    if(lseek(fd,((off_t)65<<20)-1,SEEK_SET)<0)return 5;
    if(write(fd,"x",1)!=1)return 6;
    struct stat st;if(fstat(fd,&st))return 7;
    printf("size=%llu\n",(unsigned long long)st.st_size);
    return close(fd)?8:0;
}
''')
        cls.binary = cls.directory/"sparse-growth"
        subprocess.run(["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                        "-Wall", "-Wextra", "-Werror", str(source), "-o", str(cls.binary)],
                       capture_output=True, text=True, check=True)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def invoke(self, limit=None):
        before = (resource.getrlimit(resource.RLIMIT_FSIZE), resource.getrlimit(resource.RLIMIT_CORE))
        with tempfile.TemporaryDirectory(prefix="castlevania-file-limit-run-") as temporary:
            target = Path(temporary)/"owned-sparse-fixture"
            preexec = runner.child_limits if limit is None else functools.partial(runner.child_limits, limit)
            result = subprocess.run([str(self.binary), str(target)], capture_output=True, text=True,
                                    preexec_fn=preexec, timeout=5, env={"PATH":"/usr/bin:/bin"})
            info = target.stat()
            self.assertLess(info.st_blocks * 512, 1 << 20)
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(info.st_uid, os.getuid())
        after = (resource.getrlimit(resource.RLIMIT_FSIZE), resource.getrlimit(resource.RLIMIT_CORE))
        self.assertEqual(after, before)
        return result, info

    def test_default64_mib_really_terminates_growth_with_sigxfsz(self):
        result, info = self.invoke()
        self.assertEqual(result.returncode, -signal.SIGXFSZ)
        self.assertIn(f"fsize={64<<20},{64<<20} core=0,0", result.stdout)
        self.assertLessEqual(info.st_size, 64 << 20)
        self.assertNotIn("size=", result.stdout.splitlines()[-1].removeprefix("fsize="))

    def test_explicit128_mib_allows65_mib_sparse_growth_without_changing_parent(self):
        result, info = self.invoke(128)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(info.st_size, 65 << 20)
        self.assertIn(f"fsize={128<<20},{128<<20} core=0,0", result.stdout)
        self.assertIn(f"size={65<<20}", result.stdout)


class RunnerFileLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): proof_fixture.HostRunnerProofTests.setUpClass()

    @classmethod
    def tearDownClass(cls): proof_fixture.HostRunnerProofTests.tearDownClass()

    def setUp(self):
        self.fixture = proof_fixture.HostRunnerProofTests("test_default_performs_full_C_hash_and_saves_exact_build_receipt")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def invoke(self, limit=None):
        args = argparse.Namespace(work=self.fixture.work, timeout=5, app_pool=0xce000000,
                                  with_window=False, reuse_romfs_proof_from=self.fixture.prior)
        if limit is not None: args.file_size_limit_mib = limit
        launches = []
        popen = subprocess.Popen
        def capture(command, *positional, **keywords):
            if command[0] == str(self.fixture.binary): launches.append(keywords)
            return popen(command, *positional, **keywords)
        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        with mock.patch.object(runner.subprocess, "Popen", side_effect=capture):
            receipt = runner.run(args)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before)
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["state"], "bounded_experimental_host_run_finished")
        self.assertEqual(receipt, json.loads((Path(receipt["run_root"])/"receipt.json").read_text()))
        self.assertEqual(len(launches), 1)
        return receipt, launches[0]

    def test_legacy_namespace_keeps64_default_and_binds_child_preexec_receipt(self):
        receipt, launch = self.invoke()
        self.assertEqual(receipt["diagnostic_file_size_limit_mib"], 64)
        self.assertEqual(receipt["child_rlimit_fsize_bytes"], 64 << 20)
        self.assertFalse(receipt["file_size_limit_is_measured_title_contract"])
        self.assertIs(launch["preexec_fn"].func, runner.child_limits)
        self.assertEqual(launch["preexec_fn"].args, (64,))
        self.assertEqual(receipt["timeout_seconds"], 5)
        self.assertFalse(receipt["gpu_submit_requested"])
        self.assertNotIn("TOTK_GPU_ALLOW_SUBMIT", launch["env"])
        self.assertEqual(receipt["runtime_romfs_verification_mode"], "reused_previous_C_full_hash_record")

    def test_explicit_limits_and_inclusive_boundaries_bind_exactly(self):
        for limit in (64, 128, 1024, 2048):
            with self.subTest(limit=limit):
                receipt, launch = self.invoke(limit)
                self.assertEqual(receipt["diagnostic_file_size_limit_mib"], limit)
                self.assertEqual(receipt["child_rlimit_fsize_bytes"], limit << 20)
                self.assertEqual(launch["preexec_fn"].args, (limit,))

    def test_direct_api_rejects_bool_noninteger_and_out_of_range_before_io(self):
        for limit in (True, False, 0, 63, 2049, -1, 64.0, "1024", None):
            with self.subTest(limit=limit), mock.patch.object(runner.Path, "resolve") as resolve:
                args = argparse.Namespace(work=Path("absent"), file_size_limit_mib=limit)
                with self.assertRaisesRegex(ValueError, "file size limit"):
                    runner.run(args)
                resolve.assert_not_called()

    def test_cli_rejects_invalid_limits_before_work_io(self):
        for limit in ("63", "2049", "true", "64.0", "-1"):
            with self.subTest(limit=limit):
                result = subprocess.run([sys.executable, str(Path(runner.__file__)), "--work",
                                         str(self.fixture.base/"absent"), "--file-size-limit-mib", limit],
                                        capture_output=True, text=True,
                                        env={"PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"})
                self.assertEqual(result.returncode, 2)
                self.assertRegex(result.stderr, "file size limit|invalid int value")


if __name__ == "__main__": unittest.main()
