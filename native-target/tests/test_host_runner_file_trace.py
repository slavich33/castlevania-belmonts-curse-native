"""Private trace opt-in using real tiny native RomFS open/read, no game or GPU."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_host_runner_proof as proof_fixture

runner = proof_fixture.runner


class HostRunnerFileTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proof_fixture.HostRunnerProofTests.setUpClass()
        cls.directory = Path(proof_fixture.HostRunnerProofTests.compilation.name)
        source = cls.directory/"file_trace.c"
        source.write_text(r'''
#include "romfs.c"
#include <mach/mach_time.h>
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){mach_timebase_info_data_t t;mach_timebase_info(&t);return (uint64_t)((__uint128_t)mach_absolute_time()*t.numer/t.denom);}
void runtime_boot_progress(const char *s,uint64_t n,uint64_t t){(void)s;(void)n;(void)t;}
void runtime_boot_status(const char *s,const char *d){(void)s;(void)d;}
void *runtime_fs_host_override(const char *s){(void)s;return NULL;}
void dm_guest_write_prepare(void *p,size_t n){(void)p;(void)n;}
int main(void){
    runtime_fs_init();if(mount_rom("rom",NULL,0))return 3;
    uint64_t h=0,n=0;char bytes[20];
    if(runtime_romfs_open(&h,"rom:/hello.txt",1))return 4;
    if(runtime_romfs_read(&n,h,0,bytes,sizeof bytes)||n!=sizeof bytes)return 5;
    if(memcmp(bytes,"owned fixture bytes\n",sizeof bytes))return 6;
    runtime_romfs_close(h);puts("original tiny file read; no guest/GPU");return 0;
}
''')
        cls.trace_native = cls.directory/"file-trace"
        subprocess.run(["/usr/bin/xcrun","clang","-arch","arm64","-std=gnu11","-O1",
                        "-Wall","-Wextra","-Werror","-Wno-deprecated-declarations",
                        "-DGAME_CASTLEVANIA=1","-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
                        "-I"+str(runner.ROOT/"runtime"),
                        "-I"+str(runner.ROOT/"third_party/d2r_gfx/gfx/nvn/include"),
                        "-I"+str(cls.directory),str(source),"-framework","CoreFoundation",
                        "-o",str(cls.trace_native)],check=True,capture_output=True,text=True)

    @classmethod
    def tearDownClass(cls): proof_fixture.HostRunnerProofTests.tearDownClass()

    def setUp(self):
        self.fixture = proof_fixture.HostRunnerProofTests("test_default_performs_full_C_hash_and_saves_exact_build_receipt")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.binary.write_bytes(self.trace_native.read_bytes());self.fixture.binary.chmod(0o700)
        self.fixture.build["binary_sha256"]=runner.sha(self.fixture.binary)
        self.fixture.write_json(self.fixture.work/"host-build-receipt.json",self.fixture.build)

    def args(self):
        return argparse.Namespace(work=self.fixture.work,timeout=5,app_pool=0xce000000,
                                  with_window=False,reuse_romfs_proof_from=self.fixture.prior)

    def invoke(self, trace=None):
        args=self.args()
        if trace is not None:args.trace_files=trace
        launches=[];popen=subprocess.Popen
        def capture(command,*positional,**keywords):
            if command[0]==str(self.fixture.binary):launches.append(keywords)
            return popen(command,*positional,**keywords)
        with mock.patch.object(runner.subprocess,"Popen",side_effect=capture):receipt=runner.run(args)
        self.assertEqual(receipt["exit_code"],0)
        self.assertEqual(receipt["state"],"bounded_experimental_host_run_finished")
        self.assertEqual(len(launches),1)
        self.assertEqual(receipt,json.loads((Path(receipt["run_root"])/"receipt.json").read_text()))
        return receipt,launches[0]["env"]

    def test_default_off_ignores_hostile_parent_flags_and_has_no_trace_output(self):
        with mock.patch.dict(os.environ,{"CASTLEVANIA_FS_LOG":"1","CASTLEVANIA_FS_TIMING":"1",
                                         "CASTLEVANIA_TRACE_SVC":"1","TOTK_FS_LOG":"1"}):
            receipt,env=self.invoke()
        self.assertFalse(receipt["file_trace_requested"])
        self.assertFalse(receipt["file_trace_flags_applied_to_child"])
        for key in ("CASTLEVANIA_FS_LOG","CASTLEVANIA_FS_TIMING","CASTLEVANIA_TRACE_SVC","TOTK_FS_LOG"):
            self.assertNotIn(key,env)
        self.assertNotIn("[totk-fs]",Path(receipt["log"]).read_text())

    def test_explicit_opt_in_logs_real_open_and_read_timing_only_to_private_log(self):
        receipt,env=self.invoke(True)
        self.assertTrue(receipt["file_trace_requested"])
        self.assertTrue(receipt["file_trace_flags_applied_to_child"])
        self.assertEqual(env["CASTLEVANIA_FS_LOG"],"1")
        self.assertEqual(env["CASTLEVANIA_FS_TIMING"],"1")
        self.assertNotIn("CASTLEVANIA_TRACE_SVC",env)
        self.assertNotIn("TOTK_GPU_ALLOW_SUBMIT",env)
        log=Path(receipt["log"]);text=log.read_text()
        self.assertIn("rom rom:/hello.txt",text)
        self.assertRegex(text,r"read window .*calls=1 bytes=20")
        self.assertEqual(log.stat().st_mode&0o777,0o600)
        self.assertEqual(log.parent.stat().st_mode&0o777,0o700)
        self.assertEqual(log.parent.parent.stat().st_mode&0o777,0o700)
        self.assertEqual((log.parent.parent/"receipt.json").stat().st_mode&0o777,0o600)
        self.assertNotIn("hello.txt",json.dumps(receipt))
        self.assertFalse(receipt["gpu_execution_verified"])

    def test_explicit_false_omits_flags_instead_of_setting_zero(self):
        receipt,env=self.invoke(False)
        self.assertFalse(receipt["file_trace_requested"])
        self.assertNotIn("CASTLEVANIA_FS_LOG",env)
        self.assertNotIn("CASTLEVANIA_FS_TIMING",env)

    def test_direct_api_rejects_nonbool_before_any_work_io(self):
        for value in (0,1,"true",None,[],{}):
            with self.subTest(value=value),mock.patch.object(runner.Path,"resolve") as resolve:
                args=self.args();args.trace_files=value
                with self.assertRaisesRegex(ValueError,"file trace option"):runner.run(args)
                resolve.assert_not_called()

    def test_cli_opt_in_and_invalid_explicit_values(self):
        command=[sys.executable,str(Path(runner.__file__)),"--work",str(self.fixture.work),
                 "--reuse-romfs-proof-from",str(self.fixture.prior)]
        env={"PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"}
        result=subprocess.run([*command,"--trace-files"],capture_output=True,text=True,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertTrue(receipt["file_trace_requested"])
        self.assertIn("rom rom:/hello.txt",Path(receipt["log"]).read_text())
        for option in ("--trace-files=true","--trace-files=1","--trace-files=0"):
            result=subprocess.run([*command,option],capture_output=True,text=True,env=env)
            self.assertEqual(result.returncode,2)
            self.assertIn("ignored explicit argument",result.stderr)


if __name__=="__main__":unittest.main()
