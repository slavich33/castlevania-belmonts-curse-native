"""Real sealed .app + NSBundle identity using authored native fixtures, no UI/game/GPU."""
import argparse
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import unittest
from unittest import mock

import test_host_runner_proof as proof_fixture

runner = proof_fixture.runner


class HostRunnerAppBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proof_fixture.HostRunnerProofTests.setUpClass()
        cls.directory = Path(proof_fixture.HostRunnerProofTests.compilation.name)
        source = cls.directory/"bundle_identity.m"
        source.write_text(r'''
#import <Foundation/Foundation.h>
#include "romfs.c"
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){return 0;}
void runtime_boot_progress(const char *s,uint64_t n,uint64_t t){(void)s;(void)n;(void)t;}
void runtime_boot_status(const char *s,const char *d){(void)s;(void)d;}
void *runtime_fs_host_override(const char *s){(void)s;return NULL;}
void dm_guest_write_prepare(void *p,size_t n){(void)p;(void)n;}
int main(int argc,char **argv){@autoreleasepool{
    if(argc!=3||strcmp(argv[2],"boot"))return 3;
    runtime_fs_init();
    NSBundle *b=NSBundle.mainBundle;
    printf("NSBundle-id=%s\nNSBundle-path=%s\nNSBundle-executable=%s\n",
           b.bundleIdentifier.UTF8String?:"none",b.bundlePath.UTF8String,b.executablePath.UTF8String);
    return 0;
}}
''')
        cls.identity = cls.directory/"bundle-identity"
        subprocess.run(["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                        "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
                        "-DGAME_CASTLEVANIA=1", "-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
                        "-I"+str(runner.ROOT/"runtime"),
                        "-I"+str(runner.ROOT/"third_party/d2r_gfx/gfx/nvn/include"),
                        "-I"+str(cls.directory), str(source), "-framework", "Foundation",
                        "-framework", "CoreFoundation", "-o", str(cls.identity)],
                       capture_output=True, text=True, check=True)

    @classmethod
    def tearDownClass(cls): proof_fixture.HostRunnerProofTests.tearDownClass()

    def setUp(self):
        self.fixture = proof_fixture.HostRunnerProofTests("test_default_performs_full_C_hash_and_saves_exact_build_receipt")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.binary.write_bytes(self.identity.read_bytes())
        self.fixture.binary.chmod(0o700)
        self.fixture.build["binary_sha256"] = runner.sha(self.fixture.binary)
        self.fixture.build["shader_tool_sha256"] = {}
        for relative in runner.SHADER_TOOLS:
            path = self.fixture.work/"build"/relative
            path.parent.mkdir(parents=True)
            path.write_bytes(self.fixture.native.read_bytes()); path.chmod(0o700)
            self.fixture.build["shader_tool_sha256"][relative] = runner.sha(path)
        self.save_build()

    def save_build(self):
        self.fixture.write_json(self.fixture.work/"host-build-receipt.json", self.fixture.build)

    def args(self, **options):
        args = argparse.Namespace(work=self.fixture.work, timeout=5, app_pool=0xce000000,
                                  with_window=True, app_bundle=True,
                                  reuse_romfs_proof_from=self.fixture.prior)
        for key, value in options.items(): setattr(args, key, value)
        return args

    def invoke(self, **options):
        signs, launches = [], []
        original_run, original_popen = subprocess.run, subprocess.Popen
        def capture_run(command, *positional, **keywords):
            if command[0] == "/usr/bin/codesign" and "--sign" in command: signs.append(command)
            return original_run(command, *positional, **keywords)
        def capture_popen(command, *positional, **keywords):
            if str(command[0]).endswith("/Contents/MacOS/castlevania-native"):
                launches.append((command, keywords))
            return original_popen(command, *positional, **keywords)
        with mock.patch.object(runner.subprocess, "run", side_effect=capture_run), \
                mock.patch.object(runner.subprocess, "Popen", side_effect=capture_popen):
            result = runner.run(self.args(**options))
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["state"], "bounded_experimental_host_run_finished")
        self.assertEqual(len(launches), 1)
        return result, signs, launches[0]

    def test_actual_bundle_identity_seal_and_isolated_native_launch(self):
        result, signs, (command, launch) = self.invoke()
        root = Path(result["run_root"]); app = root/runner.APP_NAME
        executable = app/"Contents/MacOS/castlevania-native"
        self.assertEqual(command, [str(executable), str(root/"rewritten/v110"), "boot"])
        self.assertEqual(launch["cwd"], root)
        self.assertTrue(launch["start_new_session"])
        self.assertEqual(launch["env"]["HOME"], str(root/"home"))
        self.assertEqual(launch["env"]["CASTLEVANIA_SAVE_DIR"], str(root/"saves"))
        self.assertNotIn("TOTK_GPU_ALLOW_SUBMIT", launch["env"])
        log = Path(result["log"]).read_text()
        self.assertIn("NSBundle-id="+runner.APP_ID, log)
        self.assertIn("NSBundle-path="+str(app), log)
        self.assertIn("NSBundle-executable="+str(executable), log)
        runner.verify_code(app); runner.verify_code(executable)
        info_path = app/"Contents/Info.plist"
        self.assertEqual(info_path.stat().st_mode & 0o777, 0o600)
        info = plistlib.loads(info_path.read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], runner.APP_ID)
        self.assertEqual(info["CFBundlePackageType"], "APPL")
        self.assertEqual(info["CFBundleExecutable"], executable.name)
        self.assertNotIn("LSEnvironment", info)
        self.assertEqual(app.stat().st_mode & 0o777, 0o700)
        self.assertFalse(any(path.is_symlink() for path in app.rglob("*")))
        allowed_signs = {str(app)} | {str(app/"Contents/build"/r) for r in runner.SHADER_TOOLS}
        self.assertEqual({sign[-1] for sign in signs}, allowed_signs)
        self.assertTrue(all(sign[sign.index("--sign")+1] == "-" for sign in signs))
        self.assertFalse(result["gpu_execution_verified"])
        self.assertFalse(result["first_frame_verified"])

    def test_receipt_binds_original_copy_derivative_tools_and_exact_build_receipt(self):
        result, _, _ = self.invoke()
        root = Path(result["run_root"]); app = root/runner.APP_NAME
        bundled = result["app_bundle"]
        self.assertEqual(json.loads((root/"app-bundle-receipt.json").read_text()), bundled)
        self.assertEqual(json.loads((root/"receipt.json").read_text()), result)
        self.assertEqual(result["binary_sha256"], self.fixture.build["binary_sha256"])
        self.assertEqual(runner.sha(self.fixture.binary), result["binary_sha256"])
        self.assertEqual(result["launched_binary_sha256"], runner.sha(Path(result["command"][0])))
        self.assertNotEqual(result["launched_binary_sha256"], result["binary_sha256"])
        self.assertEqual((root/"compiled-build-receipt.json").read_bytes(),
                         (self.fixture.work/"host-build-receipt.json").read_bytes())
        for relative, entry in bundled["code_copies"].items():
            self.assertEqual(entry["source_sha256"], entry["pre_sign_copy_sha256"])
            self.assertEqual(runner.sha(Path(entry["source"])), entry["source_sha256"])
            self.assertEqual(runner.sha(app/relative), entry["signed_copy_sha256"])
            runner.verify_code(app/relative)
        self.assertEqual(runner.sha(app/"Contents/Info.plist"), bundled["info_plist_sha256"])
        self.assertEqual(runner.sha(app/"Contents/_CodeSignature/CodeResources"), bundled["code_resources_sha256"])
        self.assertFalse(bundled["standalone_installable_game"])
        self.assertFalse(bundled["UI_inspection_verified"])

    def test_bundle_prior_cannot_supply_proof_but_original_baseline_still_can(self):
        result, _, _ = self.invoke()
        self.assertFalse(result["proof_reuse_eligible"])
        with self.assertRaisesRegex(ValueError, "bundled prior"):
            self.fixture.reuse(Path(result["run_root"]))
        self.assertTrue(self.fixture.reuse()["copied_byte_exact"])

    def test_app_option_rejects_bad_types_or_missing_window_before_io(self):
        for options in ({"app_bundle":True,"with_window":False}, {"app_bundle":True,"with_window":"yes"},
                        {"app_bundle":"true"}, {"app_bundle":1}, {"app_bundle":None}):
            with self.subTest(options=options), mock.patch.object(runner.Path,"resolve") as resolve:
                with self.assertRaisesRegex(ValueError,"app bundle|requires --with-window"):
                    runner.run(self.args(**options))
                resolve.assert_not_called()
        result = subprocess.run([sys.executable,str(Path(runner.__file__)),"--work",str(self.fixture.work),
                                 "--app-bundle"],capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertIn("requires --with-window",result.stderr)

    def test_unrequested_app_keeps_original_command_and_no_bundle_files(self):
        result = runner.run(self.args(app_bundle=False,with_window=False))
        self.assertEqual(result["command"][0],str(self.fixture.binary))
        self.assertEqual(result["launched_binary_sha256"],result["binary_sha256"])
        self.assertEqual(result["app_bundle"],{"requested":False})
        self.assertFalse((Path(result["run_root"])/runner.APP_NAME).exists())

    def test_wrong_missing_or_extra_shader_tool_metadata_rejected(self):
        original = dict(self.fixture.build["shader_tool_sha256"])
        for tools in ({}, {**original,"unexpected/tool":"0"*64},
                      {**original,runner.SHADER_TOOLS[0]:"0"*64}):
            with self.subTest(tools=list(tools)):
                self.fixture.build["shader_tool_sha256"] = tools; self.save_build()
                with self.assertRaisesRegex(ValueError,"shader tools|readback differs"):
                    runner.run(self.args())

    def test_source_helper_symlink_is_rejected(self):
        path = self.fixture.work/"build"/runner.SHADER_TOOLS[0]
        original = path.with_name("original-helper"); path.rename(original); path.symlink_to(original)
        with self.assertRaisesRegex(ValueError,"source path/digest"):
            runner.run(self.args())

    def test_entitlement_bearing_build_is_explicitly_rejected_without_dropping_it(self):
        entitlements = self.fixture.base/"test-entitlements.plist"
        entitlements.write_bytes(plistlib.dumps({"com.apple.security.cs.allow-jit":True}))
        subprocess.run(["/usr/bin/codesign","--force","--sign","-","--timestamp=none",
                        "--entitlements",str(entitlements),str(self.fixture.binary)],
                       check=True,capture_output=True)
        original_sha = runner.sha(self.fixture.binary)
        self.fixture.build["binary_sha256"] = original_sha; self.save_build()
        with self.assertRaisesRegex(ValueError,"entitlement-free"):
            runner.run(self.args())
        self.assertEqual(runner.sha(self.fixture.binary),original_sha)

    def test_full_bundle_seal_rejects_later_plist_tampering(self):
        result, _, _ = self.invoke()
        app = Path(result["app_bundle"]["bundle"])
        path = app/"Contents/Info.plist"
        info = plistlib.loads(path.read_bytes()); info["CFBundleName"] = "tampered"
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaises(subprocess.CalledProcessError): runner.verify_code(app)


if __name__ == "__main__": unittest.main()
