"""Native guard and tiny read-only RomFS fixture tests; no guest/GPU code."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy

class NativeHostPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-policy-tests-")
        cls.work = Path(cls.temporary.name).resolve()
        cls.image = b"owned fixture bytes\n"
        name = b"hello.txt\0"
        cls.index = (struct.pack("<8sQQ", b"TOTKRFS1", 1, 48) +
                     struct.pack("<QQII", 0, len(cls.image), 0, len(name)) + name)
        (cls.work / "romfs_config.h").write_text(
            f'#define ROMFS_IMAGE_SIZE {len(cls.image)}ULL\n'
            f'#define ROMFS_IMAGE_SHA256 "{hashlib.sha256(cls.image).hexdigest()}"\n'
            f'#define ROMFS_INDEX_SHA256 "{hashlib.sha256(cls.index).hexdigest()}"\n')
        source = cls.work / "fixture.c"
        source.write_text(r'''
#include "romfs.c"
#include "game_slot.c"
_Noreturn void runtime_fail(const char *message) {fprintf(stderr,"FAIL: %s\n",message);exit(2);}
uint64_t runtime_now_ns(void) {return 0;}
void runtime_boot_progress(const char *s,uint64_t n,uint64_t t) {(void)s;(void)n;(void)t;}
void runtime_boot_status(const char *s,const char *d) {(void)s;(void)d;}
void *runtime_fs_host_override(const char *s) {(void)s;return NULL;}
void dm_guest_write_prepare(void *p,size_t n) {(void)p;(void)n;} /* fixture buffer is ordinary host RAM */
int main(int argc,char **argv) {
 castlevania_check_host_scratch();
 if(argc>1&&!strncmp(argv[1],"slot",4)){
  runtime_game_slot_acquire("boot");puts("slot-held");fflush(stdout);
  if(!strcmp(argv[1],"slot-hold"))getchar();
 }else if(argc>1&&!strcmp(argv[1],"mount")){
  uint64_t h=0,n=0;char bytes[128]={0};
  if(mount_rom("rom",NULL,0)||runtime_romfs_open(&h,"rom:/hello.txt",1)||
     runtime_romfs_read(&n,h,0,bytes,sizeof bytes))return 3;
  fwrite(bytes,1,n,stdout);runtime_romfs_close(h);
 }else puts("guard-only accepted; no boot executed");
 return 0;
}
''')
        cls.binary = cls.work / "guard-fixture"
        cls.disabled = cls.work / "guard-disabled-fixture"
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                  "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1", "-I"+str(policy.ROOT / "runtime"),
                  "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), "-I"+str(cls.work), str(source), "-framework", "CoreFoundation"]
        for option, output in [("1", cls.binary), (None, cls.disabled)]:
            defines = ["-DCASTLEVANIA_DIAGNOSTIC_BOOT="+option] if option else []
            result = subprocess.run(common+defines+["-o", str(output)], capture_output=True, text=True)
            if result.returncode: raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def make_run(self, parent):
        run = policy.create_run(parent)
        root = Path(run["root"])
        (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
        log = root / "logs/native-host.log"
        log.touch(mode=0o600)
        env = policy.child_environment(run)
        env["CASTLEVANIA_LOG_FILE"] = str(log)
        return run, env, log

    def invoke(self, run, env, log, *args, binary=None, cwd=None, redirect=True):
        with log.open("ab") as stream:
            result = subprocess.run([str(binary or self.binary), *args], cwd=cwd or run["root"], env=env,
                                    stdout=subprocess.PIPE, stderr=stream if redirect else subprocess.PIPE)
        return result, log.read_text() if redirect else result.stderr.decode()

    def test_valid_scratch_guard_does_not_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(Path(directory))
            result, _ = self.invoke(run, env, log)
            self.assertEqual(result.returncode, 0)
            self.assertIn(b"no boot executed", result.stdout)

    def test_default_compile_option_stops_before_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(Path(directory))
            result, text = self.invoke(run, env, log, "mount", binary=self.disabled)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("disabled at compile time", text)
            self.assertFalse((Path(run["root"]) / "extracted").exists())

    def test_loader_marker_cannot_authorize_host(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(Path(directory)); root = Path(run["root"])
            (root / ".castlevania-host-run").rename(root / ".castlevania-loader-run")
            result, text = self.invoke(run, env, log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("marker missing", text)

    def test_profile_cannot_escape_run(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as foreign:
            run, env, log = self.make_run(Path(directory)); env["CASTLEVANIA_PROFILE_DIR"] = foreign
            result, text = self.invoke(run, env, log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside its isolated run", text)
            self.assertEqual(list(Path(foreign).iterdir()), [])

    def test_stderr_and_log_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(Path(directory))
            result, text = self.invoke(run, env, log, redirect=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("host stderr", text)
            other = log.with_name("other.log"); log.rename(other); log.symlink_to(other)
            result, text = self.invoke(run, env, log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("host stderr", text)

    def test_romfs_fixture_reads_original_and_only_writes_scratch_cache(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as foreign:
            run, env, log = self.make_run(Path(directory)); root = Path(run["root"])
            data = root / "extracted/v110/romfs"; data.mkdir(parents=True)
            for name, content in [("romfs.bin", self.image), ("runtime-index.bin", self.index)]:
                (data / name).write_bytes(content); (data / name).chmod(0o400)
            before = {p.name: policy.digest(p) for p in data.iterdir()}
            data.chmod(0o500)
            env.update(TOTK_ROMFS=foreign, TOTK_ROMFS_PROOF_DIR=foreign)
            result, text = self.invoke(run, env, log, "mount")
            self.assertEqual(result.returncode, 0, text)
            self.assertEqual(result.stdout, self.image)
            self.assertEqual(before, {p.name: policy.digest(p) for p in data.iterdir()})
            self.assertEqual(list(Path(foreign).iterdir()), [])
            self.assertTrue((root / "cache/.romfs-verified-v1").is_file())
            data.chmod(0o700)

    def test_donor_overlay_request_fails_before_romfs_access(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as foreign:
            run, env, log = self.make_run(Path(directory)); env["TOTK_ROMFS_MODS"] = foreign
            result, text = self.invoke(run, env, log, "mount")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlays/mods are not supported", text)
            self.assertNotIn("index missing", text)
            self.assertEqual(list(Path(foreign).iterdir()), [])

    def test_machine_slot_rejects_per_run_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(Path(directory))
            env["CASTLEVANIA_GAME_SLOT_DIR"] = run["profile"]
            result, text = self.invoke(run, env, log, "slot")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside the individual run", text)
            self.assertFalse((Path(run["profile"]) / "lock").exists())

    def test_shared_machine_slot_excludes_a_second_host_without_preemption(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as slot_directory:
            slot = Path(slot_directory).resolve()
            first, first_env, first_log = self.make_run(Path(directory))
            second, second_env, second_log = self.make_run(Path(directory))
            first_env["CASTLEVANIA_GAME_SLOT_DIR"] = second_env["CASTLEVANIA_GAME_SLOT_DIR"] = str(slot)
            with first_log.open("ab") as stream:
                holder = subprocess.Popen([str(self.binary), "slot-hold"], cwd=first["root"], env=first_env,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stream)
                try:
                    self.assertEqual(holder.stdout.readline(), b"slot-held\n")
                    result, text = self.invoke(second, second_env, second_log, "slot")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("machine game slot is held", text)
                    self.assertIsNone(holder.poll())
                finally:
                    holder.communicate(input=b"\n", timeout=5)
            result, text = self.invoke(second, second_env, second_log, "slot")
            self.assertEqual(result.returncode, 0, text)

if __name__ == "__main__": unittest.main()
