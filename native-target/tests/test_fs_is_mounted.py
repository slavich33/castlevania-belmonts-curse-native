"""Real native FS resolver/mount-state tests using original tiny data, no guest/GPU."""
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


FIXTURE = r'''
#include "runtime.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include "fs_host.h"
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned account_calls;
_Noreturn void runtime_fail(const char *s) {fprintf(stderr,"FAIL: %s\n",s);exit(2);}
uint64_t runtime_now_ns(void) {return 0;}
void runtime_boot_progress(const char *s,uint64_t n,uint64_t t) {(void)s;(void)n;(void)t;}
void runtime_boot_status(const char *s,const char *d) {(void)s;(void)d;}
void dm_guest_write_prepare(void *p,size_t n) {(void)p;(void)n;}
void runtime_autoload_save_file_opened(const char *p) {(void)p;}
void runtime_account_uid(uint64_t out[2]) {account_calls++;out[0]=0x1234;out[1]=0x5678;}
#define CHECK(c) do {if(!(c)){fprintf(stderr,"check failed line %d: %s\n",__LINE__,#c);return 3;}} while(0)
typedef bool (*Query)(const char *);
typedef unsigned (*MountOne)(const char *);
typedef void (*Unmount)(const char *);
static Query query;
static _Atomic int done;
static void *query_thread(void *unused) {
 (void)unused;
 do {
  (void)query("race");
  if(query("race:/")||query("missing")||runtime_romfs_is_mounted("race"))abort();
 }while(!atomic_load(&done));
 return NULL;
}
int main(int argc,char **argv) {
 if(argc!=2)return 4;
 query=(Query)runtime_fs_override("_ZN2nn2fs9IsMountedEPKc");
 CHECK(query&&query==(Query)runtime_fs_host_override("_ZN2nn2fs9IsMountedEPKc"));
 CHECK(!runtime_fs_override("_ZN2nn2fs9IsMountedEPKc_unknown"));
 CHECK(!runtime_fs_override("_ZN2nn2fs6detail9IsMountedEPbPKc"));
 if(!strcmp(argv[1],"null-name")){(void)query(NULL);return 5;}
 if(!strcmp(argv[1],"query-only")) {
  char unterminated[32];memset(unterminated,'x',sizeof unterminated);
  const char *names[]={"","rom","temp","save","cache","ram","unknown","rom:","rom:/file","/rom","a/b",unterminated};
  for(unsigned repeat=0;repeat<1000;repeat++)for(unsigned i=0;i<sizeof names/sizeof names[0];i++)CHECK(!query(names[i]));
  CHECK(!runtime_romfs_is_mounted(NULL)&&!runtime_romfs_is_mounted("")&&!runtime_romfs_is_mounted("rom"));
  CHECK(!runtime_romfs_owns("rom:/hello.txt"));CHECK(account_calls==0);
  puts("query-only-ok");return 0;
 }
 castlevania_check_host_scratch();
 CHECK(!query("rom")&&!query("temp")&&!query("save")&&!query("cache")&&!query("ram"));
 Unmount unmount=(Unmount)runtime_fs_override("_ZN2nn2fs7UnmountEPKc");
 CHECK(unmount);
 if(!strcmp(argv[1],"init-only")) {
  runtime_fs_init();CHECK(!query("rom")&&!runtime_romfs_is_mounted("rom"));CHECK(account_calls==0);
 }else if(!strcmp(argv[1],"rom")) {
  unsigned (*mount_rom)(const char*,void*,uint64_t)=(void*)runtime_fs_override("_ZN2nn2fs8MountRomEPKcPvm");
  CHECK(mount_rom&&!mount_rom("rom",NULL,0));
  CHECK(query("rom")&&runtime_romfs_is_mounted("rom"));
  CHECK(!query("ROM")&&!query("ro")&&!query("romx")&&!query("rom:")&&!query("rom:/hello.txt"));
  CHECK(!runtime_romfs_owns("rom")&&runtime_romfs_owns("rom:/hello.txt"));
  uint64_t h=0,n=0;char bytes[32]={0};
  CHECK(!runtime_romfs_open(&h,"rom:/hello.txt",1));
  CHECK(!runtime_romfs_read(&n,h,0,bytes,sizeof bytes)&&n==20&&!memcmp(bytes,"owned fixture bytes\n",20));
  runtime_romfs_close(h);
  /* Directory API itself is exercised through the native resolver. */
  uint64_t directory=0;
  unsigned (*open_dir)(uint64_t*,const char*,int)=(void*)runtime_fs_override("_ZN2nn2fs13OpenDirectoryEPNS0_15DirectoryHandleEPKci");
  void (*close_dir)(uint64_t)=(void*)runtime_fs_override("_ZN2nn2fs14CloseDirectoryENS0_15DirectoryHandleE");
  CHECK(open_dir&&close_dir&&!open_dir(&directory,"rom:/",2));close_dir(directory);
  CHECK(!mount_rom("rom",NULL,0)&&query("rom")&&account_calls==0);
 }else if(!strcmp(argv[1],"race")) {
  MountOne mount=(MountOne)runtime_fs_override("_ZN2nn2fs21MountTemporaryStorageEPKc");
  CHECK(!mount("race"));unmount("race");
  pthread_t thread;CHECK(!pthread_create(&thread,NULL,query_thread,NULL));
  for(unsigned i=0;i<128;i++){CHECK(!mount("race")&&query("race"));unmount("race");CHECK(!query("race"));}
  atomic_store(&done,1);CHECK(!pthread_join(thread,NULL));CHECK(!query("race"));
 }else {
  const char *name=argv[1];
  if(!strcmp(name,"save")) {
   unsigned (*mount)(const char*,const uint64_t*)=(void*)runtime_fs_override("_ZN2nn2fs13MountSaveDataEPKcRKNS_7account3UidE");
   const uint64_t uid[2]={0x1234,0x5678};CHECK(mount&&!mount(name,uid));
  }else if(!strcmp(name,"cache")) {
   unsigned (*create)(int,int64_t,int64_t)=(void*)runtime_fs_override("_ZN2nn2fs18CreateCacheStorageEill");
   unsigned (*mount)(const char*,int)=(void*)runtime_fs_override("_ZN2nn2fs17MountCacheStorageEPKci");
   CHECK(create&&mount&&!create(0,4096,0)&&!mount(name,0));
  }else if(!strcmp(name,"ram")) {
   unsigned (*mount)(const char*,void*,uint64_t)=(void*)runtime_fs_override("_ZN2nn2fs12MountRamDiskEPKcPvm");
   CHECK(mount&&!mount(name,NULL,0));
  }else {
   MountOne mount=(MountOne)runtime_fs_override("_ZN2nn2fs21MountTemporaryStorageEPKc");
   CHECK(mount&&!mount(name));
  }
  CHECK(query(name)&&!runtime_romfs_is_mounted(name));
  char path[64];snprintf(path,sizeof path,"%s:/",name);CHECK(!query(path));
  char different[64];snprintf(different,sizeof different,"%sx",name);CHECK(!query(different));
  strcpy(different,name);different[strlen(name)-1]=0;CHECK(!query(different));
  strcpy(different,name);if(different[0]>='a'&&different[0]<='z')different[0]-='a'-'A';CHECK(!query(different));
  CHECK(!query("unknown")&&!query(""));
  if(!strcmp(name,"hold")) {
   unsigned before=account_calls;puts("ready");fflush(stdout);CHECK(getchar()=='\n');
   for(unsigned i=0;i<10000;i++)CHECK(query(name)&&!query("unknown")&&!query("rom"));
   CHECK(account_calls==before);puts("queries-done");return 0;
  }
  unmount(name);CHECK(!query(name));
 }
 puts("ok");return 0;
}
'''


class IsMountedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-mount-tests-")
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
        source.write_text(FIXTURE)
        cls.binary = cls.work / "mount-fixture"
        result = subprocess.run([
            "/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
            "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1", "-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
            "-I"+str(policy.ROOT / "runtime"), "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"),
            "-I"+str(cls.work), str(policy.ROOT / "runtime/fs_host.c"), str(policy.ROOT / "runtime/romfs.c"),
            str(source), "-framework", "CoreFoundation", "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def make_run(self, parent, data=False):
        run = policy.create_run(Path(parent))
        root = Path(run["root"])
        (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
        log = root / "logs/native-host.log"
        log.touch(mode=0o600)
        env = policy.child_environment(run)
        env["CASTLEVANIA_LOG_FILE"] = str(log)
        if data:
            staged = root / "extracted/v110/romfs"
            staged.mkdir(parents=True)
            for name, content in [("romfs.bin", self.image), ("runtime-index.bin", self.index)]:
                (staged / name).write_bytes(content)
                (staged / name).chmod(0o400)
            staged.chmod(0o500)
        return run, env, log

    def invoke(self, command, data=False):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(directory, data=data)
            root = Path(run["root"])
            inputs = root / "extracted"
            before = self.snapshot(inputs) if data else None
            with log.open("ab") as output:
                result = subprocess.run([str(self.binary), command], cwd=root, env=env,
                                        capture_output=False, stdout=subprocess.PIPE, stderr=output)
            self.assertEqual(result.returncode, 0, log.read_text())
            if data:
                self.assertEqual(before, self.snapshot(inputs))
                (inputs / "v110/romfs").chmod(0o700)
            return result.stdout, log.read_text()

    @staticmethod
    def snapshot(root):
        return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_size, p.stat().st_mtime_ns,
                p.stat().st_ctime_ns, policy.digest(p) if p.is_file() else None)
                for p in root.rglob("*")}

    def test_exact_bool_resolver_before_any_filesystem_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"untouched")
            before = self.snapshot(root)
            env = {"CASTLEVANIA_PROFILE_DIR": "/not/a/run", "CASTLEVANIA_RUN_ROOT": "/not/a/run"}
            result = subprocess.run([str(self.binary), "query-only"], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "query-only-ok\n")
            self.assertEqual(result.stderr, "")
            self.assertEqual(before, self.snapshot(root))

    def test_temporary_mount_and_unmount(self):
        self.invoke("temp")

    def test_null_name_is_fatal_without_filesystem_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = self.snapshot(root)
            result = subprocess.run([str(self.binary), "null-name"], cwd=root, env={},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("IsMounted requires a non-null mount name", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(before, self.snapshot(root))

    def test_save_mount_and_unmount(self):
        self.invoke("save")

    def test_cache_mount_and_unmount(self):
        self.invoke("cache")

    def test_ram_mount_and_unmount(self):
        self.invoke("ram")

    def test_unknown_prefix_case_and_path_names_do_not_match(self):
        self.invoke("prefix")

    def test_existing_long_host_name_is_queried_exactly(self):
        # The inherited host registry accepts up to31 bytes; this change does not
        # silently change its registration API to the SDK's15-byte limit.
        self.invoke("existing-host-name-31-bytes-lon")

    def test_verified_image_ready_does_not_mean_romfs_is_mounted(self):
        self.invoke("init-only", data=True)

    def test_real_romfs_mount_query_and_original_file_directory_access(self):
        self.invoke("rom", data=True)

    def test_host_mount_queries_are_serialized_with_unmount(self):
        self.invoke("race")

    def test_mounted_queries_do_not_write_or_initialize_again(self):
        with tempfile.TemporaryDirectory() as directory:
            run, env, log = self.make_run(directory)
            root = Path(run["root"])
            with log.open("ab") as output:
                process = subprocess.Popen([str(self.binary), "hold"], cwd=root, env=env,
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=output)
                try:
                    self.assertEqual(process.stdout.readline(), b"ready\n")
                    before = self.snapshot(root)
                    stdout, _ = process.communicate(b"\n", timeout=10)
                    self.assertEqual(process.returncode, 0, log.read_text())
                    self.assertEqual(stdout, b"queries-done\n")
                    self.assertEqual(before, self.snapshot(root))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()


if __name__ == "__main__":
    unittest.main()
