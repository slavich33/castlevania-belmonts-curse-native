"""Proof reuse policy + real tiny native RomFS runs; no game or GPU execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import run_experimental_host as runner


class HostRunnerProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilation = tempfile.TemporaryDirectory(prefix="castlevania-proof-native-")
        directory = Path(cls.compilation.name)
        cls.image = b"owned fixture bytes\n"
        name = b"hello.txt\0"
        cls.index = (struct.pack("<8sQQ", b"TOTKRFS1", 1, 48)+
                     struct.pack("<QQII", 0, len(cls.image), 0, len(name))+name)
        cls.config = (f'#define ROMFS_IMAGE_SIZE {len(cls.image)}ULL\n'
                      f'#define ROMFS_IMAGE_SHA256 "{hashlib.sha256(cls.image).hexdigest()}"\n'
                      f'#define ROMFS_INDEX_SHA256 "{hashlib.sha256(cls.index).hexdigest()}"\n').encode()
        (directory/"romfs_config.h").write_bytes(cls.config)
        source = directory/"fixture.c"
        source.write_text(r'''
#include "romfs.c"
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){return 0;}
void runtime_boot_progress(const char *s,uint64_t n,uint64_t t){(void)s;(void)n;(void)t;}
void runtime_boot_status(const char *s,const char *d){(void)s;(void)d;}
void *runtime_fs_host_override(const char *s){(void)s;return NULL;}
void dm_guest_write_prepare(void *p,size_t n){(void)p;(void)n;}
int main(void){runtime_fs_init();puts("tiny native RomFS fixture; no guest/GPU");return 0;}
''')
        cls.native = directory/"tiny-romfs"
        command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                   "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
                   "-DGAME_CASTLEVANIA=1", "-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
                   "-I"+str(runner.ROOT/"runtime"),
                   "-I"+str(runner.ROOT/"third_party/d2r_gfx/gfx/nvn/include"),
                   "-I"+str(directory), str(source), "-framework", "CoreFoundation", "-o", str(cls.native)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls): cls.compilation.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="castlevania-runner-proof-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.work = self.base/"work";self.work.mkdir(mode=0o700)
        (self.work/".castlevania-host-build").write_text(runner.TITLE+"\n")
        for path in ("build", "generated", "extracted/v110/romfs", "rewritten/v110"):
            (self.work/path).mkdir(parents=True)
        self.binary = self.work/"build/castlevania-native"
        self.binary.write_bytes(self.native.read_bytes());self.binary.chmod(0o700)
        self.data = self.base/"romfs.bin";self.data.write_bytes(self.image)
        (self.work/"extracted/v110/romfs/romfs.bin").symlink_to(self.data)
        (self.work/"extracted/v110/romfs/runtime-index.bin").write_bytes(self.index)
        (self.work/"generated/romfs_config.h").write_bytes(self.config)
        (self.work/"rewritten/v110/main.patched.bin").write_bytes(b"not executed; runner presence fixture")
        self.build = {"schema":1,"state":"actual_native_host_compiled_not_launched","title_id":runner.TITLE,
                      "work":str(self.work),"diagnostic_boot_compiled":True,"binary":str(self.binary),
                      "binary_sha256":runner.sha(self.binary),
                      "source_hashes":{"runtime/romfs.c":runner.sha(runner.ROOT/"runtime/romfs.c")},
                      "resources":{"romfs_image":str(self.data),"romfs_image_size":len(self.image),"romfs_files":1,
                                   "romfs_image_sha256":hashlib.sha256(self.image).hexdigest(),
                                   "romfs_index_sha256":hashlib.sha256(self.index).hexdigest(),
                                   "romfs_config_sha256":hashlib.sha256(self.config).hexdigest()}}
        (self.work/"host-build-receipt.json").write_text(json.dumps(self.build)+"\n")
        self.prior_receipt = self.run_native()
        self.prior = Path(self.prior_receipt["run_root"])

    def run_native(self, prior=None):
        args = argparse.Namespace(work=self.work, timeout=5, app_pool=0xce000000,
                                  with_window=False, reuse_romfs_proof_from=prior)
        return runner.run(args)

    def write_json(self, path, value): path.write_text(json.dumps(value)+"\n")

    def write_compiled(self, value):
        path=self.prior/"compiled-build-receipt.json";self.write_json(path,value)
        receipt_path=self.prior/"receipt.json";r=json.loads(receipt_path.read_text())
        r["compiled_build_receipt_sha256"]=runner.sha(path);self.write_json(receipt_path,r)

    def destination(self):
        root = Path(tempfile.mkdtemp(prefix="host-",dir=self.work/"runs"))
        (root/"cache").mkdir(mode=0o700)
        return root/"cache"/runner.PROOF_NAME

    def reuse(self, prior=None):
        return runner.reuse_romfs_proof(self.work,self.build,prior or self.prior,self.destination())

    def test_default_performs_full_C_hash_and_saves_exact_build_receipt(self):
        self.assertEqual(self.prior_receipt["runtime_romfs_verification_mode"],"fresh_full_sha256")
        self.assertFalse(self.prior_receipt["runtime_romfs_proof_reuse"]["requested"])
        self.assertEqual((self.prior/"compiled-build-receipt.json").read_bytes(),(self.work/"host-build-receipt.json").read_bytes())
        self.assertEqual((self.prior/"cache"/runner.PROOF_NAME).stat().st_size,160)

    def test_real_C_byte_exact_copy_reuses_unchanged_image(self):
        proof = (self.prior/"cache"/runner.PROOF_NAME).read_bytes()
        result = self.run_native(self.prior)
        self.assertEqual(result["exit_code"],0)
        self.assertEqual(result["runtime_romfs_verification_mode"],"reused_previous_C_full_hash_record")
        self.assertEqual((Path(result["run_root"])/"cache"/runner.PROOF_NAME).read_bytes(),proof)
        self.assertTrue(result["runtime_romfs_proof_reuse"]["copied_byte_exact"])
        self.assertNotEqual(result["run_root"],str(self.prior))
        self.assertEqual(list((Path(result["run_root"])/"saves").iterdir()),[])

    def test_same_size_mutation_forces_real_C_hash_then_rejects_corruption(self):
        self.data.write_bytes(b"X"*len(self.image))
        result = self.run_native(self.prior)
        text = Path(result["log"]).read_text()
        self.assertNotEqual(result["exit_code"],0)
        self.assertIn("verifying local RomFS SHA256",text)
        self.assertIn("RomFS integrity mismatch",text)
        self.assertNotIn("RomFS unchanged",text)
        self.assertEqual(result["runtime_romfs_verification_mode"],"not_reached_or_incomplete")

    def test_reuse_does_not_read_the_whole_image_in_python(self):
        real_sha=runner.sha
        def sha(path):
            if Path(path).resolve()==self.data:raise AssertionError("runner reread image bytes")
            return real_sha(path)
        with mock.patch.object(runner,"sha",side_effect=sha):self.reuse()

    def test_missing_compiled_sidecar_fails(self):
        (self.prior/"compiled-build-receipt.json").unlink()
        with self.assertRaises(OSError):self.reuse()

    def test_wrong_run_title_state_paths_log_or_binary_fails(self):
        path=self.prior/"receipt.json";original=json.loads(path.read_text())
        for field,value in (("title_id","other"),("state","running"),("run_root",str(self.base)),
                            ("log_sha256","0"*64),("log_bytes",0),("binary_sha256","0"*64),
                            ("remaining_owned_process_group_pids",[1]),("run_marker_sha256","0"*64),
                            ("compiled_build_receipt_sha256","0"*64)):
            with self.subTest(field=field):
                edited=dict(original);edited[field]=value;self.write_json(path,edited)
                with self.assertRaises(ValueError):self.reuse()
        self.write_json(path,original)

    def test_wrong_compiled_source_resources_and_work_fail(self):
        path=self.prior/"compiled-build-receipt.json";original=json.loads(path.read_text())
        for field,value in (("work",str(self.base)),("title_id","other"),("diagnostic_boot_compiled",False),
                            ("binary_sha256","0"*64),("source_hashes",{"runtime/romfs.c":"0"*64}),
                            ("resources",{**original["resources"],"romfs_image":str(self.base/"other")})):
            with self.subTest(field=field):
                edited=dict(original);edited[field]=value;self.write_compiled(edited)
                with self.assertRaises(ValueError):self.reuse()
        self.write_compiled(original)

    def test_changed_config_or_index_fails_before_copy(self):
        for relative in ("generated/romfs_config.h","extracted/v110/romfs/runtime-index.bin"):
            path=self.work/relative;original=path.read_bytes();path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError,"config/index"):self.reuse()
            path.write_bytes(original)

    def test_wrong_expected_resources_fail_even_when_build_bindings_match(self):
        prior_path=self.prior/"compiled-build-receipt.json"
        original=json.loads(prior_path.read_text())
        for key,value in (("romfs_files",2),("romfs_image_sha256","0"*64)):
            with self.subTest(key=key):
                edited=json.loads(json.dumps(original));edited["resources"][key]=value
                self.build["resources"][key]=value;self.write_compiled(edited)
                with self.assertRaises(ValueError):self.reuse()
                self.build["resources"][key]=1 if key=="romfs_files" else hashlib.sha256(self.image).hexdigest()
        self.write_compiled(original)

    def test_proof_must_be_owned_regular_private_160_byte_C_record(self):
        path=self.prior/"cache"/runner.PROOF_NAME;original=path.read_bytes()
        for data in (b"short",b"X"+original[1:],original[:16]+b"0"*64+original[80:]):
            path.write_bytes(data)
            with self.assertRaises(ValueError):self.reuse()
        path.write_bytes(original);path.chmod(0o644)
        with self.assertRaises(ValueError):self.reuse()

    def test_symlink_or_hardlink_proof_is_rejected(self):
        path=self.prior/"cache"/runner.PROOF_NAME;other=self.base/"proof";path.rename(other);path.symlink_to(other)
        with self.assertRaises(ValueError):self.reuse()
        path.unlink();os.link(other,path)
        with self.assertRaises(ValueError):self.reuse()

    def test_prior_must_be_direct_canonical_private_run(self):
        alias=self.work/"runs/host-alias";alias.symlink_to(self.prior,target_is_directory=True)
        with self.assertRaises(ValueError):self.reuse(alias)
        with self.assertRaises(ValueError):self.reuse(self.base)
        self.prior.chmod(0o755)
        with self.assertRaises(ValueError):self.reuse()

    def test_missing_ready_does_not_establish_C_verification(self):
        log=self.prior/"logs/native-host.log";data=log.read_bytes().replace(b"native read-only RomFS ready",b"incomplete RomFS")
        log.write_bytes(data);path=self.prior/"receipt.json";r=json.loads(path.read_text());r["log_sha256"]=hashlib.sha256(data).hexdigest();r["log_bytes"]=len(data);self.write_json(path,r)
        with self.assertRaisesRegex(ValueError,"never reached ready"):self.reuse()

    def test_destination_is_exclusive_private_copy(self):
        destination=self.destination();destination.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):runner.reuse_romfs_proof(self.work,self.build,self.prior,destination)
        self.assertEqual(destination.read_bytes(),b"keep")

    def test_approved_old_receipt_marks_unrecorded_extra_bindings(self):
        path=self.prior/"receipt.json";r=json.loads(path.read_text());r.pop("run_marker_sha256");r.pop("compiled_build_receipt_sha256");self.write_json(path,r)
        result=self.reuse();self.assertFalse(result["prior_marker_binding_recorded"]);self.assertFalse(result["prior_compiled_receipt_binding_recorded"])


if __name__=="__main__":unittest.main()
