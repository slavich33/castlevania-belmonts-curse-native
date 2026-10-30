"""Native RSA-PSS certificate/NRR verification with ephemeral original fixtures."""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NrrValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-nrr-validation-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "nrr_validate.c"
#include "nrr_fixture.h"
#define FIXTURE_TITLE UINT64_C(0x0100ba4026e94000)
int main(int argc,char **argv){
 nrr_fixture_need(argc>=2,"mode");const char *mode=argv[1];RuntimeNrrValidated output={0};
 if(!strcmp(mode,"genuine")){
  nrr_fixture_need(argc==3,"explicit private fixture path");FILE *f=fopen(argv[2],"rb");nrr_fixture_need(f!=NULL,"read-only fixture open");
  nrr_fixture_need(!fseek(f,0,SEEK_END),"seek");long size=ftell(f);nrr_fixture_need(size>0&&size<=RUNTIME_NRR_MAX_BYTES,"file size");rewind(f);
  uint8_t *b=malloc((size_t)size);nrr_fixture_need(b&&fread(b,1,(size_t)size,f)==(size_t)size,"fixture read");fclose(f);
  const char *error=runtime_nrr_validate(b,(size_t)size,FIXTURE_TITLE,&output);if(error){fprintf(stderr,"%s\n",error);return 2;}
  nrr_fixture_need(output.hash_count==1&&output.hashes_offset==0x350&&output.key_generation==0,"owned fixture metadata");free(b);puts("genuine_public_production_RSA_chain_PASS");return 0;
 }
 NrrFixtureKeys keys=nrr_fixture_keys();uint8_t *b=nrr_fixture_make(&keys,FIXTURE_TITLE);size_t size=4096;uint64_t title=FIXTURE_TITLE;const char *expected=NULL;
 if(!strcmp(mode,"valid")){}
 else if(!strcmp(mode,"production-rejects-test-root")){
  nrr_fixture_need(runtime_nrr_validate(b,size,title,&output)!=NULL,"production entry must not trust ephemeral test root");free(b);nrr_fixture_keys_close(&keys);return 0;
 }
 else if(!strcmp(mode,"wrong-root")){memcpy(keys.root_modulus,keys.child_modulus,256);expected="certificate signature";}
 else if(!strcmp(mode,"cert-tamper")){b[0x25]^=1;expected="certificate signature";}
 else if(!strcmp(mode,"cert-signature")){b[0x130]^=1;expected="certificate signature";}
 else if(!strcmp(mode,"nrr-tamper")){b[0x900]^=1;expected="NRR signature";}
 else if(!strcmp(mode,"nrr-signature")){b[0x230]^=1;expected="NRR signature";}
 else if(!strcmp(mode,"kind")){b[0x33c]=1;nrr_fixture_sign_all(&keys,b,size);expected="unsupported kind";}
 else if(!strcmp(mode,"title")){title++;expected="program identity";}
 else if(!strcmp(mode,"mask")){nrr_fixture_u64(b+0x18,FIXTURE_TITLE+1);nrr_fixture_sign_all(&keys,b,size);expected="program mask";}
 else if(!strcmp(mode,"size")){nrr_fixture_u32(b+0x338,8192);expected="declared size";}
 else if(!strcmp(mode,"key-generation")){nrr_fixture_u32(b+4,2);expected="key generation";}
 else if(!strcmp(mode,"offset")){nrr_fixture_u32(b+0x340,0x340);expected="hash table bounds";}
 else if(!strcmp(mode,"offset-overflow")){nrr_fixture_u32(b+0x340,UINT32_MAX);expected="hash table bounds";}
 else if(!strcmp(mode,"count-overflow")){nrr_fixture_u32(b+0x344,UINT32_MAX);expected="hash table bounds";}
 else if(!strcmp(mode,"unsorted")){memset(b+0x350,0x33,32);nrr_fixture_sign_all(&keys,b,size);expected="sorted and unique";}
 else if(!strcmp(mode,"duplicate-hash")){memset(b+0x370,0x11,32);nrr_fixture_sign_all(&keys,b,size);expected="sorted and unique";}
 else if(!strcmp(mode,"magic")){b[0]='x';expected="magic";}
 else if(!strcmp(mode,"truncated")){size=0x340;expected="snapshot size";}
 else if(!strcmp(mode,"unaligned-size")){size=4095;expected="snapshot size";}
 else if(!strcmp(mode,"oversized")){size=RUNTIME_NRR_MAX_BYTES+4096;expected="snapshot size";}
 else if(!strcmp(mode,"empty-authority")){nrr_fixture_u32(b+0x344,0);nrr_fixture_sign_all(&keys,b,size);}
 else return 5;
 memset(&output,0xa5,sizeof output);RuntimeNrrValidated before=output;
 const char *error=nrr_validate_with_modulus(b,size,title,keys.root_modulus,&output);
 if(expected){nrr_fixture_need(error&&strstr(error,expected),"specific validation rejection");nrr_fixture_need(!memcmp(&output,&before,sizeof output),"failure cannot publish partial metadata");}
 else {nrr_fixture_need(!error,"valid signed fixture");nrr_fixture_need(output.hash_count==(!strcmp(mode,"empty-authority")?0u:2u)&&output.hashes_offset==0x350&&output.key_generation==0,"validated metadata");uint8_t digest[32];CC_SHA256(b+0x330,(CC_LONG)(size-0x330),digest);nrr_fixture_need(!memcmp(digest,output.signed_area_sha256,32),"immutable signed-area digest");}
 free(b);nrr_fixture_keys_close(&keys);return 0;
}
''')
        cls.binary = directory / "nrr-native"
        command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                   "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
                   "-I" + str(ROOT / "runtime"), "-I" + str(ROOT / "tests"), str(source),
                   "-framework", "Security", "-framework", "CoreFoundation", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode):
        result = subprocess.run([str(self.binary), mode], env={"PATH": "/usr/bin:/bin"},
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_two_level_ephemeral_signed_nrr_passes_native_security_api(self): self.fixture("valid")
    def test_production_entry_never_trusts_the_test_root(self): self.fixture("production-rejects-test-root")
    def test_wrong_root_or_certificate_tamper_fails(self):
        for mode in ("wrong-root", "cert-tamper", "cert-signature"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_nrr_data_or_signature_tamper_fails(self):
        for mode in ("nrr-tamper", "nrr-signature"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_authenticated_kind_title_and_mask_are_required(self):
        for mode in ("kind", "title", "mask"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_declared_size_and_supported_production_generation_are_required(self):
        for mode in ("size", "key-generation"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_hash_range_count_and_order_are_checked(self):
        for mode in ("offset", "offset-overflow", "count-overflow", "unsorted", "duplicate-hash"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_snapshot_magic_alignment_and_resource_bounds_are_checked(self):
        for mode in ("magic", "truncated", "unaligned-size", "oversized"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_valid_empty_hash_table_grants_no_module_hash_authority(self): self.fixture("empty-authority")
    def test_explicit_private_genuine_fixture_uses_production_wrapper_read_only(self):
        value = os.environ.get("CASTLEVANIA_TEST_NRR_FIXTURE")
        if not value:
            self.skipTest("private genuine fixture is explicit and remains outside Git")
        path = Path(value).resolve(strict=True)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(before, "dd97a3ca8c5bff347be41289bef9c88ad6293f204ce162ea3a614aee5bd45770")
        result = subprocess.run([str(self.binary), "genuine", str(path)], env={"PATH": "/usr/bin:/bin"},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("genuine_public_production_RSA_chain_PASS", result.stdout)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
