"""Native tests of the real alias helper and independently authored tiny DSOs.

No game/SDK instructions, generated tables, assets or guest execution are used.
The tiny SDK writes its own callback through the alias, as a normal data store.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RtldRoAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-rtld-ro-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "rtld_ro_abi.h"
#include <stdio.h>
#include <stdlib.h>

static void check(int ok,const char *message){if(!ok){fprintf(stderr,"FAIL: %s\n",message);exit(2);}}
typedef struct {
    _Alignas(16) uint8_t image[160];
    Symbol symbols[3];Module module;
} TinyDso;
static void tiny_dso(TinyDso *d){
    memset(d,0,sizeof *d);
    d->symbols[0]=(Symbol){.name=""};
    d->symbols[1]=(Symbol){.name=RUNTIME_RO_MANUAL_SLOT_SYMBOL,.value=64,.size=8,.defined=1,.binding=1,.type=1};
    d->symbols[2]=(Symbol){.name="unrelated_global",.value=80,.size=8,.defined=1,.binding=1,.type=1};
    d->module=(Module){.name="independent-tiny-dso",.size=sizeof d->image,.data_off=32,.key_off=128,.base=d->image,.symbols=d->symbols,.nsym=3};
    uintptr_t sentinel=0x12345678;memcpy(d->image+80,&sentinel,8);
}
static uintptr_t word(const TinyDso *d){uintptr_t v;memcpy(&v,d->image+64,8);return v;}
static uintptr_t unrelated(const TinyDso *d){uintptr_t v;memcpy(&v,d->image+80,8);return v;}
static unsigned calls;
static void *tiny_sdk_lookup(const void *module,const char *name){check(module==(void *)(uintptr_t)17&&!strcmp(name,"tiny-symbol"),"exact callback arguments survive");calls++;return (void *)(uintptr_t)91;}
static void *tiny_sdk_replacement(const void *module,const char *name){(void)module;(void)name;calls++;return (void *)(uintptr_t)92;}
/* This callback ABI belongs only to the independent tiny fixture, not the SDK.
 * The actual helper handles an opaque 64-bit code address and never calls it. */
typedef void *(*TinyLookup)(const void *,const char *);
static uintptr_t *tiny_alias(const TinyDso *d){return (uintptr_t *)word(d);}
int main(int argc,char **argv){
    check(argc==2,"one test mode");const char *mode=argv[1];TinyDso a,b;tiny_dso(&a);tiny_dso(&b);
    RuntimeRtldRoState state={0};const char *error;
    if(!strcmp(mode,"lifecycle")){
        check(word(&a)==0&&state.manual_lookup_address==0,"fresh image and slot");
        check(!runtime_rtld_ro_prepare(&state,&a.module,1),"valid symbol-resolved alias");
        check(state.prepared==1&&word(&a)==(uintptr_t)&state.manual_lookup_address&&state.manual_lookup_address==0&&calls==0,"preparation owns storage without installing or calling SDK callback");
        *tiny_alias(&a)=(uintptr_t)tiny_sdk_lookup;
        check(state.manual_lookup_address==(uintptr_t)tiny_sdk_lookup,"normal tiny SDK store populates host-owned slot");
        check(((TinyLookup)*tiny_alias(&a))((void *)(uintptr_t)17,"tiny-symbol")== (void *)(uintptr_t)91&&calls==1,"callback remains original tiny SDK code");
        *tiny_alias(&a)=(uintptr_t)tiny_sdk_replacement;
        check(state.manual_lookup_address==(uintptr_t)tiny_sdk_replacement&&((TinyLookup)*tiny_alias(&a))(NULL,NULL)==(void *)(uintptr_t)92&&calls==2,"SDK can rebind writable callback slot");
        check(unrelated(&a)==0x12345678,"unrelated data unchanged");return 0;
    }
    if(!strcmp(mode,"shared")){
        b.symbols[1].binding=2;Module modules[]={a.module,b.module};
        check(!runtime_rtld_ro_prepare(&state,modules,2),"all exported global and weak definitions aliased");
        check(word(&a)==word(&b)&&word(&a)==(uintptr_t)&state.manual_lookup_address,"one process-wide slot");
        *tiny_alias(&a)=(uintptr_t)tiny_sdk_lookup;check(*tiny_alias(&b)==(uintptr_t)tiny_sdk_lookup,"second tiny DSO sees SDK callback");
        *tiny_alias(&b)=(uintptr_t)tiny_sdk_replacement;check(*tiny_alias(&a)==(uintptr_t)tiny_sdk_replacement,"shared rebind");return 0;
    }
    if(!strcmp(mode,"undefined-import")){
        a.symbols[1].defined=0;Module modules[]={a.module,b.module};
        check(!runtime_rtld_ro_prepare(&state,modules,2)&&!word(&a)&&word(&b),"undefined import skipped, real provider bound");return 0;
    }
    if(!strcmp(mode,"repeat")){
        check(!runtime_rtld_ro_prepare(&state,&a.module,1),"initial preparation");uintptr_t before=word(&a);
        check(runtime_rtld_ro_prepare(&state,&a.module,1)&&word(&a)==before&&state.manual_lookup_address==0,"repeat rejected without mutation");return 0;
    }
    if(!strcmp(mode,"transaction")){
        b.symbols[1].size=16;Module modules[]={a.module,b.module};
        check(runtime_rtld_ro_prepare(&state,modules,2)&&!word(&a)&&!word(&b)&&!state.prepared,"late invalid provider cannot partially bind first one");return 0;
    }
    if(!strcmp(mode,"null-arguments")){
        check(runtime_rtld_ro_prepare(NULL,&a.module,1)&&runtime_rtld_ro_prepare(&state,NULL,1)&&runtime_rtld_ro_prepare(&state,&a.module,0),"null and empty inputs rejected");return 0;
    }
    if(!strcmp(mode,"missing"))a.module.nsym=1;
    else if(!strcmp(mode,"near-name"))a.symbols[1].name=RUNTIME_RO_MANUAL_SLOT_SYMBOL "Extra";
    else if(!strcmp(mode,"local"))a.symbols[1].binding=0;
    else if(!strcmp(mode,"unknown-binding"))a.symbols[1].binding=3;
    else if(!strcmp(mode,"function"))a.symbols[1].type=2;
    else if(!strcmp(mode,"small-size"))a.symbols[1].size=4;
    else if(!strcmp(mode,"large-size"))a.symbols[1].size=16;
    else if(!strcmp(mode,"bad-defined"))a.symbols[1].defined=2;
    else if(!strcmp(mode,"rodata"))a.symbols[1].value=16;
    else if(!strcmp(mode,"end"))a.symbols[1].value=128;
    else if(!strcmp(mode,"cross-end"))a.symbols[1].value=124;
    else if(!strcmp(mode,"unaligned"))a.symbols[1].value=65;
    else if(!strcmp(mode,"overflow"))a.symbols[1].value=UINT64_MAX;
    else if(!strcmp(mode,"bad-data-range"))a.module.data_off=129;
    else if(!strcmp(mode,"bad-image-range"))a.module.key_off=161;
    else if(!strcmp(mode,"null-base"))a.module.base=NULL;
    else if(!strcmp(mode,"null-symbols"))a.module.symbols=NULL;
    else if(!strcmp(mode,"null-name"))a.symbols[1].name=NULL;
    else if(!strcmp(mode,"duplicate"))a.symbols[2]=a.symbols[1];
    else if(!strcmp(mode,"nonzero-global")){uintptr_t previous=0xdecaf;memcpy(a.image+64,&previous,8);}
    else if(!strcmp(mode,"nonzero-slot"))state.manual_lookup_address=(uintptr_t)tiny_sdk_lookup;
    else return 5;
    uintptr_t before=word(&a);error=runtime_rtld_ro_prepare(&state,&a.module,1);
    check(error&&word(&a)==before&&!state.prepared&&unrelated(&a)==0x12345678,"negative case fails without guest or unrelated writes");return 0;
}
''')
        cls.binary = directory / "fixture"
        result = subprocess.run(["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=c11",
                                 "-O2", "-Wall", "-Wextra", "-Werror",
                                 "-I" + str(ROOT / "runtime"), str(source), "-o", str(cls.binary)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin"}, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_original_tiny_sdk_installs_and_rebinds_its_own_callback(self): self.fixture("lifecycle")
    def test_multiple_definitions_share_one_native_slot(self): self.fixture("shared")
    def test_undefined_import_does_not_replace_real_provider(self): self.fixture("undefined-import")
    def test_repeated_preparation_is_rejected(self): self.fixture("repeat")
    def test_invalid_second_provider_never_leaves_partial_alias(self): self.fixture("transaction")
    def test_null_or_empty_inputs_are_rejected(self): self.fixture("null-arguments")
    def test_missing_or_similar_name_is_not_an_alias(self):
        for mode in ("missing", "near-name"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_unsupported_symbol_metadata_is_rejected(self):
        for mode in ("local", "unknown-binding", "function", "small-size", "large-size", "bad-defined", "duplicate"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_only_aligned_writable_image_storage_is_accepted(self):
        for mode in ("rodata", "end", "cross-end", "unaligned", "overflow", "bad-data-range", "bad-image-range", "null-base"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_missing_metadata_is_rejected(self):
        for mode in ("null-symbols", "null-name"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_nonzero_image_global_or_slot_is_never_overwritten(self):
        for mode in ("nonzero-global", "nonzero-slot"):
            with self.subTest(mode=mode): self.fixture(mode)


if __name__ == "__main__":
    unittest.main()
