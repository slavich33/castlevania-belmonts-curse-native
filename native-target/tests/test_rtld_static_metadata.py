"""Inactive RTLD metadata candidate, independent native tiny-image fixtures.

No original module files, SDK calls, guest execution or loader integration.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StaticRtldMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="castlevania-static-rtld-")
        root = Path(cls.work.name)
        source = root / "fixture.c"
        source.write_text(r'''
#include "rtld_static_metadata.h"
#include <stdio.h>
typedef struct {uint8_t *image;Module m;Symbol symbols[8];unsigned strings,tags;} Tiny;
static void need(int ok,const char *why){if(!ok){fprintf(stderr,"FAIL: %s\n",why);exit(2);}}
static void w32(void *p,uint32_t x){memcpy(p,&x,4);}
static void w64(void *p,uint64_t x){memcpy(p,&x,8);}
static void tag(Tiny *t,uint64_t k,uint64_t v){w64(t->image+0x3000+t->tags*16,k);w64(t->image+0x3008+t->tags++*16,v);}
static unsigned string(Tiny *t,const char *s){unsigned off=t->strings;size_t n=strlen(s)+1;need(off+n<0x200,"tiny string table");memcpy(t->image+0x1200+off,s,n);t->strings+=(unsigned)n;return off;}
static void symbol(Tiny *t,unsigned i,const char *name,unsigned bind,unsigned type,uint64_t value,unsigned size){
 unsigned str=string(t,name);uint8_t *p=t->image+0x1400+i*24;uint16_t section=i?1:0;
 w32(p,str);p[4]=(uint8_t)(bind<<4|type);memcpy(p+6,&section,2);w64(p+8,value);w64(p+16,size);
 t->symbols[i]=(Symbol){.name=(char *)t->image+0x1200+str,.value=value,.size=size,.defined=!!i,.binding=bind,.type=type};
}
static void tiny(Tiny *t,unsigned binding){
 memset(t,0,sizeof *t);t->image=calloc(1,0x5000);need(t->image!=NULL,"tiny allocation");
 t->m=(Module){.name="tiny",.digest="0000000000000000000000000000000000000000000000000000000000000000",.file_size=0x4000,.size=0x5000,.text_end=0x1000,.ro_off=0x1000,.data_off=0x3000,.key_off=0x5000,.symbols=t->symbols,.nsym=8,.base=t->image};
 w32(t->image+4,0x1000);w32(t->image+0x1000,0x30444f4d);
 const unsigned fields[]={0x2000,0x3000,0x4000,0x800,0x900,0x3100};
 for(unsigned i=0;i<6;i++)w32(t->image+0x1004+i*4,fields[i]);
 symbol(t,0,"",0,0,0,0);
 for(unsigned i=0;i<5;i++)symbol(t,i+1,rtld_static_alias_names[i],1,1,0x4400+i*8,8);
 symbol(t,6,"shared",binding,2,0x200,16);symbol(t,7,"localonly",0,2,0x300,16);
 unsigned soname=string(t,"tiny");w32(t->image+0x1100,1);w32(t->image+0x1104,8);w32(t->image+0x1108,1);
 for(unsigned i=1;i<7;i++)w32(t->image+0x110c+i*4,i+1);
 tag(t,4,0x1100);tag(t,5,0x1200);tag(t,6,0x1400);tag(t,10,t->strings);tag(t,11,24);
 tag(t,14,soname);tag(t,7,0x1600);tag(t,8,24);tag(t,9,24);tag(t,23,0x1700);tag(t,2,48);tag(t,20,7);
 tag(t,3,0x3200);tag(t,12,0x100);tag(t,13,0x104);tag(t,30,8);tag(t,0x6ffffffb,0x8000001);
 tag(t,35,8);tag(t,36,0x1800);tag(t,37,8);tag(t,0x6ffffff9,0);tag(t,0,0);
 w64(t->image+0x1700,0x3218);w64(t->image+0x1708,((uint64_t)6<<32)|1026);
 w64(t->image+0x1718,0x3220);w64(t->image+0x1720,((uint64_t)6<<32)|1026);
 w64(t->image+0x3218,0x250);w64(t->image+0x3220,0x250);
}
static RtldStaticMetadata *active;
static void *tiny_callback(const char *name){return rtld_static_lookup_export(active,name);}
static uint64_t alias(Tiny *t,unsigned a){return rtld_static_u64(t->image+0x4400+a*8);}
static void clear(Tiny *a,Tiny *b){free(a->image);free(b->image);}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];Tiny a,b;tiny(&a,2);tiny(&b,1);Module modules[]={a.m,b.m};
 RtldStaticBindingSource captures[2];memset(captures,0,sizeof captures);
 if(!strcmp(mode,"capture-after-bind")){modules[0].symbolic=1;need(rtld_static_capture_binding_source(&modules[0],&captures[0])&&rtld_static_zero(&captures[0],sizeof captures[0]),"late capture rejected");clear(&a,&b);return 0;}
 if(!strcmp(mode,"capture-inconsistent")){w64(a.image+0x3220,0x254);need(rtld_static_capture_binding_source(&modules[0],&captures[0])&&rtld_static_zero(&captures[0],sizeof captures[0]),"inconsistent originals rejected transactionally");clear(&a,&b);return 0;}
 need(!rtld_static_capture_binding_source(&modules[0],&captures[0])&&!rtld_static_capture_binding_source(&modules[1],&captures[1]),"capture authentic originals before binding");
 need(captures[0].lazy_offset==0x250&&captures[0].jump_slots==2,"measured original common lazy target");
 w64(a.image+0x3218,0x1234abcd);w64(b.image+0x3218,0x1234abcd); /* Simulated existing HLE binding, never restored by helper. */
 RtldStaticMetadata state;memset(&state,0,sizeof state);active=&state;
 if(!strcmp(mode,"positive")){
  a.m.weak=1;modules[0]=a.m;
  need(!rtld_static_metadata_prepare(&state,modules,captures,2,(uintptr_t)tiny_callback),"valid full metadata preparation");
  RtldStaticRoModule *first=(void *)(a.image+0x4100),*second=(void *)(b.image+0x4100);
  need(state.automatic.next==(uintptr_t)first&&state.automatic.prev==(uintptr_t)second&&first->next==(uintptr_t)second&&second->prev==(uintptr_t)first,"real ordered auto descriptors");
  need(first->prev==(uintptr_t)&state.automatic&&second->next==(uintptr_t)&state.automatic,"real self sentinel ends");
  need(state.manual.prev==(uintptr_t)&state.manual&&state.manual.next==(uintptr_t)&state.manual&&!state.debug_flag&&!state.manual_lookup_address,"legitimate empty manual and debug-zero storage");
  need(first->base==(uintptr_t)a.image&&first->dynamic==(uintptr_t)a.image+0x3000&&first->image_size==0x5000,"base/dynamic/mapped size");
  need(first->jmprel==(uintptr_t)a.image+0x1700&&first->relocations==(uintptr_t)a.image+0x1600&&first->pltrelsz==48&&first->relasz==24&&!first->relsz,"complete relocation metadata, not applied again");
  need(first->buckets==(uintptr_t)a.image+0x1108&&first->chains==(uintptr_t)a.image+0x110c&&first->nbucket==1&&first->nchain==8,"exact SysV lookup fields");
  need(first->state_c0==0x13&&first->flags_c3==14&&second->flags_c3==6&&!first->opaque20&&first->lazy_c8==(uintptr_t)a.image+0x250&&!first->zero_c4,"measured state/flags and recovered original lazy baseline");
  for(unsigned i=0;i<5;i++)need(alias(&a,i)==alias(&b,i),"all definitions share actual native storage");
  need(alias(&a,0)==(uintptr_t)&state.manual_lookup_address&&alias(&a,1)==(uintptr_t)&state.manual&&alias(&a,2)==(uintptr_t)&state.debug_flag&&alias(&a,3)==(uintptr_t)tiny_callback&&alias(&a,4)==(uintptr_t)&state.automatic,"all five distinct alias semantics");
  need(((void *(*)(const char *))(uintptr_t)alias(&a,3))("shared")==a.image+0x200,"first weak provider wins before later strong, exact address return");
  need(!tiny_callback("localonly")&&!tiny_callback("missing"),"locals and missing exports do not resolve");
  need(rtld_static_u64(a.image+0x3218)==0x1234abcd&&!rtld_static_u64(a.image+0x4800),"existing HLE slot and ctor state unchanged");
  state.manual_lookup_address=0x7788;need(rtld_static_metadata_prepare(&state,modules,captures,2,(uintptr_t)tiny_callback)!=NULL&&state.manual_lookup_address==0x7788,"repeat cannot reset SDK-owned callback");clear(&a,&b);return 0;
 }
 if(!strcmp(mode,"arguments")){
  need(rtld_static_metadata_prepare(NULL,modules,captures,2,(uintptr_t)tiny_callback)&&rtld_static_metadata_prepare(&state,NULL,captures,2,(uintptr_t)tiny_callback)&&rtld_static_metadata_prepare(&state,modules,captures,0,(uintptr_t)tiny_callback)&&rtld_static_metadata_prepare(&state,modules,captures,2,0)&&rtld_static_metadata_prepare(&state,modules,captures,2,1),"bad arguments rejected");clear(&a,&b);return 0;
 }
 if(!strcmp(mode,"bad-last-module"))w32(b.image+0x1000,0);
 else if(!strcmp(mode,"descriptor-end"))w32(b.image+0x1018,0x3fff);
 else if(!strcmp(mode,"descriptor-before-bss"))w32(b.image+0x1018,0x2f00);
 else if(!strcmp(mode,"descriptor-nonzero"))b.image[0x4100]=1;
 else if(!strcmp(mode,"bad-mod0"))w32(b.image+4,0xfffffff0);
 else if(!strcmp(mode,"truncated-dynamic"))w32(b.image+0x1004,0x2ff8);
 else if(!strcmp(mode,"bad-hash-index"))w32(b.image+0x1108,8);
 else if(!strcmp(mode,"hash-cycle"))w32(b.image+0x1110,1);
 else if(!strcmp(mode,"symbol-count"))b.m.nsym=7;
 else if(!strcmp(mode,"symbol-name"))b.symbols[6].name="wrong";
 else if(!strcmp(mode,"alias-type")){b.symbols[1].type=2;b.image[0x1400+24+4]=0x12;}
 else if(!strcmp(mode,"alias-local")){b.symbols[1].binding=0;b.image[0x1400+24+4]=1;}
 else if(!strcmp(mode,"alias-nonzero"))w64(b.image+0x4400,1);
 else if(!strcmp(mode,"overlapping-alias")){b.symbols[2].value=0x4400;w64(b.image+0x1400+48+8,0x4400);}
 else if(!strcmp(mode,"missing-alias")){a.symbols[1].defined=0;b.symbols[1].defined=0;uint16_t zero=0;memcpy(a.image+0x1400+24+6,&zero,2);memcpy(b.image+0x1400+24+6,&zero,2);}
 else if(!strcmp(mode,"tls")){b.symbols[6].type=6;b.image[0x1400+6*24+4]=0x16;}
 else if(!strcmp(mode,"unknown-tag"))w64(b.image+0x3000,0x12345678);
 else if(!strcmp(mode,"unknown-flags"))w64(b.image+0x3008+15*16,0x10);
 else if(!strcmp(mode,"bad-relr"))w64(b.image+0x3008+19*16,16);
 else if(!strcmp(mode,"overlapping-modules")){modules[1]=modules[0];}
 else if(!strcmp(mode,"capture-mismatch"))captures[1].base=a.image;
 else return 5;
 if(strcmp(mode,"overlapping-modules")){modules[0]=a.m;modules[1]=b.m;}
 uint8_t before_a[0x5000],before_b[0x5000];memcpy(before_a,a.image,sizeof before_a);memcpy(before_b,b.image,sizeof before_b);
 need(rtld_static_metadata_prepare(&state,modules,captures,2,(uintptr_t)tiny_callback)!=NULL,"negative metadata rejected");
 need(!memcmp(before_a,a.image,sizeof before_a)&&!memcmp(before_b,b.image,sizeof before_b)&&rtld_static_zero(&state,sizeof state),"all validation transactional before any guest/state mutation");
 clear(&a,&b);return 0;
}
''')
        cls.binary = root / "fixture"
        result = subprocess.run(["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=c11",
                                 "-O1", "-Wall", "-Wextra", "-Werror",
                                 "-I"+str(ROOT / "proposals"), "-I"+str(ROOT / "runtime"),
                                 str(source), "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def fixture(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin"}, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_full_measured_metadata_order_aliases_and_export_callback(self): self.fixture("positive")
    def test_invalid_arguments_fail(self): self.fixture("arguments")
    def test_original_lazy_capture_requires_pre_binding_and_one_common_target(self):
        for mode in ("capture-after-bind", "capture-inconsistent", "capture-mismatch"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_mod0_bss_descriptor_bounds_and_freshness(self):
        for mode in ("bad-last-module", "descriptor-end", "descriptor-before-bss", "descriptor-nonzero", "bad-mod0", "truncated-dynamic"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_symbol_hash_and_raw_generated_metadata_are_validated(self):
        for mode in ("bad-hash-index", "hash-cycle", "symbol-count", "symbol-name"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_all_named_aliases_need_distinct_fresh_exported_object_storage(self):
        for mode in ("alias-type", "alias-local", "alias-nonzero", "overlapping-alias", "missing-alias"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_unsupported_tls_dynamic_flags_and_relocations_fail(self):
        for mode in ("tls", "unknown-tag", "unknown-flags", "bad-relr", "overlapping-modules"):
            with self.subTest(mode=mode): self.fixture(mode)


if __name__ == "__main__":
    unittest.main()
