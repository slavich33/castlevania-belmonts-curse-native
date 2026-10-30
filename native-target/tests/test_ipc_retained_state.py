"""Native generic CMIF ownership tests using actual ipc.c/threads.c.

Fixtures own tiny host state only. No SDK, guest instructions, GPU or assets.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RetainedIpcStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="castlevania-ipc-retained-")
        directory = Path(cls.work.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#define CMIF_IN_MAGIC 0x49434653u
#define CMIF_OUT_MAGIC 0x4f434653u
void fixture_dispatch(IpcSession *,uint32_t *);
void fixture_sm(IpcSession *,const IpcRequest *,IpcResponse *);
unsigned fixture_transport_live(void);
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void runtime_trace_guest(uint64_t fp,uint64_t lr){(void)fp;(void)lr;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
static void need(int c,const char *why){if(!c)runtime_fail(why);}
typedef struct {unsigned refs,identity,magic;} State;
static unsigned opened,live,retains,releases,destroyed,calls;
static void *state_open(void){State *s=calloc(1,sizeof *s);need(s!=NULL,"state allocation");s->refs=1;s->identity=++opened;s->magic=0x1a2b3c4d;live++;return s;}
static void state_retain(void *p){State *s=p;need(s&&s->magic==0x1a2b3c4d&&s->refs,"retain live state");s->refs++;retains++;}
static void state_close(void *p){State *s=p;need(s&&s->magic==0x1a2b3c4d&&s->refs,"release live state once");releases++;if(!--s->refs){s->magic=0;live--;destroyed++;free(s);}}
static void service(IpcSession *s,const IpcRequest *q,IpcResponse *r){
 State *state=s->state;need(state&&state->magic==0x1a2b3c4d&&state->refs,"handler only sees live state");
 if(q->cmd)ipc_unimplemented(s,q);calls++;IPC_OUT(r,state->identity);
}
static void message(uint32_t *m,unsigned type,unsigned cmd,const void *data,unsigned size){
 memset(m,0,256);m[0]=type;m[1]=(8+16+size+3)/4;m[4]=CMIF_IN_MAGIC;m[6]=cmd;if(size)memcpy(m+8,data,size);
}
static void success(uint32_t *m){need(m[4]==CMIF_OUT_MAGIC&&!m[6],"real CMIF success");}
static IpcSession *session(uint32_t h){IpcSession *s=runtime_handle_get(h,1);need(s!=NULL,"real session handle");return s;}
static uint32_t open_service(const char *name){
 _Alignas(16) uint32_t m[64];char name8[8]={0};memcpy(name8,name,strlen(name));
 IpcSession manager={.name="sm:",.handler=fixture_sm};message(m,6,1,name8,8);fixture_dispatch(&manager,m);success(m);
 need(m[1]>>31&&((m[2]>>5)&15)==1,"SM returns one MOVE");return m[3];
}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");need(!runtime_handle_get(h,1),"closed handle removed");}
static uint32_t control(uint32_t h,unsigned cmd,uint32_t input){
 _Alignas(16) uint32_t m[64];message(m,5,cmd,(cmd==1||cmd==4)?&input:NULL,(cmd==1||cmd==4)?4:0);fixture_dispatch(session(h),m);success(m);
 if(cmd==0)return m[8];need((m[1]>>31)&&((m[2]>>5)&15)==1,"control returns one MOVE");return m[3];
}
static void call(uint32_t h,unsigned id,unsigned identity){
 _Alignas(16) uint32_t m[64];if(id){memset(m,0,256);m[0]=6;m[1]=14;m[4]=1|(16u<<16);m[5]=id;m[8]=CMIF_IN_MAGIC;}
 else message(m,6,0,NULL,0);
 fixture_dispatch(session(h),m);need(m[id?8:4]==CMIF_OUT_MAGIC&&!m[id?10:6]&&m[id?12:8]==identity,"handler survives through actual CMIF");
}
static void close_object(uint32_t h,unsigned id){
 _Alignas(16) uint32_t m[64];memset(m,0,sizeof m);m[0]=6;m[1]=10;m[4]=2;m[5]=id;fixture_dispatch(session(h),m);
 need(m[8]==CMIF_OUT_MAGIC&&!m[10],"actual domain object close");
}
static void clear(void){
 need(!live&&destroyed==opened&&!fixture_transport_live(),"all state and transport allocations freed");
 for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all real handle slots reclaimed");
}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 if(!strcmp(mode,"missing-retain")){runtime_ipc_register_retained("bad",service,state_open,NULL,state_close);return 5;}
 if(!strcmp(mode,"missing-close")){runtime_ipc_register_retained("bad",service,state_open,state_retain,NULL);return 5;}
 runtime_ipc_register_retained("owned",service,state_open,state_retain,state_close);
 runtime_ipc_register("legacy",service,state_open,state_close);
 need(!opened&&!fixture_transport_live(),"registration performs no opens or allocation");
 if(!strcmp(mode,"registration"))return 0;
 uint32_t h=open_service(!strcmp(mode,"legacy")?"legacy":"owned");
 need(opened==1&&live==1&&fixture_transport_live()==1,"open owns one state and transport");
 if(!strcmp(mode,"legacy")){
  uint32_t c=control(h,2,0);need(!session(h)->retain&&!session(c)->retain&&!session(c)->close,"legacy clone remains borrowed");
  call(c,0,1);close_handle(c);need(!releases&&live==1,"legacy clone close does not release borrowed state");close_handle(h);clear();return 0;
 }
 need(session(h)->retain==state_retain&&session(h)->close==state_close,"registry propagates retained hooks");
 if(!strcmp(mode,"open-close")){call(h,0,1);close_handle(h);need(!retains&&releases==1,"first owner released once");clear();return 0;}
 if(!strcmp(mode,"independent")){
  uint32_t second=open_service("owned");need(session(second)->state!=session(h)->state,"independent open gets independent state");
  call(h,0,1);call(second,0,2);close_handle(h);call(second,0,2);close_handle(second);need(!retains&&releases==2,"two first owners released");clear();return 0;
 }
 if(!strcmp(mode,"clone-original-first")||!strcmp(mode,"clone-copy-first")||!strcmp(mode,"clone-ex")){
  uint32_t c=control(h,!strcmp(mode,"clone-ex")?4:2,77);need(retains==1&&session(c)->state==session(h)->state&&session(c)->retain==state_retain&&session(c)->close==state_close,"independent clone owns retained reference");
  if(!strcmp(mode,"clone-copy-first")){close_handle(c);need(live==1&&releases==1,"original retained after clone close");call(h,0,1);close_handle(h);}
  else {close_handle(h);need(live==1&&releases==1,"clone retained after original close");call(c,0,1);close_handle(c);}
  need(releases==2&&destroyed==1,"last owner destroys once");clear();return 0;
 }
 uint32_t id=control(h,0,0);need(id==1&&!retains&&!session(h)->close&&!session(h)->retain,"conversion transfers ownership and clears transport hooks");
 if(!strcmp(mode,"convert")){call(h,id,1);close_handle(h);need(releases==1,"domain root is sole owner");clear();return 0;}
 if(!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-reverse")){
  uint32_t c=control(h,2,0);need(!retains&&!session(c)->close&&!session(c)->retain,"domain transport clone only retains domain");
  if(!strcmp(mode,"domain-clone")){close_handle(h);need(!releases&&live==1,"domain clone preserves root");call(c,id,1);close_handle(c);}
  else {close_handle(c);need(!releases&&live==1,"original domain preserves root");call(h,id,1);close_handle(h);}
  need(releases==1,"domain root closes exactly once");clear();return 0;
 }
 uint32_t c=control(h,1,id);need(retains==1&&session(c)->retain==state_retain&&session(c)->close==state_close&&!session(c)->domain,"CopyFromDomain owns independent reference");
 if(!strcmp(mode,"copy-survives-domain")){close_handle(h);need(live==1&&releases==1,"copy survives entire domain destruction");call(c,0,1);close_handle(c);}
 else if(!strcmp(mode,"copy-close-first")){close_handle(c);need(live==1&&releases==1,"domain survives copy close");call(h,id,1);close_handle(h);}
 else if(!strcmp(mode,"object-close")){close_object(h,id);need(live==1&&releases==1,"copy survives explicit root-object close");call(c,0,1);close_handle(h);need(releases==1,"transport adds no state release");close_handle(c);}
 else if(!strcmp(mode,"mixed-domains")){
  uint32_t did=control(c,0,0);uint32_t transport=control(h,2,0);uint32_t second=control(c,1,did);
  need(retains==2,"only independent owners retain, conversions and domain clones do not");
  close_object(h,id);close_handle(h);close_handle(transport);need(live==1&&releases==1,"second domain and copy keep state alive");
  call(c,did,1);close_handle(c);need(live==1&&releases==2,"last independent copy remains");call(second,0,1);close_handle(second);
 }
 else return 5;
 need(destroyed==1&&releases==retains+1,"every real owner releases once, final release destroys once");clear();return 0;
}
''')
        transport = directory / "transport.c"
        transport.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned transport_live;
static void *tracked_calloc(size_t n,size_t size){
 void *p=calloc(n,size);if(!p)abort();
 for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;transport_live++;return p;}abort();
}
static void tracked_free(void *p){
 if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;transport_live--;free(p);return;}abort();
}
#define calloc tracked_calloc
#define free tracked_free
#include "ipc.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm(IpcSession *s,const IpcRequest *q,IpcResponse *r){sm(s,q,r);}
unsigned fixture_transport_live(void){return transport_live;}
''')
        cls.binary = directory / "ipc-retained-native"
        result = subprocess.run(
            ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
             "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
             "-DGAME_CASTLEVANIA=1", "-I"+str(ROOT / "runtime"),
             "-I"+str(ROOT / "third_party/d2r_gfx/gfx/nvn/include"),
             str(source), str(transport), "-Wl,-dead_strip", "-o", str(cls.binary)],
            capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def fixture(self, mode, failure=None):
        result = subprocess.run([str(self.binary), mode], capture_output=True,
                                text=True, env={"PATH": "/usr/bin:/bin"}, timeout=5)
        if failure:
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn(failure, result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_registration_does_not_open_or_allocate(self): self.fixture("registration")
    def test_initial_owner_opens_and_releases_once(self): self.fixture("open-close")
    def test_separate_service_opens_do_not_share_state(self): self.fixture("independent")
    def test_clone_survives_original_close(self): self.fixture("clone-original-first")
    def test_original_survives_clone_close(self): self.fixture("clone-copy-first")
    def test_clone_ex_owns_a_reference(self): self.fixture("clone-ex")
    def test_domain_conversion_transfers_reference(self): self.fixture("convert")
    def test_domain_clone_keeps_root_until_last_transport_close(self): self.fixture("domain-clone")
    def test_domain_clone_reverse_close_order(self): self.fixture("domain-clone-reverse")
    def test_copy_from_domain_survives_full_domain_destruction(self): self.fixture("copy-survives-domain")
    def test_domain_survives_copied_session_close(self): self.fixture("copy-close-first")
    def test_copy_survives_explicit_domain_object_close(self): self.fixture("object-close")
    def test_independent_domains_and_copy_release_exactly_once(self): self.fixture("mixed-domains")
    def test_legacy_borrowed_clone_behavior_is_unchanged(self): self.fixture("legacy")
    def test_retained_api_requires_both_lifetime_hooks(self):
        for mode in ("missing-retain", "missing-close"):
            with self.subTest(mode=mode): self.fixture(mode, "requires retain and close")


if __name__ == "__main__":
    unittest.main()
