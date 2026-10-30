"""Real native ectx:aw SM/CMIF lifetime tests; no guest or context-write fake."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeEctxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="castlevania-ectx-tests-")
        directory = Path(cls.work.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "ectx_host.c"
#define CMIF_IN_MAGIC 0x49434653u
#define CMIF_OUT_MAGIC 0x4f434653u
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void runtime_trace_guest(uint64_t fp,uint64_t lr){(void)fp;(void)lr;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
void fixture_dispatch(IpcSession *,uint32_t *);
void fixture_sm(const IpcRequest *,IpcResponse *);
unsigned fixture_registrations(void),fixture_live_allocations(void),fixture_domain_refs(IpcSession *);
int fixture_domain_has(IpcSession *,uint32_t);
static void need(int c,const char *why){if(!c)runtime_fail(why);}
static void close_handle(uint32_t h){uint64_t regs[32]={h};need(svc_thread(0x16,regs)&&!regs[0],"actual CloseHandle success");need(!runtime_handle_get(h,1),"closed slot reclaimed");}
static uint32_t open_service(void){
 const char name[8]="ectx:aw";IpcRequest q={.type=17,.cmd=1,.data=(const uint8_t *)name,.data_size=8};IpcResponse r={0};
 fixture_sm(&q,&r);need(!r.result&&r.nmove==1&&!r.ncopy&&!r.data_size,"SM real moved session");
 IpcSession *s=runtime_handle_get(r.move[0],1);need(s&&s->handler==ectx_service&&!s->state&&!s->domain&&!s->close,"real stateless ectx session");return r.move[0];
}
static void request(uint32_t *m,unsigned cmd,unsigned type,const void *data,unsigned size){
 memset(m,0,256);m[0]=type;m[1]=(8+16+size+16+3)/4;
 m[4]=CMIF_IN_MAGIC;m[6]=cmd;if(size)memcpy(m+8,data,size);
}
static void success(const uint32_t *m){need(m[4]==CMIF_OUT_MAGIC&&!m[6],"actual CMIF success header");}
static uint32_t control(IpcSession *s,uint32_t *m,unsigned cmd,unsigned type,const void *data,unsigned size){
 request(m,cmd,type,data,size);fixture_dispatch(s,m);success(m);
 if(cmd==0)return m[8];
 if(cmd==2||cmd==4||cmd==1){need((m[1]>>31)&&!((m[2]>>1)&15)&&((m[2]>>5)&15)==1,"control returns one MOVE");return m[3];}
 need(cmd==3&&(m[8]&0xffff)==0x8000,"real pointer buffer size");return 0;
}
static void domain_request(uint32_t *m,unsigned kind,unsigned id,unsigned cmd){
 memset(m,0,256);m[0]=6;m[1]=14;m[4]=kind|(kind==1?16u<<16:0);m[5]=id;
 if(kind==1){m[8]=CMIF_IN_MAGIC;m[10]=cmd;}
}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(fixture_registrations()==1&&!fixture_live_allocations(),"registration only before main");
 for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"constructor creates no handles/events");
 if(!strcmp(mode,"register"))return 0;
 uint32_t h=open_service();IpcSession *s=runtime_handle_get(h,1);_Alignas(16) uint32_t m[64];
 need(fixture_live_allocations()==1,"only one actual session allocation");
 if(!strcmp(mode,"open")){close_handle(h);need(!fixture_live_allocations(),"open/close frees session");return 0;}
 if(!strcmp(mode,"unknown")||!strcmp(mode,"unknown-zero")||!strcmp(mode,"tipc")){
  request(m,!strcmp(mode,"unknown")?999:0,!strcmp(mode,"tipc")?16:6,NULL,0);fixture_dispatch(s,m);return 4;
 }
 if(!strcmp(mode,"unknown-control")){request(m,99,5,NULL,0);fixture_dispatch(s,m);return 4;}
 if(!strcmp(mode,"non-domain-clone")){
  uint32_t c=control(s,m,2,5,NULL,0);IpcSession *copy=runtime_handle_get(c,1);need(copy&&copy!=s&&copy->handler==ectx_service,"independent clone session");
  close_handle(h);need(fixture_live_allocations()==1,"clone survives original close");control(copy,m,3,5,NULL,0);close_handle(c);need(!fixture_live_allocations(),"clone last close frees session");return 0;
 }
 uint32_t id=control(s,m,0,5,NULL,0);need(id==1&&fixture_domain_has(s,id)&&fixture_domain_refs(s)==1,"real ConvertToDomain root id1");
 need(fixture_live_allocations()==3,"transport, domain, root object allocations");
 if(!strcmp(mode,"domain")){control(s,m,3,7,NULL,0);close_handle(h);need(!fixture_live_allocations(),"last transport closes domain/root");return 0;}
 if(!strcmp(mode,"double-convert")){control(s,m,0,5,NULL,0);return 4;}
 if(!strcmp(mode,"domain-unknown")||!strcmp(mode,"domain-bad-id")){
  domain_request(m,1,!strcmp(mode,"domain-bad-id")?200:id,0);fixture_dispatch(s,m);return 4;
 }
 if(!strcmp(mode,"domain-close")){
  domain_request(m,2,id,0);fixture_dispatch(s,m);need(m[8]==CMIF_OUT_MAGIC&&!m[10]&&!fixture_domain_has(s,id),"domain root closed");
  need(fixture_live_allocations()==2,"root object freed before transport");control(s,m,3,5,NULL,0);close_handle(h);need(!fixture_live_allocations(),"domain transport closes cleanly");return 0;
 }
 if(!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-ex")){
  uint32_t tag=0x1234;unsigned cmd=!strcmp(mode,"domain-clone-ex")?4:2;
  uint32_t c=control(s,m,cmd,5,cmd==4?&tag:NULL,cmd==4?4:0);IpcSession *copy=runtime_handle_get(c,1);
  need(copy&&copy!=s&&copy->domain==s->domain&&fixture_domain_refs(copy)==2,"domain clone retains same domain");
  close_handle(h);need(fixture_live_allocations()==3&&fixture_domain_refs(copy)==1&&fixture_domain_has(copy,id),"clone keeps root alive");
  control(copy,m,3,5,NULL,0);close_handle(c);need(!fixture_live_allocations(),"last clone frees domain and object");return 0;
 }
 if(!strcmp(mode,"domain-copy")){
  uint32_t c=control(s,m,1,5,&id,4);IpcSession *copy=runtime_handle_get(c,1);need(copy&&!copy->domain&&copy->handler==ectx_service,"copied root is real independent session");
  close_handle(h);need(fixture_live_allocations()==1,"copy survives domain destruction");control(copy,m,3,5,NULL,0);close_handle(c);need(!fixture_live_allocations(),"copied session freed");return 0;
 }
 if(!strcmp(mode,"cycles")){
  close_handle(h);
  for(unsigned i=0;i<1000;i++){h=open_service();s=runtime_handle_get(h,1);control(s,m,0,5,NULL,0);uint32_t c=control(s,m,2,5,NULL,0);close_handle(h);close_handle(c);need(!fixture_live_allocations(),"no allocation leak across domain lifecycle");}
  for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all actual handle slots reclaimed");return 0;
 }
 return 5;
}
''')
        transport = directory / "transport.c"
        transport.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned live;
static void *tracked_calloc(size_t n,size_t size){
 void *p=calloc(n,size);if(!p)abort();for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;live++;return p;}abort();
}
static void tracked_free(void *p){
 if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;live--;free(p);return;}abort();
}
#define calloc tracked_calloc
#define free tracked_free
#include "ipc.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm(const IpcRequest *q,IpcResponse *r){sm(NULL,q,r);}
unsigned fixture_registrations(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"ectx:aw");return n;}
unsigned fixture_live_allocations(void){return live;}
unsigned fixture_domain_refs(IpcSession *s){return s->domain?s->domain->sessions:0;}
int fixture_domain_has(IpcSession *s,uint32_t id){return s->domain&&id<DOMAIN_OBJECTS&&s->domain->objects[id]!=NULL;}
''')
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                  "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
                  "-DGAME_CASTLEVANIA=1", "-I"+str(policy.ROOT / "runtime"),
                  "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"),
                  str(source), str(transport), "-Wl,-dead_strip"]
        cls.binary = directory / "ectx-native"
        cls.disabled = directory / "ectx-default-disabled"
        for defines, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.disabled)]:
            result = subprocess.run(common+defines+["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def fixture(self, mode, failure=None, no_run=False, disabled=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-ectx-run-") as directory:
            parent = Path(directory)
            binary = self.disabled if disabled else self.binary
            if no_run:
                result = subprocess.run([str(binary), mode], cwd=parent, env={"PATH": "/usr/bin:/bin"},
                                        capture_output=True, text=True, timeout=10)
                text = result.stderr
                self.assertEqual(list(parent.iterdir()), [])
            else:
                run = policy.create_run(parent);root=Path(run["root"])
                (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
                log=root/"logs/native-host.log";log.touch(mode=0o600)
                env=policy.child_environment(run);env["CASTLEVANIA_LOG_FILE"]=str(log)
                before={str(p.relative_to(root)) for p in root.rglob("*")}
                with log.open("ab") as stream:
                    result=subprocess.run([str(binary),mode],cwd=root,env=env,stdout=subprocess.PIPE,stderr=stream,timeout=10)
                text=log.read_text()
                self.assertEqual(before,{str(p.relative_to(root)) for p in root.rglob("*")},"adapter must not create context files/logs")
            if failure:
                self.assertNotEqual(result.returncode,0,text);self.assertIn(failure,text)
            else:
                self.assertEqual(result.returncode,0,text)

    def test_pre_main_only_registers_without_handles_allocations_or_io(self): self.fixture("register",no_run=True)
    def test_default_disabled_build_still_only_registers_before_main(self): self.fixture("register",no_run=True,disabled=True)
    def test_service_manager_returns_real_moved_session_then_frees_it(self): self.fixture("open")
    def test_open_requires_checked_host_run(self): self.fixture("open","run root",no_run=True)
    def test_default_compile_gate_prevents_service_open(self): self.fixture("open","disabled at compile time",disabled=True)
    def test_real_convert_domain_and_last_close_free_all_transport_allocations(self): self.fixture("domain")
    def test_domain_object_close_releases_root_before_transport(self): self.fixture("domain-close")
    def test_non_domain_clone_survives_original_close(self): self.fixture("non-domain-clone")
    def test_domain_clone_retains_root_until_last_transport_close(self): self.fixture("domain-clone")
    def test_domain_clone_ex_keeps_same_ownership(self): self.fixture("domain-clone-ex")
    def test_copy_from_domain_survives_domain_destruction(self): self.fixture("domain-copy")
    def test_1000_domain_clone_close_cycles_leak_no_allocations_or_handles(self): self.fixture("cycles")
    def test_no_ectx_service_command_fabricates_success(self):
        for mode in ("unknown-zero","unknown","tipc","domain-unknown"):
            with self.subTest(mode=mode):self.fixture(mode,"ectx:aw: command")
    def test_unknown_control_is_not_a_service_command(self): self.fixture("unknown-control","control command 99 not implemented")
    def test_double_domain_conversion_rejected(self): self.fixture("double-convert","already a domain")
    def test_invalid_domain_object_is_rejected(self): self.fixture("domain-bad-id","domain object")


if __name__ == "__main__":
    unittest.main()
