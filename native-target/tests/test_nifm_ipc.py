"""Actual native CMIF factory/domain lifetime tests; no network/guest execution."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeNifmIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-nifm-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "nifm_host.c"
void fixture_dispatch(IpcSession *,uint32_t *);
void fixture_sm_dispatch(uint32_t *);
unsigned fixture_registrations(void),fixture_ipc_live(void),fixture_domain_refs(IpcSession *);
#define CMIF_IN_MAGIC 0x49434653u
#define CMIF_OUT_MAGIC 0x4f434653u
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void runtime_trace_guest(uint64_t f,uint64_t l){(void)f;(void)l;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
static void need(int ok,const char *why){if(!ok)runtime_fail(why);}
static thr_t main_thread;
static uint64_t wire_pid;
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,unsigned ncopy,unsigned nmove,
                    const void *data,unsigned size,unsigned buffer){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid||ncopy||nmove){m[1]=1u<<31;*p++=(pid?1u:0u)|(ncopy<<1)|(nmove<<5);
  if(pid){memcpy(p,&wire_pid,8);p+=2;}for(unsigned i=0;i<ncopy+nmove;i++)*p++=0xffff8001u;
 }
 if(buffer&&buffer<=4){m[0]|=1u<<(12+buffer*4);p+=buffer==1?2:3;}
 uint8_t *words=(uint8_t *)p,*payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t header[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,header,16);payload+=16;
 if(size)memcpy(payload,data,size);memset(payload+size,0xa5,16);
 m[1]|=(unsigned)(payload+size+16-words+3)/4;if(buffer==5)m[1]|=2u<<10;
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("missing CMIF response");}
static uint32_t result(uint32_t *m){return response(m)[2];}
static IpcSession *session(uint32_t h){IpcSession *s=runtime_handle_get(h,1);need(s!=NULL,"live actual session handle");return s;}
static uint32_t moved(uint32_t *m){need((m[1]>>31)&&!((m[2]>>1)&15)&&((m[2]>>5)&15)==1,"one real MOVE session");(void)session(m[3]);return m[3];}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0]&&!runtime_handle_get(h,1),"actual CloseHandle");}
static uint32_t open_factory(uint32_t *m,const char *name){
 char service[8]={0};memcpy(service,name,strlen(name));request(m,6,0,1,0,0,0,service,8,0);fixture_sm_dispatch(m);need(!result(m),"SM success");
 uint32_t h=moved(m);IpcSession *s=session(h);need(s->handler==nifm_factory&&!s->state&&!s->close&&!s->retain&&!s->domain,"real stateless user factory");return h;
}
static uint32_t control(uint32_t h,uint32_t *m,unsigned cmd,const void *data,unsigned size){
 request(m,5,0,cmd,0,0,0,data,size,0);fixture_dispatch(session(h),m);need(!result(m),"actual control success");
 if(cmd==0||cmd==3)return response(m)[4];return moved(m);
}
static uint32_t create(uint32_t h,uint32_t *m,unsigned object,unsigned type){
 uint64_t reserved=0;request(m,type,object,5,1,0,0,&reserved,8,0);fixture_dispatch(session(h),m);need(!result(m),"CreateGeneralService success");
 if(object){need(!(m[1]>>31)&&response(m)[-4]==1,"one real domain object, no handles");unsigned id=response(m)[4];need(id>1,"child id distinct from factory");return id;}
 uint32_t child=moved(m);IpcSession *s=session(child);need(s->handler==nifm_general&&!s->state&&!s->close&&!s->retain,"real stateless GeneralService");return child;
}
static void clean(void){need(!fixture_ipc_live(),"all tracked IPC transport/object allocations freed");for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all handle slots reclaimed");}
static void domain_close(uint32_t h,uint32_t *m,unsigned id){memset(m,0,256);m[0]=6;m[1]=12;m[4]=2;m[5]=id;fixture_dispatch(session(h),m);need(!result(m),"domain object close");}
int main(int argc,char **argv){
 need(argc==2,"mode");const char *mode=argv[1];need(fixture_registrations()==1&&!fixture_ipc_live(),"premain registration only");
 if(!strcmp(mode,"register")){clean();return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];uint32_t h=open_factory(m,!strcmp(mode,"admin")?"nifm:a":!strcmp(mode,"system")?"nifm:s":"nifm:u");
 if(!strcmp(mode,"open")){close_handle(h);clean();return 0;}
 if(!strcmp(mode,"factory-clone")){uint32_t copy=control(h,m,2,NULL,0);close_handle(h);h=copy;}
 if(!strcmp(mode,"domain")||!strcmp(mode,"domain-copy")||!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-ex")||
    !strcmp(mode,"domain-child-close")||!strcmp(mode,"domain-unknown")||!strcmp(mode,"truncated")||!strcmp(mode,"oversized")){
  unsigned root=control(h,m,0,NULL,0);need(root==1&&fixture_ipc_live()==3,"domain root and transport allocated");
  if(!strcmp(mode,"truncated")||!strcmp(mode,"oversized")){
   uint64_t raw[4]={0};request(m,6,root,5,1,0,0,raw,!strcmp(mode,"truncated")?7:29,0);fixture_dispatch(session(h),m);return 4;
  }
  unsigned child=create(h,m,root,6);need(fixture_ipc_live()==4,"factory and child domain objects are real");
  if(!strcmp(mode,"domain-unknown")){request(m,6,child,18,0,0,0,NULL,0,0);fixture_dispatch(session(h),m);return 4;}
  if(!strcmp(mode,"domain-copy")){
   uint32_t copy=control(h,m,1,&child,4);need(session(copy)->handler==nifm_general,"CopyFromDomain copies child");close_handle(h);
   need(fixture_ipc_live()==1&&control(copy,m,3,NULL,0)==0x8000,"copy outlives entire factory/domain");close_handle(copy);clean();return 0;
  }
  if(!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-ex")){
   unsigned cmd=!strcmp(mode,"domain-clone-ex")?4:2;uint32_t tag=123;uint32_t copy=control(h,m,cmd,cmd==4?&tag:NULL,cmd==4?4:0);
   need(session(copy)->domain==session(h)->domain&&fixture_domain_refs(session(copy))==2,"domain lifetime retained by clone");
   close_handle(h);need(fixture_ipc_live()==4&&fixture_domain_refs(session(copy))==1,"clone keeps original objects alive");close_handle(copy);clean();return 0;
  }
  if(!strcmp(mode,"domain-child-close")){
   domain_close(h,m,child);need(fixture_ipc_live()==3,"child freed independently of factory");(void)create(h,m,root,6);need(fixture_ipc_live()==4,"factory creates new real child after previous close");
  }
  close_handle(h);clean();return 0;
 }
 if(!strcmp(mode,"cycles")){
  close_handle(h);clean();for(unsigned i=0;i<1000;i++){
   h=open_factory(m,"nifm:u");unsigned root=control(h,m,0,NULL,0),child=create(h,m,root,6);uint32_t tag=i;
   uint32_t clone=control(h,m,4,&tag,4),copy=control(h,m,1,&child,4);close_handle(h);close_handle(clone);
   need(fixture_ipc_live()==1&&control(copy,m,3,NULL,0)==0x8000,"independent child copy survives last domain transport");close_handle(copy);clean();
  }return 0;
 }
 if(!strcmp(mode,"factory-unknown")||!strcmp(mode,"legacy")){request(m,6,0,!strcmp(mode,"legacy")?4:999,0,0,0,NULL,0,0);fixture_dispatch(session(h),m);return 4;}
 if(!strcmp(mode,"missing-pid")||!strcmp(mode,"copy-handle")||!strcmp(mode,"move-handle")||!strcmp(mode,"reserved")||
    !strcmp(mode,"x-buffer")||!strcmp(mode,"a-buffer")||!strcmp(mode,"b-buffer")||!strcmp(mode,"w-buffer")||!strcmp(mode,"c-buffer")||!strcmp(mode,"tipc")){
  uint64_t reserved=!strcmp(mode,"reserved");unsigned buffer=!strcmp(mode,"x-buffer")?1:!strcmp(mode,"a-buffer")?2:!strcmp(mode,"b-buffer")?3:!strcmp(mode,"w-buffer")?4:!strcmp(mode,"c-buffer")?5:0;
  request(m,!strcmp(mode,"tipc")?21:6,0,5,strcmp(mode,"missing-pid")!=0,!strcmp(mode,"copy-handle"),!strcmp(mode,"move-handle"),&reserved,8,buffer);fixture_dispatch(session(h),m);return 4;
 }
 if(!strcmp(mode,"wire-pid"))wire_pid=UINT64_MAX;
 uint32_t child=create(h,m,0,!strcmp(mode,"type4")?4:6);
 if(!strcmp(mode,"two-children")){
  uint32_t second=create(h,m,0,6);need(child!=second&&session(child)!=session(second),"independent real child sessions");close_handle(child);need(control(second,m,3,NULL,0)==0x8000,"other child survives sibling close");close_handle(second);close_handle(h);clean();return 0;
 }
 if(!strcmp(mode,"child-clone")){
  uint32_t copy=control(child,m,2,NULL,0);need(session(copy)!=session(child)&&session(copy)->handler==nifm_general,"independent clone transport");close_handle(child);child=copy;
 }
 if(!strcmp(mode,"child-domain")){
  unsigned id=control(child,m,0,NULL,0);need(id==1,"independent child conversion");uint32_t copy=control(child,m,2,NULL,0);close_handle(child);close_handle(h);
  need(control(copy,m,3,NULL,0)==0x8000,"child domain clone independent of factory");close_handle(copy);clean();return 0;
 }
 close_handle(h);need(fixture_ipc_live()==1,"child independent of closed factory");
 if(!strcmp(mode,"client-id")||!strcmp(mode,"ip")||!strcmp(mode,"status")||!strcmp(mode,"request")||!strcmp(mode,"general-unknown")){
  unsigned cmd=!strcmp(mode,"client-id")?1:!strcmp(mode,"ip")?12:!strcmp(mode,"status")?18:!strcmp(mode,"request")?4:999;
  request(m,6,0,cmd,0,0,0,NULL,0,0);fixture_dispatch(session(child),m);return 4;
 }
 need(control(child,m,3,NULL,0)==0x8000,"real child control after factory close, without network RPC");close_handle(child);clean();return 0;
}
''')
        transport = directory / "transport.c"
        transport.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned live;
static void *ipc_test_calloc(size_t n,size_t size){void *p=calloc(n,size);if(!p)abort();for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;live++;return p;}abort();}
static void ipc_test_free(void *p){if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;live--;free(p);return;}abort();}
#define calloc ipc_test_calloc
#define free ipc_test_free
#include "ipc.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm_dispatch(uint32_t *m){IpcSession s={.name="sm:",.handler=sm};dispatch(&s,m);}
unsigned fixture_registrations(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"nifm:u");return n;}
unsigned fixture_ipc_live(void){return live;}
unsigned fixture_domain_refs(IpcSession *s){return s->domain?s->domain->sessions:0;}
''')
        cls.binary = directory / "nifm-native"
        cls.disabled = directory / "nifm-disabled"
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra",
                  "-Werror", "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1", "-I" + str(policy.ROOT / "runtime"),
                  "-I" + str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), str(source), str(transport), "-Wl,-dead_strip"]
        for defines, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.disabled)]:
            result = subprocess.run(common + defines + ["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, failure=None, no_run=False, disabled=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-nifm-run-") as directory:
            binary = self.disabled if disabled else self.binary
            if no_run:
                result = subprocess.run([str(binary), mode], cwd=directory, env={"PATH": "/usr/bin:/bin"},
                                        capture_output=True, text=True, timeout=15)
                text = result.stderr
                self.assertEqual(list(Path(directory).iterdir()), [])
            else:
                run = policy.create_run(Path(directory));root = Path(run["root"])
                (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
                log = root / "logs/native-host.log";log.touch(mode=0o600)
                env = policy.child_environment(run);env["CASTLEVANIA_LOG_FILE"] = str(log)
                before = {str(p.relative_to(root)) for p in root.rglob("*")}
                with log.open("ab") as stream:
                    result = subprocess.run([str(binary), mode], cwd=root, env=env,
                                            stdout=subprocess.PIPE, stderr=stream, timeout=15)
                text = log.read_text()
                self.assertEqual(before, {str(p.relative_to(root)) for p in root.rglob("*")}, "no network/profile/config files created")
            if failure:
                self.assertNotEqual(result.returncode, 0, text);self.assertIn(failure, text)
            else:
                self.assertEqual(result.returncode, 0, text)
            return text

    def test_constructor_only_registers_without_allocations_handles_or_io(self): self.fixture("register", no_run=True)
    def test_default_disabled_constructor_still_only_registers(self): self.fixture("register", no_run=True, disabled=True)
    def test_open_close_allocates_and_frees_actual_factory_session(self): self.fixture("open")
    def test_factory_returns_real_moved_general_session_independent_of_parent(self): self.fixture("create")
    def test_type4_cmif_factory_is_supported(self): self.fixture("type4")
    def test_wire_pid_does_not_fabricate_a_network_identity(self): self.fixture("wire-pid")
    def test_independent_children_keep_distinct_real_sessions(self): self.fixture("two-children")
    def test_cloned_factory_survives_original_close_and_can_create_child(self): self.fixture("factory-clone")
    def test_child_clone_survives_original_and_factory_close(self): self.fixture("child-clone")
    def test_child_domain_clone_survives_original_child_and_factory_close(self): self.fixture("child-domain")
    def test_actual_domain_factory_returns_one_object_and_closes_all(self): self.fixture("domain")
    def test_domain_child_copy_survives_entire_factory_domain_destruction(self): self.fixture("domain-copy")
    def test_domain_clone_retains_real_root_and_children_until_last_close(self): self.fixture("domain-clone")
    def test_domain_clone_ex_has_same_real_object_lifetime(self): self.fixture("domain-clone-ex")
    def test_domain_child_can_close_without_destroying_factory(self): self.fixture("domain-child-close")
    def test_1000_open_domain_create_clone_copy_close_cycles_leave_no_allocations_or_handles(self): self.fixture("cycles")
    def test_only_measured_user_endpoint_is_registered(self):
        for mode in ("admin", "system"):
            with self.subTest(mode=mode): self.fixture(mode, "service not implemented")
    def test_legacy_or_unknown_factory_command_is_not_accepted(self):
        for mode in ("legacy", "factory-unknown"):
            with self.subTest(mode=mode): self.fixture(mode, "nifm:u: command")
    def test_pid_and_handle_shape_is_required(self):
        for mode in ("missing-pid", "copy-handle", "move-handle"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_reserved_zero_is_required(self): self.fixture("reserved", "reserved argument must be zero")
    def test_all_buffer_families_and_unmeasured_tipc_fail(self):
        for mode in ("x-buffer", "a-buffer", "b-buffer", "w-buffer", "c-buffer", "tipc"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_truncated_or_oversized_domain_raw_input_fails(self):
        for mode in ("truncated", "oversized"):
            with self.subTest(mode=mode): self.fixture(mode, "argument size")
    def test_no_identity_ip_connectivity_or_request_result_is_fabricated(self):
        for mode in ("client-id", "ip", "status", "request", "general-unknown", "domain-unknown"):
            with self.subTest(mode=mode):
                text = self.fixture(mode, "nifm:IGeneralService: command")
                self.assertIn("Horizon network bridge is unimplemented", text)
    def test_checked_host_run_is_required_before_open(self): self.fixture("open", "run root", no_run=True)
    def test_compile_default_gate_prevents_open(self): self.fixture("open", "disabled at compile time", disabled=True)


if __name__ == "__main__":
    unittest.main()
