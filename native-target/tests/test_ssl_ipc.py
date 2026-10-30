"""Real SM/CMIF/domain/retained SSL interface-state tests; no TLS or guest I/O."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


FIXTURE = r'''
#include "threads.c"
static unsigned ssl_live;
static void *ssl_calloc(size_t n,size_t s){void *p=calloc(n,s);if(p)ssl_live++;return p;}
static void ssl_free(void *p){if(p){if(!ssl_live)abort();ssl_live--;free(p);}}
#define calloc ssl_calloc
#define free ssl_free
#include "ssl_host.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession*,uint32_t*),fixture_sm_dispatch(uint32_t*);
unsigned fixture_registrations(void),fixture_ipc_live(void);
#define CMIF_IN_MAGIC 0x49434653u
#define CMIF_OUT_MAGIC 0x4f434653u
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void runtime_trace_guest(uint64_t f,uint64_t l){(void)f;(void)l;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void*)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
static void need(int ok,const char *m){if(!ok)runtime_fail(m);}
static IpcSession *session(uint32_t h){IpcSession *s=runtime_handle_get(h,1);need(s!=NULL,"real session handle");return s;}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("CMIF response missing");}
static void success(uint32_t *m){need(!response(m)[2],"Result success");}
static uint32_t moved(uint32_t *m){need((m[1]>>31)&&!((m[2]>>1)&15)&&((m[2]>>5)&15)==1,"one actual MOVE handle");(void)session(m[3]);return m[3];}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0]&&!runtime_handle_get(h,1),"actual CloseHandle");}
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,unsigned copies,unsigned moves,
                    const void *data,unsigned size,unsigned buffer,unsigned slack){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid||copies||moves){m[1]=1u<<31;*p++=(pid?1u:0u)|(copies<<1)|(moves<<5);if(pid)p+=2;
  for(unsigned i=0;i<copies+moves;i++)*p++=0xffff8001;}
 if(buffer&&buffer<=4){m[0]|=1u<<(12+buffer*4);p+=buffer==1?2:3;}
 uint8_t *words=(void*)p,*payload=(void*)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t header[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,header,16);payload+=16;
 if(size)memcpy(payload,data,size);memset(payload+size,0xa5,slack);
 m[1]|=(unsigned)(payload+size+slack-words+3)/4;
 if(buffer==5)m[1]|=2u<<10;
}
static uint32_t open_ssl(uint32_t *m){
 const char name[8]="ssl:s";request(m,6,0,1,0,0,0,name,8,0,16);fixture_sm_dispatch(m);success(m);uint32_t h=moved(m);
 IpcSession *s=session(h);SslManager *state=s->state;
 need(s->handler==ssl_service&&s->retain==ssl_retain&&s->close==ssl_close&&state&&state->references==1&&!state->interface_version,"real independent retained manager starts undeclared");return h;
}
static uint32_t control(uint32_t h,uint32_t *m,unsigned cmd,const void *data,unsigned size){
 request(m,5,0,cmd,0,0,0,data,size,0,16);fixture_dispatch(session(h),m);success(m);return cmd==0?response(m)[4]:moved(m);
}
static void declare(uint32_t h,uint32_t *m,unsigned object,uint32_t version){
 request(m,6,object,5,0,0,0,&version,4,0,object?16:0);fixture_dispatch(session(h),m);success(m);
 need(!(m[1]>>31)&&!m[0],"version declaration returns no handles or buffers");
 if(object)need(!response(m)[-4],"no output domain object");
 for(unsigned i=4;i<12;i++)need(response(m)[i]==0,"no fabricated raw response payload");
}
static void domain_close(uint32_t h,uint32_t *m,unsigned object){
 memset(m,0,256);m[0]=6;m[1]=10;m[4]=2;m[5]=object;fixture_dispatch(session(h),m);success(m);
}
static void clean(void){need(!ssl_live&&!fixture_ipc_live(),"all actual manager/IPC allocations reclaimed");for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all actual handle slots reclaimed");}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(fixture_registrations()==1&&!ssl_live&&!fixture_ipc_live(),"constructor only registers ssl:s");
 for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"constructor creates no handles");
 if(!strcmp(mode,"register"))return 0;
 _Alignas(16) uint32_t m[64];
 if(!strcmp(mode,"fallback-endpoint")){const char name[8]="ssl";request(m,6,0,1,0,0,0,name,8,0,16);fixture_sm_dispatch(m);return 4;}
 uint32_t h=open_ssl(m);IpcSession *s=session(h);SslManager *state=s->state;
 need(ssl_live==1&&fixture_ipc_live()==1,"one real manager plus session");
 if(!strcmp(mode,"open")){close_handle(h);clean();return 0;}
 if(!strcmp(mode,"plain-exact")){declare(h,m,0,3);need(state->interface_version==3,"actual state stores declared interface version");close_handle(h);clean();return 0;}
 if(!strcmp(mode,"ordinary-type4")){uint32_t version=3;request(m,4,0,5,0,0,0,&version,4,0,0);fixture_dispatch(s,m);return 4;}
 if(!strcmp(mode,"tipc")){memset(m,0,256);m[0]=21;m[1]=1;m[2]=3;fixture_dispatch(s,m);return 4;}
 if(!strcmp(mode,"unknown-control")){request(m,5,0,5,0,0,0,NULL,0,0,16);fixture_dispatch(s,m);return 4;}
 if(!strcmp(mode,"independent")){
  uint32_t other=open_ssl(m);SslManager *second=session(other)->state;need(second!=state,"independent manager identity");
  declare(h,m,0,3);need(state->interface_version==3&&!second->interface_version,"separate SM open does not inherit declaration");
  close_handle(h);declare(other,m,0,3);close_handle(other);clean();return 0;
 }
 if(!strcmp(mode,"clone-before")||!strcmp(mode,"clone-after")){
  if(!strcmp(mode,"clone-after"))declare(h,m,0,3);
  uint32_t c=control(h,m,2,NULL,0);need(session(c)->state==state&&state->references==2,"clone retains shared manager");
  declare(c,m,0,3);need(state->interface_version==3,"clone state persists declaration");close_handle(h);
  need(ssl_live==1&&state->references==1,"clone keeps state after original close");declare(c,m,0,3);close_handle(c);clean();return 0;
 }
 uint32_t id=control(h,m,0,NULL,0);need(id==1&&state->references==1,"domain conversion transfers owned manager");
 if(!strcmp(mode,"domain")||!strcmp(mode,"repeat")){
  declare(h,m,id,3);need(state->interface_version==3,"measured domain declaration persists");
  if(!strcmp(mode,"repeat"))for(unsigned i=0;i<100;i++)declare(h,m,id,3);
  need(ssl_live==1&&state->references==1,"repeat has no state/reference growth");close_handle(h);clean();return 0;
 }
 if(!strcmp(mode,"domain-root-close")){declare(h,m,id,3);domain_close(h,m,id);need(!ssl_live&&fixture_ipc_live()==2,"root close releases manager before transport");close_handle(h);clean();return 0;}
 if(!strcmp(mode,"domain-clone")||!strcmp(mode,"clone-ex")){
  declare(h,m,id,3);uint32_t tag=0x1234;unsigned cmd=!strcmp(mode,"clone-ex")?4:2;
  uint32_t c=control(h,m,cmd,cmd==4?&tag:NULL,cmd==4?4:0);need(session(c)->domain==s->domain&&state->references==1,"domain clone owns domain only");
  close_handle(h);declare(c,m,id,3);close_handle(c);clean();return 0;
 }
 if(!strcmp(mode,"domain-copy")||!strcmp(mode,"copy-root-close")){
  uint32_t c=control(h,m,1,&id,4);need(session(c)->state==state&&state->references==2&&!session(c)->domain,"CopyFromDomain retains real manager");
  if(!strcmp(mode,"copy-root-close")){domain_close(h,m,id);need(state->references==1,"copy outlives domain root");}
  close_handle(h);need(state->references==1,"copy survives whole original domain");declare(c,m,0,3);close_handle(c);clean();return 0;
 }
 if(!strcmp(mode,"cycles")){
  close_handle(h);clean();
  for(unsigned i=0;i<1000;i++){
   h=open_ssl(m);id=control(h,m,0,NULL,0);declare(h,m,id,3);uint32_t c=control(h,m,1,&id,4),d=control(h,m,2,NULL,0);
   close_handle(h);close_handle(d);declare(c,m,0,3);close_handle(c);clean();
  }return 0;
 }
 uint32_t data[8]={3};unsigned type=6,size=4,cmd=5,buffer=0,copies=0,moves=0;int pid=0;
 if(!strcmp(mode,"version0"))data[0]=0;
 else if(!strcmp(mode,"version1"))data[0]=1;
 else if(!strcmp(mode,"version2"))data[0]=2;
 else if(!strcmp(mode,"version4"))data[0]=4;
 else if(!strcmp(mode,"version-max"))data[0]=UINT32_MAX;
 else if(!strcmp(mode,"short"))size=2;
 else if(!strcmp(mode,"empty"))size=0;
 else if(!strcmp(mode,"oversize"))size=8;
 else if(!strcmp(mode,"pid"))pid=1;
 else if(!strcmp(mode,"copy"))copies=1;
 else if(!strcmp(mode,"move"))moves=1;
 else if(!strncmp(mode,"buffer",6))buffer=(unsigned)atoi(mode+6);
 else if(!strncmp(mode,"command",7))cmd=(unsigned)atoi(mode+7);
 else if(!strcmp(mode,"input-object")){
  request(m,type,id,cmd,0,0,0,data,size,0,16);((uint8_t *)(m+4))[1]=1;fixture_dispatch(s,m);return 4;
 }else if(!strcmp(mode,"invalid-object"))id=123;
 else runtime_fail("unknown fixture mode");
 request(m,type,id,cmd,pid,copies,moves,data,size,buffer,16);fixture_dispatch(s,m);return 4;
}
'''

TRANSPORT = r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned live;
static void *tracked_calloc(size_t n,size_t s){void *p=calloc(n,s);if(!p)abort();for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;live++;return p;}abort();}
static void tracked_free(void *p){if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;live--;free(p);return;}abort();}
#define calloc tracked_calloc
#define free tracked_free
#include "ipc.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm_dispatch(uint32_t *m){IpcSession s={.name="sm:",.handler=sm};dispatch(&s,m);}
unsigned fixture_registrations(void){unsigned count=0;for(unsigned i=0;i<nservices;i++){if(!strcmp(services[i].name,"ssl:s"))count++;else abort();}return count;}
unsigned fixture_ipc_live(void){return live;}
'''


class NativeSslTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-ssl-tests-")
        directory = Path(cls.temporary.name)
        source, transport = directory / "fixture.c", directory / "transport.c"
        source.write_text(FIXTURE)
        transport.write_text(TRANSPORT)
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                  "-DGAME_CASTLEVANIA=1", "-I"+str(policy.ROOT / "runtime"),
                  "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), str(source), str(transport)]
        cls.binary, cls.disabled = directory / "ssl-native", directory / "ssl-disabled"
        for defines, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.disabled)]:
            result = subprocess.run(common+defines+["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, failure=None, no_run=False, disabled=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-ssl-run-") as directory:
            parent = Path(directory)
            binary = self.disabled if disabled else self.binary
            if no_run:
                result = subprocess.run([str(binary), mode], cwd=parent, env={"PATH": "/usr/bin:/bin"},
                                        capture_output=True, text=True, timeout=10)
                text = result.stderr
                self.assertEqual(list(parent.iterdir()), [])
            else:
                run = policy.create_run(parent)
                root = Path(run["root"])
                (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
                log = root / "logs/native-host.log"
                log.touch(mode=0o600)
                env = policy.child_environment(run)
                env["CASTLEVANIA_LOG_FILE"] = str(log)
                before = {str(p.relative_to(root)) for p in root.rglob("*")}
                with log.open("ab") as stream:
                    result = subprocess.run([str(binary), mode], cwd=root, env=env, stdout=subprocess.PIPE,
                                            stderr=stream, timeout=10)
                text = log.read_text()
                self.assertEqual(before, {str(p.relative_to(root)) for p in root.rglob("*")})
            if failure:
                self.assertNotEqual(result.returncode, 0, text)
                self.assertIn(failure, text)
            else:
                self.assertEqual(result.returncode, 0, text)

    def test_pre_main_only_registers_ssl_system_endpoint(self): self.fixture("register", no_run=True)
    def test_default_disabled_constructor_only_registers(self): self.fixture("register", no_run=True, disabled=True)
    def test_open_creates_and_releases_real_retained_manager(self): self.fixture("open")
    def test_open_requires_owned_checked_run(self): self.fixture("open", "run root", no_run=True)
    def test_default_compile_gate_blocks_open(self): self.fixture("open", "disabled at compile time", disabled=True)
    def test_exact_non_domain_logical_argument_persists_version(self): self.fixture("plain-exact")
    def test_measured_domain_version3_result_only(self): self.fixture("domain")
    def test_repeated_version3_is_idempotent(self): self.fixture("repeat")
    def test_separate_service_opens_have_independent_state(self): self.fixture("independent")
    def test_clone_before_declaration_shares_owned_state(self): self.fixture("clone-before")
    def test_clone_after_declaration_survives_original_close(self): self.fixture("clone-after")
    def test_domain_root_close_releases_state_before_transport(self): self.fixture("domain-root-close")
    def test_domain_clone_lifetime(self): self.fixture("domain-clone")
    def test_domain_clone_ex_lifetime(self): self.fixture("clone-ex")
    def test_copy_from_domain_survives_original_domain(self): self.fixture("domain-copy")
    def test_copy_from_domain_survives_root_object_close(self): self.fixture("copy-root-close")
    def test_thousand_actual_domain_clone_copy_close_cycles(self): self.fixture("cycles")
    def test_versions_other_than_measured3_fail(self):
        for mode in ("version0", "version1", "version2", "version4", "version-max"):
            with self.subTest(mode=mode): self.fixture(mode, "interface version unsupported")
    def test_unmeasured_request_type4_fails(self): self.fixture("ordinary-type4", "unexpected transport")
    def test_tipc_fails(self): self.fixture("tipc", "unexpected transport")
    def test_pid_is_not_part_of_this_command(self): self.fixture("pid", "unexpected transport")
    def test_input_copy_handle_fails(self): self.fixture("copy", "unexpected transport")
    def test_input_move_handle_fails(self): self.fixture("move", "unexpected transport")
    def test_every_buffer_family_fails(self):
        for mode in ("buffer1", "buffer2", "buffer3", "buffer4", "buffer5"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_exact4_argument_required(self):
        for mode in ("empty", "short", "oversize"):
            with self.subTest(mode=mode): self.fixture(mode, "requires exact u32")
    def test_context_certificate_connection_related_commands_remain_unsupported(self):
        for cmd in (0, 1, 2, 3, 6, 7, 8, 9, 100, 101, 102, 999):
            with self.subTest(cmd=cmd): self.fixture("command"+str(cmd), "ssl:s: command")
    def test_control_cmd5_cannot_be_confused_with_service_cmd5(self): self.fixture("unknown-control", "control command 5 not implemented")
    def test_input_domain_object_fails(self): self.fixture("input-object", "input objects not implemented")
    def test_unknown_domain_object_fails(self): self.fixture("invalid-object", "domain object")
    def test_unobserved_ssl_fallback_endpoint_is_not_registered(self): self.fixture("fallback-endpoint", 'service "ssl" not implemented')


if __name__ == "__main__":
    unittest.main()
