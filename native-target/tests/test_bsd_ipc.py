"""Native measured BSD registration/monitor and explicit offline wire tests."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeBsdIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-bsd-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
static unsigned bsd_state_live;
static void *bsd_test_calloc(size_t n,size_t size){void *p=calloc(n,size);if(p)bsd_state_live++;return p;}
static void bsd_test_free(void *p){if(p){if(!bsd_state_live)abort();bsd_state_live--;free(p);}}
#define calloc bsd_test_calloc
#define free bsd_test_free
#include "bsd_host.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *,uint32_t *),fixture_sm_dispatch(uint32_t *);
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
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
int socket(int domain,int type,int protocol){(void)domain;(void)type;(void)protocol;runtime_fail("OS socket must not run");}
static void need(int ok,const char *why){if(!ok)runtime_fail(why);}
static thr_t main_thread;
typedef struct {BsdConfig config;uint64_t placeholder,size;} RegisterInput;
_Static_assert(sizeof(RegisterInput)==48,"independent raw registration fixture");
static uint64_t wire_pid;static uint32_t copy_handle;static unsigned slack=16;
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,unsigned ncopy,unsigned nmove,
                    const void *data,unsigned size,unsigned buffer){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid||ncopy||nmove){m[1]=1u<<31;*p++=(pid?1u:0u)|(ncopy<<1)|(nmove<<5);
  if(pid){memcpy(p,&wire_pid,8);p+=2;}for(unsigned i=0;i<ncopy+nmove;i++)*p++=copy_handle;
 }
 if(buffer&&buffer<=4){m[0]|=1u<<(12+buffer*4);p+=buffer==1?2:3;}
 uint8_t *words=(uint8_t *)p,*payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t header[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,header,16);payload+=16;
 if(size)memcpy(payload,data,size);memset(payload+size,0xa5,slack);
 m[1]|=(unsigned)(payload+size+slack-words+3)/4;if(buffer==5)m[1]|=2u<<10;
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("CMIF response missing");}
static IpcSession *session(uint32_t h){IpcSession *s=runtime_handle_get(h,1);need(s!=NULL,"live actual session");return s;}
static uint32_t moved(uint32_t *m){need((m[1]>>31)&&!((m[2]>>1)&15)&&((m[2]>>5)&15)==1,"one real MOVE");(void)session(m[3]);return m[3];}
static uint32_t open_bsd(uint32_t *m,const char *name){char service[8]={0};memcpy(service,name,strlen(name));request(m,6,0,1,0,0,0,service,8,0);fixture_sm_dispatch(m);need(!response(m)[2],"SM open");uint32_t h=moved(m);IpcSession *s=session(h);BsdSessionState *state=s->state;need(s->handler==bsd_handler&&s->retain==bsd_retain&&s->close==bsd_close&&state&&state->references==1&&!state->client,"real unbound retained session");return h;}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");}
static uint32_t control(uint32_t h,uint32_t *m,unsigned cmd,const void *data,unsigned size){request(m,5,0,cmd,0,0,0,data,size,0);fixture_dispatch(session(h),m);need(!response(m)[2],"CMIF control");if(cmd==0||cmd==3)return response(m)[4];return moved(m);}
static void register_client(uint32_t h,uint32_t *m,unsigned object,const RegisterInput *input){request(m,6,object,0,1,1,0,input,48,0);fixture_dispatch(session(h),m);need(!response(m)[2]&&response(m)[4]==0&&!(m[1]>>31),"registration CMIF result and status0/nohandles");}
static void monitor(uint32_t h,uint32_t *m,unsigned object){uint64_t zero=0;request(m,6,object,1,1,0,0,&zero,8,0);fixture_dispatch(session(h),m);need(!response(m)[2]&&!(m[1]>>31),"real monitor empty result");}
static void clean(void){need(!bsd_state_live&&!fixture_ipc_live()&&!bsd_registered,"all client/session/TMEM/IPC state freed");for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all handles reclaimed");}
static void domain_close(uint32_t h,uint32_t *m,unsigned id){memset(m,0,256);m[0]=6;m[1]=12;m[4]=2;m[5]=id;fixture_dispatch(session(h),m);need(!response(m)[2],"domain object close");}
int main(int argc,char **argv){
 need(argc==2,"mode");const char *mode=argv[1];need(fixture_registrations()==1&&!bsd_state_live&&!fixture_ipc_live()&&!bsd_registered,"premain only registers");
 if(!strcmp(mode,"register")){clean();return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];uint32_t h=open_bsd(m,!strcmp(mode,"legacy-endpoint")?"bsd:u":"bsd:s");
 if(!strcmp(mode,"open")){close_handle(h);clean();return 0;}
 void *backing=NULL;need(!posix_memalign(&backing,4096,2u*1024u*1024u),"original allocated TMEM backing");
 uint64_t r[32]={0,(uintptr_t)backing,2u*1024u*1024u,0};need(runtime_ipc_svc(0x15,r)&&!r[0],"actual CreateTransferMemory");uint32_t tmem=(uint32_t)r[1];copy_handle=tmem;
 RegisterInput input={{10,0x8000,0x10000,0x30000,0x30000,0x2400,0xa500,4},0,2u*1024u*1024u};
 BsdSessionState *state=session(h)->state;
 if(!strcmp(mode,"cycles")){
  close_handle(tmem);close_handle(h);clean();
  for(unsigned i=0;i<1000;i++){
   uint64_t tm[32]={0,(uintptr_t)backing,input.size,0};need(runtime_ipc_svc(0x15,tm)&&!tm[0],"cycle actual TMEM");copy_handle=(uint32_t)tm[1];
   h=open_bsd(m,"bsd:s");unsigned id=control(h,m,0,NULL,0);register_client(h,m,id,&input);
   uint32_t copy=control(h,m,1,&id,4),mon=open_bsd(m,"bsd:s");monitor(mon,m,0);close_handle(copy_handle);
   close_handle(h);need(bsd_registered&&bsd_registered->references==2,"copied client and monitor retain registry after domain destruction");
   close_handle(copy);need(bsd_registered&&bsd_registered->references==1&&bsd_registered->monitors==1,"monitor retains after last client copy");close_handle(mon);clean();
  }free(backing);return 0;
 }
 if(!strcmp(mode,"monitor-before")){uint32_t mon=open_bsd(m,"bsd:s");monitor(mon,m,0);return 4;}
 if(!strcmp(mode,"socket-before")){int32_t args[3]={2,1,0};request(m,6,0,2,0,0,0,args,12,0);fixture_dispatch(session(h),m);return 4;}
 if(!strcmp(mode,"bad-handle"))copy_handle=7;
 else if(!strcmp(mode,"session-handle"))copy_handle=h;
 else if(!strcmp(mode,"event-handle"))copy_handle=runtime_event_new();
 else if(!strcmp(mode,"closed-tmem")){close_handle(tmem);}
 else if(!strcmp(mode,"version"))input.config.version=1;
 else if(!strcmp(mode,"efficiency"))input.config.efficiency=0;
 else if(!strcmp(mode,"max-buffer"))input.config.tcp_tx_max=1;
 else if(!strcmp(mode,"large-config"))input.config.udp_tx=UINT32_MAX;
 else if(!strcmp(mode,"placeholder"))input.placeholder=1;
 else if(!strcmp(mode,"tmem-size"))input.size-=4096;
 else if(!strcmp(mode,"tmem-perm"))((IpcTransferMemory*)runtime_handle_get(tmem,0))->perm=3;
 else if(!strcmp(mode,"tmem-align"))((IpcTransferMemory*)runtime_handle_get(tmem,0))->addr++;
 else if(!strcmp(mode,"tmem-overflow"))((IpcTransferMemory*)runtime_handle_get(tmem,0))->addr=UINT64_MAX-4095;
 else if(!strcmp(mode,"tmem-cap")){input.size=BSD_TMEM_MAX+4096;((IpcTransferMemory*)runtime_handle_get(tmem,0))->size=input.size;}
 else if(!strcmp(mode,"wire-pid"))wire_pid=UINT64_MAX;
 if(!strcmp(mode,"raw-truncated")||!strcmp(mode,"raw-oversized")){
  unsigned root=control(h,m,0,NULL,0);uint8_t raw[72]={0};memcpy(raw,&input,48);request(m,6,root,0,1,1,0,raw,!strcmp(mode,"raw-truncated")?47:69,0);fixture_dispatch(session(h),m);return 4;
 }
 if(!strcmp(mode,"missing-pid")||!strcmp(mode,"missing-copy")||!strcmp(mode,"extra-copy")||!strcmp(mode,"move-handle")||
    !strcmp(mode,"x-buffer")||!strcmp(mode,"a-buffer")||!strcmp(mode,"b-buffer")||!strcmp(mode,"w-buffer")||!strcmp(mode,"c-buffer")||!strcmp(mode,"tipc")){
  unsigned buffer=!strcmp(mode,"x-buffer")?1:!strcmp(mode,"a-buffer")?2:!strcmp(mode,"b-buffer")?3:!strcmp(mode,"w-buffer")?4:!strcmp(mode,"c-buffer")?5:0;
  request(m,!strcmp(mode,"tipc")?16:6,0,0,strcmp(mode,"missing-pid")!=0,!strcmp(mode,"missing-copy")||!strcmp(mode,"move-handle")?0:!strcmp(mode,"extra-copy")?2:1,!strcmp(mode,"move-handle"),&input,48,buffer);fixture_dispatch(session(h),m);return 4;
 }
 if(!strcmp(mode,"observed"))slack=8;
 unsigned root=!strcmp(mode,"domain")||!strcmp(mode,"domain-copy")||!strcmp(mode,"domain-root-close")?control(h,m,0,NULL,0):0;
 if(!strcmp(mode,"exact-output")){
  IpcRequest q={.type=6,.cmd=0,.has_pid=1,.ncopy=1,.data=(uint8_t*)&input,.data_size=48};q.copy[0]=tmem;IpcResponse out={0};
  bsd_handler(session(h),&q,&out);need(!out.result&&out.data_size==4&&!out.ncopy&&!out.nmove&&!out.nobjects,"measured output is exactly u32status0 not fakeu64PID");
 }else register_client(h,m,root,&input);
 BsdClient *client=state->client;need(client&&client==bsd_registered&&client->host_pid==(uint64_t)getpid()&&client->references==1&&!client->monitors&&!memcmp(&client->config,&input.config,32),"real current-process registration/config");
 need(client->transfer.addr==(uintptr_t)backing&&client->transfer.size==input.size&&client->transfer.perm==0,"owned TMEM metadata");
 if(!strcmp(mode,"repeat-register")){register_client(h,m,root,&input);return 4;}
 if(!strcmp(mode,"second-register")){uint32_t second=open_bsd(m,"bsd:s");register_client(second,m,0,&input);return 4;}
 close_handle(tmem);need(client->transfer.addr==(uintptr_t)backing&&client->transfer.size==input.size,"metadata survives caller COPY handle close without borrowed object");
 if(!strcmp(mode,"clone-client")){uint32_t copy=control(h,m,2,NULL,0);need(state->references==2,"real clone state retain");close_handle(h);h=copy;need(state->references==1,"clone survives original close");}
 if(!strcmp(mode,"domain-copy")){uint32_t copy=control(h,m,1,&root,4);close_handle(h);h=copy;root=0;need(state->references==1,"copy survives entire domain");}
 if(!strcmp(mode,"domain-root-close")){domain_close(h,m,root);need(!bsd_registered&&!bsd_state_live,"last root object releases registration before transportclose");close_handle(h);clean();free(backing);return 0;}
 uint32_t mon=open_bsd(m,"bsd:s");BsdSessionState *monitor_state=session(mon)->state;
 if(!strcmp(mode,"monitor-placeholder")){uint64_t nonzero=7;request(m,6,0,1,1,0,0,&nonzero,8,0);fixture_dispatch(session(mon),m);return 4;}
 if(!strcmp(mode,"monitor-pid")||!strcmp(mode,"monitor-handle")){uint64_t zero=0;request(m,6,0,1,!strcmp(mode,"monitor-handle"),!strcmp(mode,"monitor-handle"),0,&zero,8,0);fixture_dispatch(session(mon),m);return 4;}
 if(!strcmp(mode,"observed"))slack=4;
 monitor(mon,m,0);need(monitor_state->monitor&&monitor_state->client==client&&client->references==2&&client->monitors==1,"monitor meaningfully retains registered process");
 if(!strcmp(mode,"repeat-monitor")){monitor(mon,m,0);return 4;}
 if(!strcmp(mode,"monitor-socket")){int32_t args[3]={2,1,0};request(m,6,0,2,0,0,0,args,12,0);fixture_dispatch(session(mon),m);return 4;}
 if(!strcmp(mode,"unknown")){request(m,6,root,999,0,0,0,NULL,0,0);fixture_dispatch(session(h),m);return 4;}
 if(!strcmp(mode,"socket")||!strcmp(mode,"socket-exempt")){
  int32_t args[3]={2,1,0};request(m,6,root,!strcmp(mode,"socket-exempt")?3:2,0,0,0,args,12,0);fixture_dispatch(session(h),m);
  need(!response(m)[2]&&(int32_t)response(m)[4]==-1&&response(m)[5]==100,"offline Horizon wire result is -1/Linux ENETDOWN100");
 }
 if(!strcmp(mode,"clone-monitor")){uint32_t copy=control(mon,m,2,NULL,0);close_handle(mon);mon=copy;need(monitor_state->references==1&&client->monitors==1,"cloned monitor retains one attachment");}
 if(!strcmp(mode,"close-monitor-first")){close_handle(mon);need(client==bsd_registered&&client->references==1&&!client->monitors,"monitor detaches without destroying live client");close_handle(h);}
 else {close_handle(h);need(client==bsd_registered&&client->references==1&&client->monitors==1,"monitor keeps registration alive after clientclose");close_handle(mon);}
 clean();free(backing);return 0;
}
''')
        transport = directory / "transport.c"
        transport.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned live;
static void *record(void *p){if(!p)abort();for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;live++;return p;}abort();}
static void *ipc_test_calloc(size_t n,size_t z){return record(calloc(n,z));}
static void *ipc_test_malloc(size_t z){return record(malloc(z));}
static void ipc_test_free(void *p){if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;live--;free(p);return;}abort();}
#define calloc ipc_test_calloc
#define malloc ipc_test_malloc
#define free ipc_test_free
#include "ipc.c"
#undef calloc
#undef malloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm_dispatch(uint32_t *m){IpcSession s={.name="sm:",.handler=sm};dispatch(&s,m);}
unsigned fixture_registrations(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"bsd:s");return n;}
unsigned fixture_ipc_live(void){return live;}
''')
        cls.binary = directory / "bsd-native"
        cls.disabled = directory / "bsd-disabled"
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                  "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1", "-I" + str(policy.ROOT / "runtime"),
                  "-I" + str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), str(source), str(transport), "-Wl,-dead_strip"]
        for defines, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.disabled)]:
            result = subprocess.run(common + defines + ["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, failure=None, no_run=False, disabled=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-bsd-run-") as directory:
            binary = self.disabled if disabled else self.binary
            if no_run:
                result = subprocess.run([str(binary), mode], cwd=directory, env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=15)
                text = result.stderr;self.assertEqual(list(Path(directory).iterdir()), [])
            else:
                run = policy.create_run(Path(directory));root = Path(run["root"])
                (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
                log = root / "logs/native-host.log";log.touch(mode=0o600)
                env = policy.child_environment(run);env["CASTLEVANIA_LOG_FILE"] = str(log)
                before = {str(p.relative_to(root)) for p in root.rglob("*")}
                with log.open("ab") as stream:
                    result = subprocess.run([str(binary), mode], cwd=root, env=env, stdout=subprocess.PIPE, stderr=stream, timeout=15)
                text = log.read_text();self.assertEqual(before, {str(p.relative_to(root)) for p in root.rglob("*")})
            if failure:
                self.assertNotEqual(result.returncode, 0, text);self.assertIn(failure, text)
            else:
                self.assertEqual(result.returncode, 0, text)
            return text

    def test_constructor_only_registers_without_allocations_or_io(self): self.fixture("register", no_run=True)
    def test_default_disabled_constructor_only_registers(self): self.fixture("register", no_run=True, disabled=True)
    def test_real_retained_open_close_frees_unbound_state(self): self.fixture("open")
    def test_real_tmem_config_registration_and_monitor_then_final_release(self): self.fixture("initialize")
    def test_exact_modern_register_output_is_u32_status_not_generated_pid(self): self.fixture("exact-output")
    def test_actual_encoder_alignment_shapes_cmd0raw56_cmd1raw12(self):
        text = self.fixture("observed");self.assertIn("cmd=0 type=6 bytes=56", text);self.assertIn("cmd=1 type=6 bytes=12", text)
    def test_wire_pid_is_not_trusted_as_native_identity(self): self.fixture("wire-pid")
    def test_client_clone_survives_original_close(self): self.fixture("clone-client")
    def test_monitor_clone_keeps_single_attachment_until_last_close(self): self.fixture("clone-monitor")
    def test_monitor_detach_preserves_registered_client(self): self.fixture("close-monitor-first")
    def test_real_domain_registration_and_final_close(self): self.fixture("domain")
    def test_copied_domain_client_survives_domain_destruction(self): self.fixture("domain-copy")
    def test_last_domain_root_close_releases_registration(self): self.fixture("domain-root-close")
    def test_1000_tmem_register_domain_copy_monitor_close_cycles_reclaim_all_state(self): self.fixture("cycles")
    def test_legacy_unvalidated_endpoint_is_not_registered(self): self.fixture("legacy-endpoint", "service not implemented")
    def test_missing_pid_copy_or_extra_moved_handles_fail(self):
        for mode in ("missing-pid", "missing-copy", "extra-copy", "move-handle"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_non_tmem_or_closed_handle_is_rejected(self):
        for mode in ("bad-handle", "session-handle", "event-handle", "closed-tmem"):
            with self.subTest(mode=mode): self.fixture(mode, "not live transfer memory")
    def test_version_and_configuration_bounds_are_checked(self):
        for mode, message in (("version", "config version"), ("efficiency", "config buffer bounds"), ("max-buffer", "config buffer bounds"), ("large-config", "smaller than buffer")):
            with self.subTest(mode=mode): self.fixture(mode, message)
    def test_tmem_size_alignment_overflow_permission_and_cap_are_checked(self):
        for mode in ("tmem-size", "tmem-perm", "tmem-align", "tmem-overflow", "tmem-cap"):
            with self.subTest(mode=mode): self.fixture(mode, "transfer-memory bounds")
    def test_client_process_placeholder_must_be_zero(self): self.fixture("placeholder", "placeholder must be zero")
    def test_unmeasured_buffers_and_tipc_fail(self):
        for mode in ("x-buffer", "a-buffer", "b-buffer", "w-buffer", "c-buffer", "tipc"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_truncated_and_oversized_domain_input_fails(self):
        for mode in ("raw-truncated", "raw-oversized"):
            with self.subTest(mode=mode): self.fixture(mode, "argument size")
    def test_duplicate_client_registration_is_an_explicit_host_gate(self):
        for mode in ("repeat-register", "second-register"):
            with self.subTest(mode=mode): self.fixture(mode, "already registered")
    def test_monitor_before_registration_or_duplicate_attach_fails(self):
        for mode in ("monitor-before", "repeat-monitor"):
            with self.subTest(mode=mode): self.fixture(mode, "monitor requires live")
    def test_monitor_pid_handle_and_placeholder_shape_is_checked(self):
        for mode, message in (("monitor-placeholder", "placeholder must be zero"), ("monitor-pid", "unexpected transport"), ("monitor-handle", "unexpected transport")):
            with self.subTest(mode=mode): self.fixture(mode, message)
    def test_unregistered_or_monitor_session_cannot_create_socket(self):
        for mode in ("socket-before", "monitor-socket"):
            with self.subTest(mode=mode): self.fixture(mode, "socket requires a registered")
    def test_socket_and_exempt_return_honest_offline_linux_errno_without_os_socket(self):
        for mode in ("socket", "socket-exempt"):
            with self.subTest(mode=mode): self.fixture(mode)
    def test_unknown_commands_still_fail(self): self.fixture("unknown", "bsd:s: command")
    def test_checked_host_run_is_required(self): self.fixture("open", "run root", no_run=True)
    def test_compile_default_gate_prevents_open(self): self.fixture("open", "disabled at compile time", disabled=True)


if __name__ == "__main__":
    unittest.main()
