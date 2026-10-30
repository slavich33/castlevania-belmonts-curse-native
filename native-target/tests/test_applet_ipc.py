"""Actual native CMIF/handle/event applet adapter tests; no SDK or guest entry."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeAppletIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-applet-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "applet_host.c"
#include "applet_ipc_host.c"
void fixture_dispatch(IpcSession *,uint32_t *);
unsigned fixture_registration_count(void);
#define dispatch fixture_dispatch
#define CMIF_IN_MAGIC 0x49434653u
#define CMIF_OUT_MAGIC 0x4f434653u
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int fixture_focus=1,fixture_handheld;
int runtime_front_focus(void){return fixture_focus;} /* controlled existing-policy API */
int runtime_handheld_mode(void){return fixture_handheld;}
void runtime_trace_guest(uint64_t f,uint64_t l){(void)f;(void)l;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
static void need(int ok,const char *why){if(!ok)runtime_fail(why);}
static thr_t main_thread;
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,uint32_t copy,const void *data,unsigned size){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid||copy){m[1]=1u<<31;*p++=(pid?1u:0u)|(copy?2u:0u);if(pid){*p++=0;*p++=0;}if(copy)*p++=copy;}
 uint8_t *payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t h[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,h,16);payload+=16;
 if(size)memcpy(payload,data,size);
 memset(payload+size,0xa5,16); /* legal unspecified alignment slack */
 m[1]|=(uint32_t)((payload+size+16-(uint8_t *)p+3)/4);
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("missing CMIF response");}
static uint64_t value(uint32_t *m){uint64_t v;memcpy(&v,response(m)+4,8);return v;}
static uint32_t copy_handle(uint32_t *m){need((m[1]>>31)&&((m[2]>>1)&15)==1&&!((m[2]>>5)&15),"read event must be COPY handle");return m[3];}
static uint32_t move_handle(uint32_t *m){need((m[1]>>31)&&((m[2]>>5)&15)==1&&!((m[2]>>1)&15),"interface must be MOVE handle");return m[3];}
static IpcSession *moved(uint32_t *m){IpcSession *s=runtime_handle_get(move_handle(m),1);need(s!=NULL,"moved session is real");return s;}
static void call(IpcSession *s,uint32_t *m,unsigned cmd,const void *data,unsigned size){request(m,6,0,cmd,0,0,data,size);dispatch(s,m);need(response(m)[2]==0,"successful CMIF command");}
static IpcSession *child(IpcSession *proxy,uint32_t *m,unsigned cmd){call(proxy,m,cmd,NULL,0);return moved(m);}
static int signaled(uint32_t readable){pthread_mutex_lock(&G);int bad=0,yes=sig_obj(readable,&bad);pthread_mutex_unlock(&G);need(!bad,"valid readable event");return yes;}
static uint64_t wait_event(uint32_t readable){uint64_t r[32]={0,(uintptr_t)&readable,1,0};need(svc_thread(0x18,r),"actual native WaitSynchronization");return r[0];}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");}
static uint32_t session_handle(IpcSession *s){for(unsigned i=1;i<MAX_H;i++)if(g_h[i].type==O_SESSION&&g_h[i].obj==s)return 0x1000+i;runtime_fail("session handle missing");}
static unsigned receive(IpcSession *common,uint32_t *m,uint32_t expected){call(common,m,1,NULL,0);uint32_t actual=(uint32_t)value(m);need(actual==expected,"expected shared queue message");return actual;}
static void *gpu_failure_callback(void *unused){(void)unused;runtime_applet_signal_gpu_error();return NULL;}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(message_event==0&&head==tail&&!applet_ipc_state.suspended_tick_event&&!applet_ipc_state.gpu_error_event&&!applet_ipc_state.gpu_error_detected,"pre-main event state untouched");
 if(!strcmp(mode,"register")){need(fixture_registration_count()==1,"exact appletOE registration");return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];uint64_t reserved=0;
 IpcSession root={.name="appletOE",.handler=applet_oe};
 int pid=strcmp(mode,"missing-pid")!=0;uint32_t process=!strcmp(mode,"missing-copy")?0u:!strcmp(mode,"bad-process")?7u:0xffff8001u;
 if(!strcmp(mode,"reserved"))reserved=1;
 if(!strcmp(mode,"service-unknown")){request(m,6,0,7,0,0,NULL,0);dispatch(&root,m);return 4;}
 if(!strcmp(mode,"domain")){
  request(m,5,0,0,0,0,NULL,0);dispatch(&root,m);unsigned root_id=(unsigned)value(m);need(root_id==1,"root domain object");
  request(m,6,root_id,0,1,0xffff8001u,&reserved,8);dispatch(&root,m);unsigned proxy_id=(unsigned)value(m);need(response(m)[-4]==1&&proxy_id>1,"proxy returned as domain object");
  request(m,6,proxy_id,0,0,0,NULL,0);dispatch(&root,m);unsigned common_id=(unsigned)value(m);need(response(m)[-4]==1&&common_id>proxy_id,"Common returned as domain object");
  request(m,6,common_id,0,0,0,NULL,0);dispatch(&root,m);unsigned event=copy_handle(m);need(signaled(event),"domain event copy initially signaled");
  request(m,6,common_id,1,0,0,NULL,0);dispatch(&root,m);need((unsigned)value(m)==15&&!signaled(event),"domain receive drains common event");
  uint32_t boost=1;request(m,6,common_id,66,0,0,&boost,4);dispatch(&root,m);need(!response(m)[2]&&applet_ipc_state.cpu_boost_requested_valid&&applet_ipc_state.cpu_boost_requested==1&&!signaled(event),"domain CPU request persists without fake notification");
  request(m,6,proxy_id,1,0,0,NULL,0);dispatch(&root,m);unsigned self_id=(unsigned)value(m);need(response(m)[-4]==1,"SelfController domain object");
  uint8_t resume=1;request(m,6,self_id,14,0,0,&resume,1);dispatch(&root,m);need(!response(m)[2]&&applet_ipc_state.resume_notification&&!signaled(event),"domain resume preference without fake event");
  resume=0;request(m,6,self_id,14,0,0,&resume,1);dispatch(&root,m);need(!response(m)[2]&&!applet_ipc_state.resume_notification,"domain resume disable retained");
  request(m,6,proxy_id,20,0,0,NULL,0);dispatch(&root,m);unsigned functions_id=(unsigned)value(m);need(response(m)[-4]==1&&functions_id>common_id,"ApplicationFunctions domain object");
  request(m,6,functions_id,130,0,0,NULL,0);dispatch(&root,m);unsigned gpu=copy_handle(m);need(!signaled(gpu),"domain GPU event initially unsignaled");
  runtime_applet_signal_gpu_error();need(signaled(gpu)&&!signaled(event),"domain GPU COPY receives only GPU failure");return 0;
 }
 request(m,!strcmp(mode,"transport")?16:6,0,0,pid,process,&reserved,8);dispatch(&root,m);IpcSession *proxy=moved(m);need(proxy->handler==applet_proxy,"ApplicationProxy handler");
 if(!strcmp(mode,"open"))return 0;
 if(!strcmp(mode,"proxy-unknown")){call(proxy,m,99,NULL,0);return 4;}
 if(!strcmp(mode,"factories")){
  unsigned commands[]={0,1,2,3,4,11,20,1000};for(unsigned i=0;i<8;i++)need(child(proxy,m,commands[i])->state==&applet_ipc_state,"shared real interface state");return 0;
 }
 IpcSession *common=child(proxy,m,0),*self=child(proxy,m,1),*window=child(proxy,m,2);
 if(!strcmp(mode,"policies")){
  IpcRequest rq={.type=6,.cmd=5};IpcResponse rs={0};applet_common(common,&rq,&rs);need(rs.data_size==1,"operation result is exactly u8");
  rq.cmd=6;memset(&rs,0,sizeof rs);applet_common(common,&rq,&rs);need(rs.data_size==4,"performance result is exactly u32");
  rq.cmd=9;memset(&rs,0,sizeof rs);applet_common(common,&rq,&rs);need(rs.data_size==1,"focus result is exactly u8");
  rq.cmd=1;memset(&rs,0,sizeof rs);applet_window(window,&rq,&rs);need(rs.data_size==8,"ARUID result is exactly u64");
  fixture_handheld=1;call(common,m,5,NULL,0);need((uint8_t)value(m)==0,"handheld u8 operation");call(common,m,6,NULL,0);need((uint32_t)value(m)==0,"normal u32 performance");
  fixture_handheld=0;call(common,m,5,NULL,0);need((uint8_t)value(m)==1,"docked u8 operation");call(common,m,6,NULL,0);need((uint32_t)value(m)==1,"boost u32 performance");
  call(common,m,9,NULL,0);need((uint8_t)value(m)==1,"existing focus enum");call(window,m,1,NULL,0);need(value(m)==1,"existing process ARUID");
  call(window,m,10,NULL,0);need(applet_ipc_state.foreground_acquired,"foreground request recorded");
  uint8_t on=1,focus[3]={0,0,1};call(self,m,11,&on,1);call(self,m,12,&on,1);call(self,m,13,focus,3);call(self,m,16,&on,1);
  need(applet_ipc_state.operation_notification&&applet_ipc_state.performance_notification&&applet_ipc_state.focus_handling[2]&&applet_ipc_state.out_of_focus_suspending,"logical configuration persisted");
  call(common,m,900,NULL,0);need(applet_ipc_state.exit_to_library_at_next_program,"future exit notification preference persisted");
  IpcSession *functions=child(proxy,m,20);call(functions,m,40,NULL,0);need((uint8_t)value(m)==1&&applet_ipc_state.running_notified,"native process notification");return 0;
 }
 if(!strcmp(mode,"suspended")){
  call(self,m,91,NULL,0);uint32_t suspended=copy_handle(m);need(!signaled(suspended)&&wait_event(suspended)==R_TIMEOUT,"suspended event not fabricated ready");
  call(common,m,0,NULL,0);uint32_t event=copy_handle(m);need(event!=suspended&&signaled(event)&&!signaled(suspended),"two distinct event sources");
  runtime_oe_push_message(15);need(!signaled(suspended),"focus notification does not signal suspended event");close_handle(suspended);return 0;
 }
 if(!strcmp(mode,"gpu")||!strcmp(mode,"gpu-before-query")){
  IpcSession *functions=child(proxy,m,20);
  if(!strcmp(mode,"gpu-before-query")){
   runtime_applet_signal_gpu_error();need(applet_ipc_state.gpu_error_detected&&!applet_ipc_state.gpu_error_event,"early GPU failure latched without event allocation");
   call(functions,m,130,NULL,0);uint32_t event=copy_handle(m);need(signaled(event)&&wait_event(event)==0,"late query observes actual prior failure");close_handle(event);return 0;
  }
  IpcRequest rq={.type=6,.cmd=130};IpcResponse rs={0};applet_functions(functions,&rq,&rs);
  need(!rs.data_size&&rs.ncopy==1&&!rs.nmove,"GPU event has no raw result and exactly one COPY");close_handle(rs.copy[0]);
  call(functions,m,130,NULL,0);uint32_t event=copy_handle(m);call(functions,m,130,NULL,0);uint32_t other=copy_handle(m);
  need(event!=other&&!signaled(event)&&!signaled(other)&&wait_event(event)==R_TIMEOUT,"fresh readable GPU copies initially unsignaled");
  call(self,m,91,NULL,0);uint32_t suspended=copy_handle(m);call(common,m,0,NULL,0);uint32_t focus=copy_handle(m);receive(common,m,15);
  pthread_t callback;need(!pthread_create(&callback,NULL,gpu_failure_callback,NULL),"host GPU callback thread created");need(!pthread_join(callback,NULL),"host GPU callback thread joined");
  need(signaled(event)&&signaled(other)&&wait_event(event)==0&&wait_event(event)==0,"GPU failure signals copies and remains manual-clear ready");
  need(!signaled(focus)&&!signaled(suspended),"GPU failure does not signal focus or suspension events");
  close_handle(event);call(functions,m,130,NULL,0);uint32_t late=copy_handle(m);need(signaled(other)&&signaled(late),"service retains GPU event after readable close");
  runtime_applet_signal_gpu_error();need(signaled(other)&&signaled(late),"repeated failure notification is idempotent");
  close_handle(other);close_handle(late);close_handle(suspended);close_handle(focus);return 0;
 }
 if(!strcmp(mode,"gpu-buffers")||!strcmp(mode,"gpu-handle")){
  IpcSession *functions=child(proxy,m,20);IpcRequest rq={.type=6,.cmd=130};IpcResponse rs={0};
  if(!strcmp(mode,"gpu-buffers"))rq.nx=1;else rq.ncopy=1;applet_functions(functions,&rq,&rs);return 4;
 }
 if(!strcmp(mode,"cpu")){
  need(!applet_ipc_state.cpu_boost_requested_valid,"no fabricated initial CPU request");
  call(common,m,0,NULL,0);uint32_t focus=copy_handle(m);receive(common,m,15);
  call(self,m,91,NULL,0);uint32_t suspended=copy_handle(m);IpcSession *functions=child(proxy,m,20);call(functions,m,130,NULL,0);uint32_t gpu=copy_handle(m);
  uint32_t boost=1;call(common,m,66,&boost,4);need(applet_ipc_state.cpu_boost_requested_valid&&applet_ipc_state.cpu_boost_requested==1,"FastLoad requested mode retained");
  need(!signaled(focus)&&!signaled(suspended)&&!signaled(gpu)&&!applet_ipc_state.gpu_error_detected,"CPU request does not signal independent events");
  call(common,m,5,NULL,0);need((uint8_t)value(m)==1,"CPU request does not change operation mode");call(common,m,6,NULL,0);need((uint32_t)value(m)==1,"CPU request does not fabricate performance mode");
  request(m,6,0,1,0,0,NULL,0);dispatch(common,m);need(response(m)[2]==0x680u,"CPU request does not enqueue a fabricated notification");
  boost=0;call(common,m,66,&boost,4);need(!applet_ipc_state.cpu_boost_requested,"Normal resets intent through actual CMIF");
  IpcRequest rq={.type=6,.cmd=66,.data=(uint8_t*)&boost,.data_size=4};IpcResponse rs={0};applet_common(common,&rq,&rs);
  need(!rs.data_size&&!rs.ncopy&&!rs.nmove&&!rs.result&&applet_ipc_state.cpu_boost_requested_valid&&!applet_ipc_state.cpu_boost_requested,"Normal resets requested intent with exact empty output");
  close_handle(focus);close_handle(suspended);close_handle(gpu);return 0;
 }
 if(!strcmp(mode,"cpu-type2")||!strcmp(mode,"cpu-unknown")||!strcmp(mode,"cpu-wide")||!strcmp(mode,"cpu-negative")){
  uint32_t boost=!strcmp(mode,"cpu-type2")?2u:!strcmp(mode,"cpu-unknown")?3u:!strcmp(mode,"cpu-wide")?0x100u:UINT32_MAX;call(common,m,66,&boost,4);return 4;
 }
 if(!strncmp(mode,"cpu-",4)){
  uint32_t boost=1;IpcRequest rq={.type=6,.cmd=66,.data=(uint8_t*)&boost,.data_size=4};IpcResponse rs={0};
  if(!strcmp(mode,"cpu-truncated"))rq.data_size=3;else if(!strcmp(mode,"cpu-oversized"))rq.data_size=25;else if(!strcmp(mode,"cpu-pid"))rq.has_pid=1;
  else if(!strcmp(mode,"cpu-handle"))rq.ncopy=1;else if(!strcmp(mode,"cpu-buffer"))rq.nx=1;else if(!strcmp(mode,"cpu-transport"))rq.type=16;else return 5;
  applet_common(common,&rq,&rs);return 4;
 }
 if(!strcmp(mode,"resume")){
  call(common,m,0,NULL,0);uint32_t focus=copy_handle(m);receive(common,m,15);call(self,m,91,NULL,0);uint32_t suspended=copy_handle(m);
  IpcSession *functions=child(proxy,m,20);call(functions,m,130,NULL,0);uint32_t gpu=copy_handle(m);
  uint8_t enabled=1;call(self,m,14,&enabled,1);need(applet_ipc_state.resume_notification&&!applet_ipc_state.operation_notification&&!applet_ipc_state.performance_notification,"resume preference independent of operation/performance preferences");
  need(!signaled(focus)&&!signaled(suspended)&&!signaled(gpu)&&!applet_ipc_state.gpu_error_detected,"enabling resume does not fabricate transitions or event signals");
  request(m,6,0,1,0,0,NULL,0);dispatch(common,m);need(response(m)[2]==0x680u,"resume preference does not enqueue Resume16 or other messages");
  enabled=0;call(self,m,14,&enabled,1);need(!applet_ipc_state.resume_notification,"resume preference disable retained through CMIF");
  IpcRequest rq={.type=6,.cmd=14,.data=&enabled,.data_size=1};IpcResponse rs={0};applet_self(self,&rq,&rs);need(!rs.result&&!rs.data_size&&!rs.ncopy&&!rs.nmove,"resume setter exact empty output");
  need(!signaled(focus)&&!signaled(suspended)&&!signaled(gpu),"disabling resume does not signal events");close_handle(focus);close_handle(suspended);close_handle(gpu);return 0;
 }
 if(!strcmp(mode,"resume-bool2")||!strcmp(mode,"resume-bool255")){uint8_t enabled=!strcmp(mode,"resume-bool2")?2:255;call(self,m,14,&enabled,1);return 4;}
 if(!strncmp(mode,"resume-",7)){
  uint8_t enabled=1;IpcRequest rq={.type=6,.cmd=14,.data=&enabled,.data_size=1};IpcResponse rs={0};
  if(!strcmp(mode,"resume-truncated"))rq.data_size=0;else if(!strcmp(mode,"resume-oversized"))rq.data_size=22;else if(!strcmp(mode,"resume-pid"))rq.has_pid=1;
  else if(!strcmp(mode,"resume-handle"))rq.ncopy=1;else if(!strcmp(mode,"resume-buffer"))rq.nx=1;else if(!strcmp(mode,"resume-transport"))rq.type=16;else return 5;
  applet_self(self,&rq,&rs);return 4;
 }
 if(!strcmp(mode,"bad-focus")){fixture_focus=0;call(common,m,9,NULL,0);return 4;}
 if(!strcmp(mode,"background-rights")){fixture_focus=2;call(window,m,10,NULL,0);return 4;}
 if(!strcmp(mode,"bad-bool")){uint8_t bad=2;call(self,m,11,&bad,1);return 4;}
 if(!strcmp(mode,"common-unknown")){call(common,m,901,NULL,0);return 4;}
 if(!strcmp(mode,"self-unknown")){call(self,m,99,NULL,0);return 4;}
 if(!strcmp(mode,"window-unknown")){call(window,m,99,NULL,0);return 4;}
 if(!strcmp(mode,"functions-unknown")){IpcSession *f=child(proxy,m,20);call(f,m,99,NULL,0);return 4;}
 if(!strcmp(mode,"audio-unknown")){IpcSession *audio=child(proxy,m,3);call(audio,m,0,NULL,0);return 4;}
 if(!strcmp(mode,"extra-pid")){request(m,6,0,9,1,0,NULL,0);dispatch(common,m);return 4;}
 if(!strcmp(mode,"buffers")){IpcRequest rq={.type=6,.cmd=9,.nx=1};IpcResponse rs={0};applet_common(common,&rq,&rs);return 4;}
 if(!strcmp(mode,"truncated")){uint8_t v[2]={0};IpcRequest rq={.type=6,.cmd=13,.data=v,.data_size=2};IpcResponse rs={0};applet_self(self,&rq,&rs);return 4;}
 if(!strcmp(mode,"clone")){
  uint32_t original=session_handle(common);request(m,5,0,2,0,0,NULL,0);dispatch(common,m);IpcSession *copy=moved(m);close_handle(original);common=copy;
 }
 call(common,m,0,NULL,0);uint32_t event=copy_handle(m);need(signaled(event),"initial focus message ready before SDK wait");
 need(wait_event(event)==0&&wait_event(event)==0,"manual-clear event remains ready until queue drain");
 receive(common,m,15);need(!signaled(event)&&wait_event(event)==R_TIMEOUT,"last receive clears real event");
 request(m,6,0,1,0,0,NULL,0);dispatch(common,m);need(response(m)[2]==0x680u,"empty ReceiveMessage returns applet error");
 call(common,m,0,NULL,0);uint32_t other=copy_handle(m);need(other!=event&&!signaled(other),"new copy without duplicate initial message");
 close_handle(event);runtime_oe_push_message(30);runtime_oe_push_message(31);need(signaled(other),"frontend producer signals shared event");
 receive(common,m,30);need(signaled(other),"partly drained queue remains signaled");receive(common,m,31);need(!signaled(other),"last pop clears every copy");
 unsigned char(*high_pop)(uint32_t*)=runtime_applet_override("_ZN2nn2oe25TryPopNotificationMessageEPj");
 runtime_oe_push_message(15);uint32_t message;need(high_pop(&message)&&message==15&&!signaled(other),"direct host adapter consumes exact same queue/event");close_handle(other);return 0;
}
''')
        transport = directory / "transport.c"
        transport.write_text('''#include "ipc.c"
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
unsigned fixture_registration_count(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"appletOE");return n;}
''')
        cls.binary = directory / "applet-ipc-fixture"
        command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                   "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
                   "-DGAME_CASTLEVANIA=1", "-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
                   "-I"+str(policy.ROOT / "runtime"),
                   "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), str(source), str(transport),
                   "-Wl,-dead_strip", "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, failure=None, no_run=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-applet-run-") as directory:
            if no_run:
                result = subprocess.run([str(self.binary), mode], env={"PATH": "/usr/bin:/bin"},
                                        capture_output=True, text=True, timeout=10)
                text = result.stderr
            else:
                run = policy.create_run(Path(directory));root=Path(run["root"])
                (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
                log = root / "logs/native-host.log";log.touch(mode=0o600)
                env=policy.child_environment(run);env["CASTLEVANIA_LOG_FILE"]=str(log)
                with log.open("ab") as output:
                    result=subprocess.run([str(self.binary), mode], cwd=root, env=env,
                                          stdout=subprocess.PIPE, stderr=output, timeout=10)
                text=log.read_text()
            if failure:
                self.assertNotEqual(result.returncode,0,text);self.assertIn(failure,text)
            else:
                self.assertEqual(result.returncode,0,text)

    def test_pre_main_registers_only_without_run_or_events(self):self.fixture("register",no_run=True)
    def test_open_proxy_returns_real_move_session(self):self.fixture("open")
    def test_measured_proxy_factories_have_real_sessions(self):self.fixture("factories")
    def test_native_wait_queue_drain_copy_lifetime_and_shared_high_level_pop(self):self.fixture("common")
    def test_domain_subobjects_preserve_copy_event_semantics(self):self.fixture("domain")
    def test_generic_clone_borrows_process_state_after_original_close(self):self.fixture("clone")
    def test_logical_policy_fields_and_protocol_output_widths(self):self.fixture("policies")
    def test_suspended_tick_event_is_distinct_and_unsignaled(self):self.fixture("suspended")
    def test_gpu_error_copy_event_is_initially_unsignaled_and_host_callback_signals_only_it(self):self.fixture("gpu")
    def test_gpu_failure_before_event_query_is_retained(self):self.fixture("gpu-before-query")
    def test_gpu_event_rejects_unmeasured_input_handles_and_buffers(self):
        for mode in ("gpu-buffers","gpu-handle"):
            with self.subTest(mode=mode):self.fixture(mode,"unexpected transport")
    def test_cpu_boost_requested_modes_have_empty_output_without_changing_policy_or_events(self):self.fixture("cpu")
    def test_cpu_boost_rejects_type2_and_every_unmeasured_enum_width(self):
        for mode in ("cpu-type2","cpu-unknown","cpu-wide","cpu-negative"):
            with self.subTest(mode=mode):self.fixture(mode,"must be Normal0 or FastLoad1")
    def test_cpu_boost_requires_four_bounded_argument_bytes(self):
        for mode in ("cpu-truncated","cpu-oversized"):
            with self.subTest(mode=mode):self.fixture(mode,"argument size")
    def test_cpu_boost_rejects_unmeasured_transport_pid_handles_and_buffers(self):
        for mode in ("cpu-pid","cpu-handle","cpu-buffer","cpu-transport"):
            with self.subTest(mode=mode):self.fixture(mode,"unexpected transport")
    def test_resume_notification_preference_has_empty_output_without_fabricated_transitions_or_events(self):self.fixture("resume")
    def test_resume_notification_rejects_non_bool_values(self):
        for mode in ("resume-bool2","resume-bool255"):
            with self.subTest(mode=mode):self.fixture(mode,"not a bool")
    def test_resume_notification_requires_one_bounded_argument_byte(self):
        for mode in ("resume-truncated","resume-oversized"):
            with self.subTest(mode=mode):self.fixture(mode,"argument size")
    def test_resume_notification_rejects_unmeasured_transport_pid_handles_and_buffers(self):
        for mode in ("resume-pid","resume-handle","resume-buffer","resume-transport"):
            with self.subTest(mode=mode):self.fixture(mode,"unexpected transport")
    def test_missing_pid_fails(self):self.fixture("missing-pid","unexpected transport")
    def test_missing_process_copy_handle_fails(self):self.fixture("missing-copy","unexpected transport")
    def test_unmeasured_process_handle_fails(self):self.fixture("bad-process","current-process COPY")
    def test_nonzero_reserved_fails(self):self.fixture("reserved","reserved0")
    def test_tipc_transport_fails(self):self.fixture("transport","unexpected transport")
    def test_non_bool_preference_fails(self):self.fixture("bad-bool","not a bool")
    def test_zero_focus_is_not_a_protocol_enum(self):self.fixture("bad-focus","not a protocol FocusState")
    def test_foreground_rights_do_not_fake_focus(self):self.fixture("background-rights","not in focus")
    def test_extra_pid_fails(self):self.fixture("extra-pid","unexpected transport")
    def test_unexpected_buffer_fails(self):self.fixture("buffers","unexpected transport")
    def test_truncated_three_bool_arguments_fail(self):self.fixture("truncated","argument size")
    def test_missing_run_guard_fails(self):self.fixture("open","run root",no_run=True)
    def test_unknown_interfaces_and_commands_fail(self):
        for mode in ("service-unknown","proxy-unknown","common-unknown","self-unknown",
                     "window-unknown","functions-unknown","audio-unknown"):
            with self.subTest(mode=mode):self.fixture(mode,"command")


if __name__ == "__main__":
    unittest.main()
