"""Native AOC CMIF/handles/event tests; no DLC, SDK, guest or GPU input."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeAocIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-aoc-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "aoc_host.c"
void fixture_dispatch(IpcSession *,uint32_t *);
void fixture_sm(IpcSession *,const IpcRequest *,IpcResponse *);
unsigned fixture_registration_count(void);
int fixture_output_descriptor_matches(uint32_t *,const void *,uint64_t);
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
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,const void *data,unsigned size,void *out,uint64_t out_size){
 memset(m,0,256);m[0]=type|(out?1u<<24:0);uint32_t *p=m+2;
 if(pid){m[1]=1u<<31;*p++=1;*p++=0;*p++=0;}
 if(out){uint64_t a=(uintptr_t)out;p[0]=(uint32_t)out_size;p[1]=(uint32_t)a;p[2]=(uint32_t)(((a>>32)&15)<<28)|((uint32_t)(a>>36)&7)<<2|((uint32_t)(out_size>>32)&15)<<24;p+=3;}
 uint8_t *payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t h[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,h,16);payload+=16;if(size)memcpy(payload,data,size);
 memset(payload+size,0xa5,16);m[1]|=(uint32_t)((payload+size+16-(uint8_t *)p+3)/4);
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("missing CMIF response");}
static uint32_t value(uint32_t *m){return response(m)[4];}
static uint32_t copy_handle(uint32_t *m){need((m[1]>>31)&&((m[2]>>1)&15)==1&&!((m[2]>>5)&15),"event must be COPY");return m[3];}
static IpcSession *moved(uint32_t *m){need((m[1]>>31)&&((m[2]>>5)&15)==1&&!((m[2]>>1)&15),"service must be real MOVE session");IpcSession *s=runtime_handle_get(m[3],1);need(s!=NULL,"real session");return s;}
static void call(IpcSession *s,uint32_t *m,unsigned cmd,const void *data,unsigned size,void *out,uint64_t out_size){request(m,6,0,cmd,1,data,size,out,out_size);if(out)need(fixture_output_descriptor_matches(m,out,out_size),"actual HIPC B descriptor address/size");fixture_dispatch(s,m);need(!response(m)[2],"CMIF success");}
static int signaled(uint32_t h){pthread_mutex_lock(&G);int bad=0,yes=sig_obj(h,&bad);pthread_mutex_unlock(&G);need(!bad,"readable event valid");return yes;}
static uint64_t wait_event(uint32_t h){uint64_t r[32]={0,(uintptr_t)&h,1,0};need(svc_thread(0x18,r),"actual native WaitSynchronization");return r[0];}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];need(!aoc_state.list_changed_event,"no pre-main event creation");
 if(!strcmp(mode,"register")){need(fixture_registration_count()==1,"exact aoc:u registration");return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];IpcSession sm={.name="sm:",.handler=fixture_sm};const char name[8]="aoc:u";
 request(m,6,0,1,0,name,8,NULL,0);fixture_dispatch(&sm,m);IpcSession *aoc=moved(m);need(aoc->handler==aoc_service&&aoc->state==&aoc_state,"real registered AOC service");
 if(!strcmp(mode,"open"))return 0;
 uint64_t pid0=0;uint32_t args[4]={0,4,0,0},out[4]={0x11111111,0x22222222,0x33333333,0x44444444};
 if(!strcmp(mode,"domain")){
  request(m,5,0,0,0,NULL,0,NULL,0);fixture_dispatch(aoc,m);unsigned id=value(m);need(id==1,"AOC domain root");
  request(m,6,id,2,1,&pid0,8,NULL,0);fixture_dispatch(aoc,m);need(!response(m)[2]&&!value(m),"domain Count zero");
  request(m,6,id,10,1,&pid0,8,NULL,0);fixture_dispatch(aoc,m);uint32_t event=copy_handle(m);need(!signaled(event)&&wait_event(event)==R_TIMEOUT,"domain COPY event unsignaled");close_handle(event);return 0;
 }
 if(!strcmp(mode,"clone")){request(m,5,0,2,0,NULL,0,NULL,0);fixture_dispatch(aoc,m);IpcSession *clone=moved(m);runtime_ipc_session_closed(aoc);aoc=clone;}
 if(!strcmp(mode,"count")||!strcmp(mode,"clone")){
  call(aoc,m,2,&pid0,8,NULL,0);need(!value(m),"no installed DLC count");IpcRequest rq={.type=6,.cmd=2,.has_pid=1,.data=(uint8_t*)&pid0,.data_size=8};IpcResponse rs={0};aoc_service(aoc,&rq,&rs);need(rs.data_size==4&&!rs.ncopy&&!rs.nmove,"count exact u32 output");return 0;
 }
 if(!strcmp(mode,"list")||!strcmp(mode,"list-zero")||!strcmp(mode,"list-offset")){
  if(!strcmp(mode,"list-zero"))args[1]=0;if(!strcmp(mode,"list-offset"))args[0]=UINT32_MAX;
  call(aoc,m,3,args,16,out,!strcmp(mode,"list-zero")?0:sizeof out);need(!value(m),"empty inventory lists zero at every offset");
  need(out[0]==0x11111111&&out[1]==0x22222222&&out[2]==0x33333333&&out[3]==0x44444444,"no fabricated entries or writes");
  call(aoc,m,2,&pid0,8,NULL,0);need(!value(m),"count/list consistent");return 0;
 }
 if(!strcmp(mode,"event")){
  call(aoc,m,10,&pid0,8,NULL,0);uint32_t first=copy_handle(m);call(aoc,m,10,&pid0,8,NULL,0);uint32_t other=copy_handle(m);
  need(first!=other&&!signaled(first)&&!signaled(other)&&wait_event(first)==R_TIMEOUT,"distinct readable copies initially unsignaled");
  call(aoc,m,2,&pid0,8,NULL,0);call(aoc,m,3,args,16,out,sizeof out);need(!signaled(first),"queries do not invent inventory changes");close_handle(first);
  need(!signaled(other)&&wait_event(other)==R_TIMEOUT,"second copy valid after first closes");close_handle(other);
  for(unsigned i=0;i<1000;i++){call(aoc,m,10,&pid0,8,NULL,0);close_handle(copy_handle(m));}return 0;
 }
 if(!strcmp(mode,"unknown")||!strcmp(mode,"prepare")||!strcmp(mode,"purchase")||!strcmp(mode,"mount")||!strcmp(mode,"legacy-event")){
  unsigned cmd=!strcmp(mode,"prepare")?7:!strcmp(mode,"purchase")?100:!strcmp(mode,"mount")?11:!strcmp(mode,"legacy-event")?8:999;
  call(aoc,m,cmd,&pid0,8,NULL,0);return 4;
 }
 IpcRequest rq={.type=6,.cmd=2,.has_pid=1,.data=(uint8_t*)&pid0,.data_size=8};IpcResponse rs={0};
 if(!strcmp(mode,"missing-pid"))rq.has_pid=0;
 else if(!strcmp(mode,"extra-handle"))rq.ncopy=1;
 else if(!strcmp(mode,"extra-buffer"))rq.nx=1;
 else if(!strcmp(mode,"transport"))rq.type=16;
 else if(!strcmp(mode,"truncated"))rq.data_size=7;
 else if(!strcmp(mode,"pid-placeholder"))pid0=1;
 else if(!strcmp(mode,"list-small")){rq.cmd=3;rq.data=(uint8_t*)args;rq.data_size=16;rq.nb=1;rq.b[0]=(IpcBuffer){(uintptr_t)out,12,0};}
 else if(!strcmp(mode,"list-overflow")){rq.cmd=3;rq.data=(uint8_t*)args;rq.data_size=16;rq.nb=1;rq.b[0]=(IpcBuffer){UINT64_MAX-4,16,0};}
 else if(!strcmp(mode,"list-missing-buffer")){rq.cmd=3;rq.data=(uint8_t*)args;rq.data_size=16;}
 else return 5;
 aoc_service(aoc,&rq,&rs);return 4;
}
''')
        transport = directory / "transport.c"
        transport.write_text('''#include "ipc.c"
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm(IpcSession *s,const IpcRequest *q,IpcResponse *r){sm(s,q,r);}
unsigned fixture_registration_count(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"aoc:u");return n;}
int fixture_output_descriptor_matches(uint32_t *m,const void *p,uint64_t n){IpcRequest q;const uint32_t *w;unsigned d;parse(m,&q,&w,&d);return q.nb==1&&q.b[0].addr==(uintptr_t)p&&q.b[0].size==n;}
''')
        cls.binary = directory / "aoc-ipc-fixture"
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
        with tempfile.TemporaryDirectory(prefix="castlevania-aoc-run-") as directory:
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

    def test_pre_main_registers_only_without_events_or_environment(self):self.fixture("register",no_run=True)
    def test_service_manager_returns_real_moved_aoc_session(self):self.fixture("open")
    def test_empty_inventory_count_is_exact_u32(self):self.fixture("count")
    def test_empty_list_preserves_buffer_and_agrees_with_count(self):self.fixture("list")
    def test_zero_capacity_list_returns_no_entries(self):self.fixture("list-zero")
    def test_out_of_range_offset_returns_no_entries(self):self.fixture("list-offset")
    def test_static_inventory_event_is_unsignaled_and_copy_handles_close_independently(self):self.fixture("event")
    def test_domain_count_and_readable_copy_event(self):self.fixture("domain")
    def test_clone_keeps_process_lifetime_policy(self):self.fixture("clone")
    def test_missing_pid_fails(self):self.fixture("missing-pid","unexpected transport")
    def test_unmeasured_handles_fail(self):self.fixture("extra-handle","unexpected transport")
    def test_unmeasured_buffers_fail(self):self.fixture("extra-buffer","unexpected transport")
    def test_unmeasured_transport_fails(self):self.fixture("transport","unexpected transport")
    def test_truncated_input_fails(self):self.fixture("truncated","argument size")
    def test_nonzero_client_process_placeholder_fails(self):self.fixture("pid-placeholder","placeholder must be zero")
    def test_list_capacity_must_fit_requested_indices(self):self.fixture("list-small","buffer bounds")
    def test_list_address_overflow_fails(self):self.fixture("list-overflow","buffer bounds")
    def test_list_requires_output_mapalias_descriptor(self):self.fixture("list-missing-buffer","unexpected transport")
    def test_missing_checked_host_run_fails(self):self.fixture("open","run root",no_run=True)
    def test_unmeasured_prepare_purchase_mount_legacy_and_unknown_commands_fail(self):
        for mode in ("prepare","purchase","mount","legacy-event","unknown"):
            with self.subTest(mode=mode):self.fixture(mode,"command")


if __name__ == "__main__":
    unittest.main()
