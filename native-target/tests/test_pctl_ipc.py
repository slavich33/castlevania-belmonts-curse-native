"""Native measured PCTL lifecycle wire tests; no restriction policy or guest input."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativePctlIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-pctl-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "pctl_host.c"
void fixture_dispatch(IpcSession *,uint32_t *);
void fixture_sm(IpcSession *,const IpcRequest *,IpcResponse *);
unsigned fixture_registration_count(void);
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
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,const void *data,unsigned size){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;if(pid){m[1]=1u<<31;*p++=1;*p++=0;*p++=0;}
 uint8_t *payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t h[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,h,16);payload+=16;if(size)memcpy(payload,data,size);
 memset(payload+size,0xa5,16);m[1]|=(uint32_t)((payload+size+16-(uint8_t *)p+3)/4);
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("missing CMIF response");}
static uint32_t value(uint32_t *m){return response(m)[4];}
static IpcSession *moved(uint32_t *m){need((m[1]>>31)&&((m[2]>>5)&15)==1&&!((m[2]>>1)&15),"interface must be real MOVE session");IpcSession *s=runtime_handle_get(m[3],1);need(s!=NULL,"real moved session");return s;}
static void call(IpcSession *s,uint32_t *m,unsigned cmd,int pid,const void *data,unsigned size){request(m,6,0,cmd,pid,data,size);fixture_dispatch(s,m);need(!response(m)[2],"CMIF success");}
static IpcSession *open_factory(uint32_t *m,unsigned family){IpcSession sm={.name="sm:",.handler=fixture_sm};char name[8]={0};strcpy(name,pctl_families[family].factory_name);call(&sm,m,1,0,name,8);IpcSession *s=moved(m);need(s->handler==pctl_factory&&s->state==&pctl_families[family],"service manager preserves factory family");return s;}
static IpcSession *create(IpcSession *factory,uint32_t *m){uint64_t reserved=0;call(factory,m,1,1,&reserved,8);IpcSession *s=moved(m);need(s->handler==pctl_service,"actual service handler");return s;}
static void initialize(IpcSession *s,uint32_t *m){call(s,m,1,0,NULL,0);need(!(m[1]>>31)&&((PctlObject*)s->state)->initialized,"Initialize persists state without output handles");}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");}
static uint32_t session_handle(IpcSession *s){for(unsigned i=1;i<MAX_H;i++)if(g_h[i].type==O_SESSION&&g_h[i].obj==s)return 0x1000+i;runtime_fail("session handle missing");}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];need(!pctl_used,"no pre-main service objects");
 if(!strcmp(mode,"register")){need(fixture_registration_count()==4,"four distinct named PCTL factories");return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];IpcSession *factory=open_factory(m,0);uint64_t reserved=0;
 if(!strcmp(mode,"family-loop")){
  PctlObject *objects[4];for(unsigned i=0;i<4;i++){IpcSession *f=i?open_factory(m,i):factory;IpcSession *s=create(f,m);objects[i]=s->state;need(objects[i]->family==&pctl_families[i]&&!objects[i]->initialized,"factory family retained without implicit Initialize");}
  IpcSession first={.name=pctl_families[0].service_name,.handler=pctl_service,.state=objects[0]};initialize(&first,m);
  for(unsigned i=1;i<4;i++)need(!objects[i]->initialized,"Initialize does not change other family objects");return 0;
 }
 if(!strcmp(mode,"domain")||!strcmp(mode,"domain-copy")){
  request(m,5,0,0,0,NULL,0);fixture_dispatch(factory,m);unsigned factory_id=value(m);need(factory_id==1,"factory domain object");
  request(m,6,factory_id,1,1,&reserved,8);fixture_dispatch(factory,m);unsigned service_id=value(m);need(!response(m)[2]&&response(m)[-4]==1&&service_id>1&&!(m[1]>>31),"factory returns domain object instead of move handle");
  if(!strcmp(mode,"domain-copy")){
   request(m,5,0,1,0,&service_id,4);fixture_dispatch(factory,m);IpcSession *copy=moved(m);PctlObject *object=copy->state;
   close_handle(session_handle(factory));need(object==&pctl_objects[0]&&!object->initialized,"copied domain child state survives entire domain destruction");initialize(copy,m);return 0;
  }
  request(m,6,service_id,1,0,NULL,0);fixture_dispatch(factory,m);need(!response(m)[2]&&pctl_objects[0].initialized,"domain Initialize reaches persisted service state");return 0;
 }
 if(!strcmp(mode,"factory-unknown")||!strcmp(mode,"factory-legacy")){call(factory,m,!strcmp(mode,"factory-legacy")?0:999,1,&reserved,8);return 4;}
 if(!strcmp(mode,"factory-missing-pid")){call(factory,m,1,0,&reserved,8);return 4;}
 if(!strcmp(mode,"factory-reserved")){reserved=1;call(factory,m,1,1,&reserved,8);return 4;}
 if(!strcmp(mode,"factory-clone")){uint32_t original=session_handle(factory);request(m,5,0,2,0,NULL,0);fixture_dispatch(factory,m);factory=moved(m);close_handle(original);}
 if(!strcmp(mode,"budget")){for(unsigned i=0;i<=PCTL_OBJECTS;i++)(void)create(factory,m);return 4;}
 IpcSession *service=create(factory,m);PctlObject *object=service->state;need(!object->initialized,"CreateServiceWithoutInitialize is uninitialized");
 if(!strcmp(mode,"create"))return 0;
 if(!strcmp(mode,"distinct-children")){IpcSession *other=create(factory,m);PctlObject *second=other->state;need(second!=object&&second->family==object->family&&!second->initialized,"same-family children own distinct lifecycle states");initialize(service,m);need(!second->initialized,"Initialize does not affect another same-family child");return 0;}
 if(!strcmp(mode,"service-clone")){uint32_t original=session_handle(service);request(m,5,0,2,0,NULL,0);fixture_dispatch(service,m);service=moved(m);close_handle(original);need(service->state==object,"clone borrows live process-lifetime object");}
 if(!strcmp(mode,"close-factory"))close_handle(session_handle(factory));
 if(!strcmp(mode,"service-unknown")||!strcmp(mode,"permission")||!strcmp(mode,"restriction")||!strcmp(mode,"settings")||!strcmp(mode,"event")){
  unsigned cmd=!strcmp(mode,"permission")?1001:!strcmp(mode,"restriction")?1031:!strcmp(mode,"settings")?1035:!strcmp(mode,"event")?1432:999;
  call(service,m,cmd,0,NULL,0);return 4;
 }
 if(!strcmp(mode,"extra-pid")){call(service,m,1,1,NULL,0);return 4;}
 if(!strcmp(mode,"buffers")||!strcmp(mode,"handles")||!strcmp(mode,"transport")||!strcmp(mode,"truncated")){
  IpcRequest rq={.type=6,.cmd=1,.has_pid=1,.data=(uint8_t*)&reserved,.data_size=8};IpcResponse rs={0};
  if(!strcmp(mode,"buffers"))rq.nx=1;else if(!strcmp(mode,"handles"))rq.ncopy=1;else if(!strcmp(mode,"transport"))rq.type=16;else rq.data_size=7;
  pctl_factory(factory,&rq,&rs);return 4;
 }
 initialize(service,m);initialize(service,m);
 IpcRequest rq={.type=6,.cmd=1};IpcResponse rs={0};pctl_service(service,&rq,&rs);need(!rs.data_size&&!rs.ncopy&&!rs.nmove&&object->initialized,"Initialize exact empty output and retained state");return 0;
}
''')
        transport = directory / "transport.c"
        transport.write_text('''#include "ipc.c"
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm(IpcSession *s,const IpcRequest *q,IpcResponse *r){sm(s,q,r);}
unsigned fixture_registration_count(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strncmp(services[i].name,"pctl",4);return n;}
''')
        cls.binary = directory / "pctl-ipc-fixture"
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
        with tempfile.TemporaryDirectory(prefix="castlevania-pctl-run-") as directory:
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

    def test_pre_main_only_registers_four_factories_without_environment(self):self.fixture("register",no_run=True)
    def test_factory_returns_real_uninitialized_service_move_session(self):self.fixture("create")
    def test_initialize_persists_per_object_state_with_exact_empty_output(self):self.fixture("initialize")
    def test_four_named_family_objects_keep_distinct_identity_and_state(self):self.fixture("family-loop")
    def test_domain_factory_and_service_initialize(self):self.fixture("domain")
    def test_copied_domain_child_survives_entire_domain_destruction(self):self.fixture("domain-copy")
    def test_same_family_children_keep_independent_initialize_state(self):self.fixture("distinct-children")
    def test_service_clone_survives_original_handle_close(self):self.fixture("service-clone")
    def test_factory_clone_survives_original_handle_close(self):self.fixture("factory-clone")
    def test_child_remains_valid_after_factory_close(self):self.fixture("close-factory")
    def test_missing_factory_pid_fails(self):self.fixture("factory-missing-pid","unexpected transport")
    def test_nonzero_factory_pid_placeholder_fails(self):self.fixture("factory-reserved","placeholder must be zero")
    def test_initialize_rejects_extra_pid(self):self.fixture("extra-pid","unexpected transport")
    def test_unmeasured_buffers_fail(self):self.fixture("buffers","unexpected transport")
    def test_unmeasured_handles_fail(self):self.fixture("handles","unexpected transport")
    def test_unmeasured_transport_fails(self):self.fixture("transport","unexpected transport")
    def test_truncated_factory_input_fails(self):self.fixture("truncated","argument size")
    def test_missing_checked_host_run_fails(self):self.fixture("create","run root",no_run=True)
    def test_host_object_allocation_is_bounded(self):self.fixture("budget","object budget exhausted")
    def test_no_permission_restriction_settings_event_or_unknown_results_are_invented(self):
        for mode in ("permission","restriction","settings","event","service-unknown","factory-unknown","factory-legacy"):
            with self.subTest(mode=mode):self.fixture(mode,"command")


if __name__ == "__main__":
    unittest.main()
