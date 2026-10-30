"""Actual native IPC/domain/handle tests for measured ldr:ro registration.

Uses original tiny CMIF requests with real ipc.c/threads.c and retained RO state;
no game code, owned module input, permission result or load operation is used.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy


class NativeRoIpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-ro-ipc-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "nrr_validate.c"
#include "nrr_fixture.h"
static NrrFixtureKeys nrr_test_keys;static unsigned nrr_test_anchor;
static const char *ro_test_validate(const uint8_t *b,size_t n,uint64_t p,RuntimeNrrValidated *out){
 return nrr_test_anchor?nrr_validate_with_modulus(b,n,p,nrr_test_keys.root_modulus,out):runtime_nrr_validate(b,n,p,out);
}
static unsigned fixture_ro_live;
static void *ro_test_calloc(size_t count,size_t bytes){void *p=calloc(count,bytes);if(p)fixture_ro_live++;return p;}
static void *ro_test_malloc(size_t bytes){void *p=malloc(bytes);if(p)fixture_ro_live++;return p;}
static void ro_test_free(void *p){if(p){if(!fixture_ro_live)abort();fixture_ro_live--;free(p);}}
#define calloc ro_test_calloc
#define malloc ro_test_malloc
#define free ro_test_free
#define runtime_nrr_validate ro_test_validate
#include "ro_host.c"
#undef runtime_nrr_validate
#undef calloc
#undef malloc
#undef free
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
static uint32_t copy_values[2]={RO_CURRENT_PROCESS_HANDLE,RO_CURRENT_PROCESS_HANDLE};
static uint64_t wire_pid;
static unsigned initialize_type=6;
static unsigned wire_slack=16;
static void request(uint32_t *m,unsigned type,unsigned object,unsigned cmd,int pid,unsigned ncopy,unsigned nmove,
                    const void *data,unsigned size,unsigned buffer){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid||ncopy||nmove){m[1]=1u<<31;*p++=(pid?1u:0u)|(ncopy<<1)|(nmove<<5);
  if(pid){memcpy(p,&wire_pid,8);p+=2;}for(unsigned i=0;i<ncopy;i++)*p++=copy_values[i];for(unsigned i=0;i<nmove;i++)*p++=RO_CURRENT_PROCESS_HANDLE;
 }
 if(buffer&&buffer<=4){m[0]|=1u<<(12+buffer*4);p+=buffer==1?2:3;}
 uint8_t *words=(uint8_t *)p,*payload=(uint8_t *)(((uintptr_t)p+15)&~(uintptr_t)15);
 if(object){payload[0]=1;uint16_t n=(uint16_t)(16+size);memcpy(payload+2,&n,2);memcpy(payload+4,&object,4);payload+=16;}
 uint32_t header[4]={CMIF_IN_MAGIC,0,cmd,0};memcpy(payload,header,16);payload+=16;
 if(size)memcpy(payload,data,size);memset(payload+size,0xa5,wire_slack);
 unsigned words_used=(unsigned)(payload+size+wire_slack-words+3)/4;m[1]|=words_used;
 if(buffer==5)m[1]|=2u<<10; /* one empty receive descriptor after raw words */
}
static uint32_t *response(uint32_t *m){for(unsigned i=2;i<60;i++)if(m[i]==CMIF_OUT_MAGIC)return m+i;runtime_fail("missing CMIF response");}
static uint32_t result(uint32_t *m){return response(m)[2];}
static IpcSession *session(uint32_t handle){IpcSession *s=runtime_handle_get(handle,1);need(s!=NULL,"real live session handle");return s;}
static uint32_t moved(uint32_t *m){need((m[1]>>31)&&!((m[2]>>1)&15)&&((m[2]>>5)&15)==1,"one real MOVE handle");(void)session(m[3]);return m[3];}
static void close_handle(uint32_t handle){uint64_t r[32]={handle};need(svc_thread(0x16,r)&&!r[0]&&!runtime_handle_get(handle,1),"actual CloseHandle reclaims session slot");}
static uint32_t open_ro(uint32_t *m){
 const char name[8]="ldr:ro";request(m,6,0,1,0,0,0,name,8,0);fixture_sm_dispatch(m);need(!result(m),"SM open success");uint32_t h=moved(m);
 IpcSession *s=session(h);need(s->handler==ro_service&&s->retain==ro_retain&&s->close==ro_close,"real retained RO handler");
 RoProcessRegistration *state=s->state;need(state&&state->references==1&&!state->registered&&!state->host_pid,"open does not register a process");return h;
}
static uint32_t control(uint32_t handle,uint32_t *m,unsigned cmd,const void *data,unsigned bytes){
 request(m,5,0,cmd,0,0,0,data,bytes,0);fixture_dispatch(session(handle),m);need(!result(m),"actual CMIF control success");return cmd==0?response(m)[4]:moved(m);
}
static uint32_t initialize(uint32_t handle,uint32_t *m,unsigned object){
 uint64_t placeholder=0;request(m,initialize_type,object,4,1,1,0,&placeholder,8,0);fixture_dispatch(session(handle),m);
 need(!(m[1]>>31),"Initialize returns no COPY or MOVE handles");if(object)need(response(m)[-4]==0,"Initialize returns no domain objects");return result(m);
}
static void no_state_leaks(void){need(!fixture_ro_live&&!fixture_ipc_live()&&!ro_registered,"all state and registration released");for(unsigned i=1;i<MAX_H;i++)need(!g_h[i].type,"all runtime handle slots reclaimed");}
static void domain_close(uint32_t handle,uint32_t *m,unsigned object){
 memset(m,0,256);m[0]=6;m[1]=12;m[4]=2;m[5]=object;fixture_dispatch(session(handle),m);need(!result(m),"domain object close succeeds");
}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(fixture_registrations()==1&&!fixture_ro_live&&!fixture_ipc_live()&&!ro_registered,"constructor registers only, without state/handles/files");
 if(!strcmp(mode,"register")){no_state_leaks();return 0;}
 need(!pthread_key_create(&g_keythr,NULL),"thread key");g_cores_on=0;pthread_cond_init(&main_thread.cv,NULL);main_thread.cur_core=-1;pthread_setspecific(g_keythr,&main_thread);
 _Alignas(16) uint32_t m[64];uint32_t h=open_ro(m);RoProcessRegistration *state=session(h)->state;
 if(!strncmp(mode,"nrr-",4)){
  nrr_test_keys=nrr_fixture_keys();nrr_test_anchor=1;uint8_t *nrr=nrr_fixture_make(&nrr_test_keys,CASTLEVANIA_TITLE_ID);
  uint64_t input[6]={0,(uintptr_t)nrr,4096};unsigned object=0,size=24,copies=0;int pid=1;
  if(strcmp(mode,"nrr-before-registration"))need(!initialize(h,m,0),"process registered before NRR");
  if(!strcmp(mode,"nrr-zero-address"))input[1]=0;
  else if(!strcmp(mode,"nrr-unaligned-address"))input[1]++;
  else if(!strcmp(mode,"nrr-zero-size"))input[2]=0;
  else if(!strcmp(mode,"nrr-unaligned-size"))input[2]--;
  else if(!strcmp(mode,"nrr-oversized"))input[2]=RUNTIME_NRR_MAX_BYTES+4096;
  else if(!strcmp(mode,"nrr-overflow")){input[1]=UINT64_MAX-4095;input[2]=8192;}
  else if(!strcmp(mode,"nrr-unreadable"))input[1]=4096;
  else if(!strcmp(mode,"nrr-missing-pid"))pid=0;
  else if(!strcmp(mode,"nrr-copy-handle"))copies=1;
  else if(!strcmp(mode,"nrr-placeholder"))input[0]=1;
  else if(!strcmp(mode,"nrr-truncated")){object=control(h,m,0,NULL,0);size=16;}
  else if(!strcmp(mode,"nrr-raw-oversized")){object=control(h,m,0,NULL,0);size=48;}
  else if(!strcmp(mode,"nrr-kind")){nrr[0x33c]=1;nrr_fixture_sign_all(&nrr_test_keys,nrr,4096);}
  else if(!strcmp(mode,"nrr-program")){nrr_fixture_u64(nrr+0x330,CASTLEVANIA_TITLE_ID+1);nrr_fixture_sign_all(&nrr_test_keys,nrr,4096);}
  else if(!strcmp(mode,"nrr-tamper"))nrr[0x900]^=1;
  else if(!strcmp(mode,"nrr-production-rejects-test"))nrr_test_anchor=0;
  if(!strcmp(mode,"nrr-observed"))wire_slack=4;
  if(!strcmp(mode,"nrr-domain"))object=control(h,m,0,NULL,0);
  request(m,6,object,2,pid,copies,0,input,size,0);fixture_dispatch(session(h),m);need(!result(m),"valid signed NRR registered");
  need(state->nrr_count==1&&state->nrrs[0].address==(uintptr_t)nrr&&state->nrrs[0].size==4096&&state->nrrs[0].snapshot!=nrr&&
       !memcmp(state->nrrs[0].snapshot,nrr,4096)&&state->nrrs[0].validated.hash_count==2,"real immutable original snapshot/hash registry");
  need(fixture_ro_live==2,"state and one owned NRR snapshot");
  if(!strcmp(mode,"nrr-duplicate")){request(m,6,0,2,1,0,0,input,24,0);fixture_dispatch(session(h),m);return 4;}
  if(!strcmp(mode,"nrr-capacity")){
   void *block=NULL;need(!posix_memalign(&block,4096,RO_MAX_NRRS*4096),"capacity source");
   for(unsigned i=0;i<RO_MAX_NRRS;i++){uint8_t *page=(uint8_t *)block+i*4096;memcpy(page,nrr,4096);input[1]=(uintptr_t)page;
    request(m,6,0,2,1,0,0,input,24,0);fixture_dispatch(session(h),m);}
   return 4;
  }
  nrr[0x350]^=1;need(state->nrrs[0].snapshot[0x350]==0x11&&state->nrrs[0].snapshot[0x370]==0x22,"post-registration caller mutation cannot change trusted original hashes");
  if(!strcmp(mode,"nrr-clone")){uint32_t copy=control(h,m,2,NULL,0);close_handle(h);need(state->nrr_count==1&&fixture_ro_live==2,"clone keeps validated registry alive");h=copy;}
  close_handle(h);no_state_leaks();free(nrr);nrr_fixture_keys_close(&nrr_test_keys);return 0;
 }
 if(!strcmp(mode,"open")){close_handle(h);no_state_leaks();return 0;}
 if(!strcmp(mode,"initialize")||!strcmp(mode,"wire-pid")||!strcmp(mode,"no-context")){
  if(!strcmp(mode,"no-context"))initialize_type=4;
  wire_pid=!strcmp(mode,"wire-pid")?UINT64_MAX:0;need(!initialize(h,m,0),"measured registration succeeds");
  need(state->references==1&&state->registered&&state->host_pid==getpid()&&ro_registered==state,"honest native process identity and real registration state");
  close_handle(h);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"repeat")){
  need(!initialize(h,m,0)&&initialize(h,m,0)==RO_RESULT_INVALID_SESSION,"same-object repeat returns actual InvalidSession");
  need(state->references==1&&ro_registered==state,"failed repeat preserves registration");close_handle(h);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"independent")||!strcmp(mode,"close-unregistered")){
  uint32_t other=open_ro(m);RoProcessRegistration *second=session(other)->state;need(second!=state,"independent service states");
  need(!initialize(h,m,0)&&initialize(other,m,0)==RO_RESULT_INVALID_SESSION&&!second->registered,"second live same-process registration rejected");
  if(!strcmp(mode,"close-unregistered")){close_handle(other);need(ro_registered==state&&state->registered,"closing unregistered state cannot clear another's registration");close_handle(h);no_state_leaks();return 0;}
  close_handle(h);need(!ro_registered&&!initialize(other,m,0)&&ro_registered==second,"final close unregisters and permits later registration");close_handle(other);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"domain-release")){
  unsigned id=control(h,m,0,NULL,0);need(!initialize(h,m,id),"domain registration");domain_close(h,m,id);
  need(!fixture_ro_live&&!ro_registered&&fixture_ipc_live()==2,"last service object release unregisters even while empty domain transport remains");
  uint32_t other=open_ro(m);need(!initialize(other,m,0),"new service can register after root object close");close_handle(other);close_handle(h);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"clone-before")||!strcmp(mode,"clone-after")){
  if(!strcmp(mode,"clone-after"))need(!initialize(h,m,0),"register before clone");
  uint32_t copy=control(h,m,2,NULL,0);need(session(copy)->state==state&&state->references==2,"clone retains same state");
  close_handle(h);need(fixture_ro_live==1&&state->references==1,"original close cannot free clone's state");
  need(initialize(copy,m,0)==(!strcmp(mode,"clone-after")?RO_RESULT_INVALID_SESSION:0u),"clone observes shared registration");
  close_handle(copy);no_state_leaks();uint32_t reopened=open_ro(m);need(!initialize(reopened,m,0),"last clone release unregisters for reopened session");close_handle(reopened);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"domain")||!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-ex")||!strcmp(mode,"domain-copy")||!strcmp(mode,"domain-object-close")){
  unsigned id=control(h,m,0,NULL,0);need(id==1&&state->references==1,"conversion transfers first owner to domain root");
  if(!strcmp(mode,"domain-clone")||!strcmp(mode,"domain-clone-ex")){
   uint32_t tag=19;unsigned cmd=!strcmp(mode,"domain-clone-ex")?4:2;uint32_t copy=control(h,m,cmd,cmd==4?&tag:NULL,cmd==4?4:0);
   need(session(copy)->domain==session(h)->domain&&fixture_domain_refs(session(copy))==2&&state->references==1,"domain clone retains domain not duplicate root state");
   close_handle(h);need(!initialize(copy,m,id)&&state->registered&&state->references==1,"domain clone can register after original transport close");close_handle(copy);no_state_leaks();return 0;
  }
  if(!strcmp(mode,"domain-copy")||!strcmp(mode,"domain-object-close")){
   uint32_t copy=control(h,m,1,&id,4);need(session(copy)->state==state&&state->references==2,"CopyFromDomain retains real service state");
   if(!strcmp(mode,"domain-object-close")){domain_close(h,m,id);need(state->references==1,"root object closes while independent copy remains");}
   close_handle(h);need(fixture_ro_live==1&&state->references==1&&!initialize(copy,m,0),"copy survives entire domain/root destruction");close_handle(copy);no_state_leaks();return 0;
  }
  need(!initialize(h,m,id)&&state->registered,"domain cmd4 registers process");close_handle(h);no_state_leaks();return 0;
 }
 if(!strcmp(mode,"cycles")){
  close_handle(h);no_state_leaks();
  for(unsigned i=0;i<1000;i++){
   h=open_ro(m);need(!initialize(h,m,0),"cycle registration");unsigned id=control(h,m,0,NULL,0);uint32_t tag=i;
   uint32_t clone=control(h,m,4,&tag,4),copy=control(h,m,1,&id,4);close_handle(h);close_handle(clone);
   need(initialize(copy,m,0)==RO_RESULT_INVALID_SESSION,"copy retains initialized identity");close_handle(copy);no_state_leaks();
  }return 0;
 }
 if(!strcmp(mode,"unknown-control")){request(m,5,0,99,0,0,0,NULL,0,0);fixture_dispatch(session(h),m);return 4;}
 if(!strcmp(mode,"unknown")||!strcmp(mode,"map")||!strcmp(mode,"unmap")||!strcmp(mode,"unregister-nrr")||!strcmp(mode,"register-ex")){
  unsigned cmd=!strcmp(mode,"map")?0:!strcmp(mode,"unmap")?1:!strcmp(mode,"unregister-nrr")?3:!strcmp(mode,"register-ex")?10:999;
  need(!initialize(h,m,0),"registration before unsupported request");request(m,6,0,cmd,0,0,0,NULL,0,0);fixture_dispatch(session(h),m);return 4;
 }
 uint64_t raw[4]={0};unsigned type=6,object=0,bytes=8,ncopy=1,nmove=0,buffer=0;int pid=1;
 if(!strcmp(mode,"missing-pid"))pid=0;
 else if(!strcmp(mode,"missing-copy"))ncopy=0;
 else if(!strcmp(mode,"extra-copy"))ncopy=2;
 else if(!strcmp(mode,"move")){ncopy=0;nmove=1;}
 else if(!strcmp(mode,"bad-process"))copy_values[0]=7;
 else if(!strcmp(mode,"thread-pseudo"))copy_values[0]=0xffff8000u;
 else if(!strcmp(mode,"session-handle"))copy_values[0]=h;
 else if(!strcmp(mode,"nonzero-placeholder"))raw[0]=1;
 else if(!strcmp(mode,"tipc"))type=20;
 else if(!strcmp(mode,"x-buffer"))buffer=1;
 else if(!strcmp(mode,"a-buffer"))buffer=2;
 else if(!strcmp(mode,"b-buffer"))buffer=3;
 else if(!strcmp(mode,"w-buffer"))buffer=4;
 else if(!strcmp(mode,"c-buffer"))buffer=5;
 else if(!strcmp(mode,"truncated")){object=control(h,m,0,NULL,0);bytes=4;}
 else if(!strcmp(mode,"oversized")){object=control(h,m,0,NULL,0);bytes=32;}
 else return 5;
 request(m,type,object,4,pid,ncopy,nmove,raw,bytes,buffer);fixture_dispatch(session(h),m);return 4;
}
''')
        transport = directory / "transport.c"
        transport.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
static void *allocations[1024];static unsigned live;
static void *ipc_test_calloc(size_t n,size_t size){
 void *p=calloc(n,size);if(!p)abort();for(unsigned i=0;i<1024;i++)if(!allocations[i]){allocations[i]=p;live++;return p;}abort();
}
static void ipc_test_free(void *p){if(!p)return;for(unsigned i=0;i<1024;i++)if(allocations[i]==p){allocations[i]=NULL;live--;free(p);return;}abort();}
#define calloc ipc_test_calloc
#define free ipc_test_free
#include "ipc.c"
#undef calloc
#undef free
void fixture_dispatch(IpcSession *s,uint32_t *m){dispatch(s,m);}
void fixture_sm_dispatch(uint32_t *m){IpcSession s={.name="sm:",.handler=sm};dispatch(&s,m);}
unsigned fixture_registrations(void){unsigned n=0;for(unsigned i=0;i<nservices;i++)n+=!strcmp(services[i].name,"ldr:ro");return n;}
unsigned fixture_ipc_live(void){return live;}
unsigned fixture_domain_refs(IpcSession *s){return s->domain?s->domain->sessions:0;}
''')
        cls.binary = directory / "ro-ipc-native"
        cls.disabled = directory / "ro-ipc-disabled"
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1",
                  "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1",
                  "-I" + str(policy.ROOT / "runtime"),
                  "-I" + str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"),
                  "-I" + str(policy.ROOT / "tests"), str(source), str(transport),
                  "-framework", "Security", "-framework", "CoreFoundation", "-Wl,-dead_strip"]
        for defines, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.disabled)]:
            result = subprocess.run(common + defines + ["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, failure=None, no_run=False, disabled=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-ro-run-") as directory:
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
                self.assertEqual(before, {str(p.relative_to(root)) for p in root.rglob("*")},
                                 "registration creates no assets, profiles or permission files")
            if failure:
                self.assertNotEqual(result.returncode, 0, text)
                self.assertIn(failure, text)
            else:
                self.assertEqual(result.returncode, 0, text)
            return text

    def test_constructor_only_registers_without_state_allocations_or_files(self): self.fixture("register", no_run=True)
    def test_default_disabled_constructor_still_has_no_side_effects(self): self.fixture("register", no_run=True, disabled=True)
    def test_service_open_allocates_then_final_close_frees_real_state(self): self.fixture("open")
    def test_cmd4_registers_actual_host_identity_with_empty_output(self): self.fixture("initialize")
    def test_non_context_cmif_type4_has_same_measured_registration(self): self.fixture("no-context")
    def test_wire_pid_is_not_trusted_as_authenticated_process_identity(self): self.fixture("wire-pid")
    def test_repeat_returns_exact_invalid_session_and_preserves_first_registration(self): self.fixture("repeat")
    def test_independent_session_cannot_register_same_process_until_final_close(self): self.fixture("independent")
    def test_unregistered_independent_close_cannot_remove_other_registration(self): self.fixture("close-unregistered")
    def test_clone_before_registration_survives_original_close(self): self.fixture("clone-before")
    def test_registered_clone_keeps_identity_then_last_close_releases_it(self): self.fixture("clone-after")
    def test_real_domain_initialization_and_final_release(self): self.fixture("domain")
    def test_domain_clone_retains_root_after_original_transport_close(self): self.fixture("domain-clone")
    def test_domain_clone_ex_control4_is_not_service_cmd4(self): self.fixture("domain-clone-ex")
    def test_copy_from_domain_survives_entire_domain_destruction(self): self.fixture("domain-copy")
    def test_root_object_close_does_not_free_live_independent_copy(self): self.fixture("domain-object-close")
    def test_last_domain_object_release_unregisters_before_transport_close(self): self.fixture("domain-release")
    def test_1000_actual_registration_domain_clone_copy_close_cycles_leave_no_state_or_handles(self): self.fixture("cycles")
    def test_missing_pid_or_copy_and_extra_or_moved_handles_fail(self):
        for mode in ("missing-pid", "missing-copy", "extra-copy", "move"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_unknown_thread_or_session_process_handles_fail(self):
        for mode in ("bad-process", "thread-pseudo", "session-handle"):
            with self.subTest(mode=mode): self.fixture(mode, "current-process COPY handle")
    def test_nonzero_client_pid_placeholder_fails(self): self.fixture("nonzero-placeholder", "placeholder must be zero")
    def test_all_buffer_families_and_tipc_fail(self):
        for mode in ("x-buffer", "a-buffer", "b-buffer", "w-buffer", "c-buffer", "tipc"):
            with self.subTest(mode=mode): self.fixture(mode, "unexpected transport")
    def test_truncated_or_oversized_domain_raw_input_fails(self):
        for mode in ("truncated", "oversized"):
            with self.subTest(mode=mode): self.fixture(mode, "argument size")
    def test_unimplemented_load_map_nrr_or_unknown_commands_never_succeed(self):
        for mode in ("map", "unmap", "unregister-nrr", "register-ex", "unknown"):
            with self.subTest(mode=mode): self.fixture(mode, "ldr:ro: command")
    def test_unknown_control_does_not_reach_registration_handler(self): self.fixture("unknown-control", "control command 99 not implemented")
    def test_checked_host_run_is_required(self): self.fixture("open", "run root", no_run=True)
    def test_compile_default_gate_prevents_open(self): self.fixture("open", "disabled at compile time", disabled=True)
    def test_cmd2_validated_snapshot_retains_original_hashes_after_source_mutation(self): self.fixture("nrr-valid")
    def test_cmd2_observed_raw28_shape_registers_real_snapshot(self):
        self.assertIn("cmd=2 type=6 bytes=28", self.fixture("nrr-observed"))
    def test_cmd2_registry_survives_clone_until_last_close_then_frees(self): self.fixture("nrr-clone")
    def test_cmd2_real_domain_request_registers_then_final_release_frees_snapshot(self): self.fixture("nrr-domain")
    def test_cmd2_requires_live_process_registration(self): self.fixture("nrr-before-registration", "requires live current-process")
    def test_cmd2_requires_aligned_bounded_nonoverflowing_memory(self):
        for mode in ("nrr-zero-address", "nrr-unaligned-address", "nrr-zero-size", "nrr-unaligned-size", "nrr-oversized", "nrr-overflow"):
            with self.subTest(mode=mode): self.fixture(mode, "address/size bounds")
    def test_cmd2_unreadable_memory_is_rejected_without_host_crash(self): self.fixture("nrr-unreadable", "not fully readable")
    def test_cmd2_transport_pid_and_raw_shape_are_checked(self):
        for mode, message in (("nrr-missing-pid", "unexpected transport"), ("nrr-copy-handle", "unexpected transport"),
                              ("nrr-placeholder", "placeholder must be zero"), ("nrr-truncated", "argument size"),
                              ("nrr-raw-oversized", "argument size")):
            with self.subTest(mode=mode): self.fixture(mode, message)
    def test_cmd2_rejects_bad_program_kind_signature_or_untrusted_root(self):
        for mode, message in (("nrr-program", "program identity"), ("nrr-kind", "unsupported kind"),
                              ("nrr-tamper", "NRR signature"), ("nrr-production-rejects-test", "certificate signature")):
            with self.subTest(mode=mode): self.fixture(mode, message)
    def test_cmd2_rejects_duplicate_address_and_registry_overflow(self):
        for mode, message in (("nrr-duplicate", "already registered"), ("nrr-capacity", "registry capacity")):
            with self.subTest(mode=mode): self.fixture(mode, message)


if __name__ == "__main__":
    unittest.main()
