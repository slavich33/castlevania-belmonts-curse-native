"""Real native Create/Start/Exit/Close/GetInfo paths; no game, SDK or GPU code."""
from pathlib import Path
import subprocess
import tempfile
import unittest


FIXTURE = r'''
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
static _Atomic int fail_allocate,fail_condition,fail_create;
static void *fixture_calloc(size_t n,size_t s){if(atomic_exchange(&fail_allocate,0))return NULL;return calloc(n,s);}
static int fixture_cond_init(pthread_cond_t *c,const pthread_condattr_t *a){if(atomic_exchange(&fail_condition,0))return EAGAIN;return pthread_cond_init(c,a);}
static int fixture_pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void*),void *p){if(atomic_exchange(&fail_create,0))return EAGAIN;return pthread_create(t,a,f,p);}
/* Fixture-only link substitutions inject native failure results. Production
 * source has no test switches; successful calls use the real pthread API. */
#define calloc fixture_calloc
#define pthread_cond_init fixture_cond_init
#define pthread_create fixture_pthread_create
#include "threads.c"
#undef calloc
#undef pthread_cond_init
#undef pthread_create

pthread_key_t runtime_keys[8];
static _Atomic unsigned guest_entries,tls_entries;
static _Atomic int block_tls,tls_blocked,release_tls;
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){
 atomic_fetch_add(&tls_entries,1);
 if(atomic_load(&block_tls)){atomic_store(&tls_blocked,1);while(!atomic_load(&release_tls))usleep(100);}
}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void*)){(void)c;(void)a;(void)f;runtime_fail("guest stack switching must not run");}
static void need(int ok,const char *s){if(!ok)runtime_fail(s);}
typedef struct { _Atomic int entered,release; } Worker;
static void original_native_entry(uint64_t argument){
 Worker *w=(void *)(uintptr_t)argument;atomic_fetch_add(&guest_entries,1);atomic_store(&w->entered,1);
 while(!atomic_load(&w->release))usleep(100);
}
void dm_thread_enter(uint64_t entry,uint64_t argument,uint64_t stack,uint64_t *context){
 (void)stack;need(context[0]==0,"fixture uses native stack only");
 need(entry==(uint64_t)(uintptr_t)original_native_entry,"only original authored native fixture entry");
 original_native_entry(argument);
 uint64_t r[32]={0};(void)svc_thread(0x0a,r);runtime_fail("real ExitThread must not return");
}
static uint64_t free_count(void){uint64_t r[32]={0,24,0xffff8001,0};need(svc_thread(0x29,r)&&!r[0],"actual GetInfo24");return r[1];}
static unsigned handles_used(void){unsigned n=0;pthread_mutex_lock(&G);for(unsigned i=1;i<MAX_H;i++)n+=g_h[i].type!=O_FREE;pthread_mutex_unlock(&G);return n;}
static unsigned objects_used(void){unsigned n=0;pthread_mutex_lock(&G);for(thr_t *t=g_all;t;t=t->all)n++;need(n==g_thread_objects,"retained object list and reserved quota agree at quiescence");pthread_mutex_unlock(&G);return n;}
static void wait_count(uint64_t expected){uint64_t deadline=runtime_now_ns()+5000000000ull;while(free_count()!=expected){need(runtime_now_ns()<deadline,"bounded actual pthread cleanup");usleep(100);}}
static void wait_flag(_Atomic int *flag){uint64_t deadline=runtime_now_ns()+5000000000ull;while(!atomic_load(flag)){need(runtime_now_ns()<deadline,"bounded native worker handoff");usleep(100);}}
static uint64_t create(Worker *w,uint32_t *handle){
 uint64_t r[32]={0,(uintptr_t)original_native_entry,(uintptr_t)w,0x10000,44,(uint64_t)-1};uint64_t original=r[1];
 need(svc_thread(0x08,r),"CreateThread handled");if(!r[0])*handle=(uint32_t)r[1];else need(r[1]==original,"Create failure does not publish output handle");return r[0];
}
static uint64_t start(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x09,r),"StartThread handled");return r[0];}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"actual CloseHandle");}
static int is_exited(uint32_t h){pthread_mutex_lock(&G);thr_t *t=h_peek(h,O_THREAD);int exited=t&&t->exited;pthread_mutex_unlock(&G);return exited;}
static void wait_exited(uint32_t h){uint64_t deadline=runtime_now_ns()+5000000000ull;while(!is_exited(h)){need(runtime_now_ns()<deadline,"real ExitThread completion");usleep(100);}}
typedef struct {uint32_t handle;uint64_t result;} StartRace;
static void *native_start(void *p){StartRace *race=p;race->result=start(race->handle);return NULL;}
typedef struct {Worker worker;uint32_t handles[127];unsigned count;} Creator;
static _Atomic unsigned creators_ready;
static _Atomic int creators_go;
static void *native_creator(void *p){
 Creator *creator=p;atomic_fetch_add(&creators_ready,1);while(!atomic_load(&creators_go))sched_yield();
 for(unsigned i=0;i<127;i++){
  uint32_t h=0;uint64_t result=create(&creator->worker,&h);
  if(result==0x10801)return NULL;
  need(!result,"concurrent reservation succeeds or reaches exact quota");creator->handles[creator->count++]=h;
 }
 return NULL;
}

int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(free_count()==128,"explicit128 host policy before main");
 /* Reproduce loader's real prerequisite: its eight Darwin runtime keys are
  * allocated before svc_thread_main_init. The inherited key0 sentinel is not
  * changed or claimed fixed by these quota tests. No guest TLS is initialized. */
 for(unsigned i=0;i<8;i++)need(!pthread_key_create(&runtime_keys[i],NULL),"ordinary loader key prerequisite");
 g_cores_on=0;uint32_t main=svc_thread_main_init();
 need(main&&free_count()==127&&objects_used()==1&&handles_used()==1,"main reserves one actual object");
 if(!strcmp(mode,"main")){puts("ok");return 0;}
 if(!strcmp(mode,"query-guards")){
  uint64_t r[32]={0,24,0xdead,1};need(svc_thread(0x29,r)&&r[0]==0xe801,"subtype guard precedes handle");
  r[0]=0;r[1]=24;r[3]=0;need(svc_thread(0x29,r)&&r[0]==0xe401,"unknown process handle");
  r[0]=0;r[1]=24;r[2]=0xffff8000;need(svc_thread(0x29,r)&&r[0]==0xe401,"thread pseudo is not process");
  r[0]=0x1234;r[1]=28;r[2]=0xffff8001;uint64_t before[32];memcpy(before,r,sizeof r);need(!svc_thread(0x29,r)&&!memcmp(before,r,sizeof r),"other InfoType delegated unchanged");
  r[1]=0x100000018ull;memcpy(before,r,sizeof r);need(!svc_thread(0x29,r)&&!memcmp(before,r,sizeof r),"InfoType is exact64bit, highbit unknown delegated");
  need(free_count()==127&&objects_used()==1,"query guards do not mutate objects");puts("ok");return 0;
 }
 Worker w={0};uint32_t h=0;
 if(!strcmp(mode,"allocate-failure")||!strcmp(mode,"condition-failure")||!strcmp(mode,"pthread-failure")){
  if(!strcmp(mode,"allocate-failure"))atomic_store(&fail_allocate,1);
  if(!strcmp(mode,"condition-failure"))atomic_store(&fail_condition,1);
  if(!strcmp(mode,"pthread-failure"))atomic_store(&fail_create,1);
  need(create(&w,&h)==0xce01&&!h,"native allocation/pthread failure is OutOfResource");
  need(free_count()==127&&objects_used()==1&&handles_used()==1&&!atomic_load(&guest_entries),"failure fully rolls back quota/list/handle");
  need(!create(&w,&h),"normal Create after rollback");close_handle(h);wait_count(127);need(objects_used()==1,"post-rollback reuse");puts("ok");return 0;
 }
 if(!strcmp(mode,"handles-full")){
  uint32_t events[MAX_H];for(unsigned i=0;i<MAX_H-2;i++)events[i]=runtime_event_new();
  need(handles_used()==MAX_H-1&&free_count()==127,"shared handles full, thread quota still available");
  need(create(&w,&h)==0xd201&&!h,"OutOfHandles distinct from quota and allocation");
  need(free_count()==127&&objects_used()==1&&handles_used()==MAX_H-1,"full-handle failure rolls back reservation");
  for(unsigned i=0;i<MAX_H-2;i++)close_handle(events[i]);need(handles_used()==1,"event slots reclaimed");puts("ok");return 0;
 }
 if(!strcmp(mode,"quota")){
  uint32_t hs[127];for(unsigned i=0;i<127;i++)need(!create(&w,&hs[i]),"real Create up to enforced quota");
  need(!free_count()&&objects_used()==128&&handles_used()==128,"all128 retained objects consume quota");
  atomic_store(&fail_allocate,1);
  need(create(&w,&h)==0x10801&&!h&&atomic_load(&fail_allocate),"exact quota LimitReached before allocation");atomic_store(&fail_allocate,0);
  need(!free_count()&&objects_used()==128&&handles_used()==128,"quota failure publishes nothing");
  for(unsigned i=0;i<127;i++)close_handle(hs[i]);wait_count(127);
  need(objects_used()==1&&handles_used()==1&&!atomic_load(&guest_entries),"all unstarted workers actually reclaimed without entry");puts("ok");return 0;
 }
 if(!strcmp(mode,"concurrent-quota")){
  Creator creators[8]={0};pthread_t native[8];
  for(unsigned i=0;i<8;i++)need(!pthread_create(&native[i],NULL,native_creator,&creators[i]),"original native concurrent creator");
  while(atomic_load(&creators_ready)!=8)sched_yield();atomic_store(&creators_go,1);
  unsigned total=0;for(unsigned i=0;i<8;i++){need(!pthread_join(native[i],NULL),"creator join");total+=creators[i].count;}
  need(total==127&&!free_count()&&objects_used()==128&&handles_used()==128,"atomic reservations never oversubscribe quota");
  for(unsigned i=0;i<8;i++)for(unsigned j=0;j<creators[i].count;j++)close_handle(creators[i].handles[j]);
  wait_count(127);need(objects_used()==1&&handles_used()==1&&!atomic_load(&guest_entries),"concurrent-created workers actually finalize");puts("ok");return 0;
 }
 if(!strcmp(mode,"close-before-worker-wait")){
  atomic_store(&block_tls,1);need(!create(&w,&h),"Create before native init barrier");wait_flag(&tls_blocked);
  close_handle(h);need(free_count()==126&&objects_used()==2&&handles_used()==1,"close keeps object while real worker blocked");
  atomic_store(&release_tls,1);wait_count(127);need(objects_used()==1&&!atomic_load(&guest_entries),"host-only cleanup after early close");puts("ok");return 0;
 }
 if(!strcmp(mode,"unstarted-cycles")){
  for(unsigned i=0;i<1000;i++){
   need(!create(&w,&h)&&free_count()==126,"Create reserves before Start");close_handle(h);wait_count(127);
  }
  need(objects_used()==1&&handles_used()==1&&!atomic_load(&guest_entries),"1000 real unstarted pthread lifecycles reclaimed");puts("ok");return 0;
 }
 if(!strcmp(mode,"start-close-race")){
  for(unsigned i=0;i<100;i++){
   Worker race_worker={0};atomic_store(&race_worker.release,1);uint32_t rh;
   need(!create(&race_worker,&rh),"race Create");StartRace race={rh,~0ull};pthread_t native;
   need(!pthread_create(&native,NULL,native_start,&race),"original native racing caller");close_handle(rh);need(!pthread_join(native,NULL),"race join");
   wait_count(127);need(race.result==0||race.result==0xe401,"Start is serialized with close");
   need(atomic_load(&race_worker.entered)==(race.result==0),"entry iff actual Start won the lock");
  }
  need(objects_used()==1&&handles_used()==1,"race finalization bounded");puts("ok");return 0;
 }
 need(!create(&w,&h)&&free_count()==126&&objects_used()==2,"Create reserves one unstarted object");
 if(!strcmp(mode,"unstarted")){
  close_handle(h);wait_count(127);need(!atomic_load(&guest_entries),"unstarted close never enters authored entry");
 }else if(!strcmp(mode,"exited-open")){
  atomic_store(&w.release,1);need(!start(h),"actual Start");wait_exited(h);
  need(atomic_load(&w.entered)&&free_count()==126&&objects_used()==2,"Exit with handle open retains reservation");
  close_handle(h);need(free_count()==127,"last reference releases quota");
 }else if(!strcmp(mode,"closed-running")){
  need(!start(h),"actual Start");wait_flag(&w.entered);close_handle(h);
  need(free_count()==126&&objects_used()==2&&handles_used()==1,"live closed-handle object retains quota");
  atomic_store(&w.release,1);wait_count(127);
 }else if(!strcmp(mode,"main-closed")){
  close_handle(h);wait_count(127);close_handle(main);
  need(free_count()==127&&objects_used()==1&&handles_used()==0,"main live reference retains quota after handle close");puts("ok");return 0;
 }else runtime_fail("unknown fixture mode");
 need(objects_used()==1&&handles_used()==1,"one actual main object remains");puts("ok");return 0;
}
'''


class ThreadBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-thread-budget-")
        work = Path(cls.temporary.name)
        runtime = Path(__file__).resolve().parents[1] / "runtime"
        source = work / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = work / "fixture"
        result = subprocess.run([
            "/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
            "-I"+str(runtime), "-I"+str(runtime.parent / "third_party/d2r_gfx/gfx/nvn/include"),
            str(source), "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def invoke(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")

    def test_main_counts_once(self): self.invoke("main")
    def test_exact_info_id_handle_subtype_guards_and_delegation(self): self.invoke("query-guards")
    def test_created_not_started_counts_then_close_reclaims(self): self.invoke("unstarted")
    def test_exit_with_open_handle_keeps_reservation(self): self.invoke("exited-open")
    def test_closed_running_thread_keeps_reservation_until_exit(self): self.invoke("closed-running")
    def test_closed_main_handle_keeps_main_object(self): self.invoke("main-closed")
    def test_early_close_wakes_worker_for_host_only_cleanup(self): self.invoke("close-before-worker-wait")
    def test_full_quota_returns_limit_reached_and_reclaims_all_real_workers(self): self.invoke("quota")
    def test_concurrent_creators_cannot_oversubscribe_quota(self): self.invoke("concurrent-quota")
    def test_native_allocation_failure_rolls_back(self): self.invoke("allocate-failure")
    def test_native_condition_failure_rolls_back(self): self.invoke("condition-failure")
    def test_native_pthread_create_failure_rolls_back(self): self.invoke("pthread-failure")
    def test_shared_handle_exhaustion_returns_out_of_handles_and_rolls_back(self): self.invoke("handles-full")
    def test_thousand_unstarted_real_pthread_lifecycles_do_not_leak(self): self.invoke("unstarted-cycles")
    def test_actual_start_close_race_is_serialized_and_never_enters_after_losing(self): self.invoke("start-close-race")


if __name__ == "__main__":
    unittest.main()
