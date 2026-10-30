"""Native queue/event bridge tests; actual threads.c handles/SVCs, no guest code."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class AppletQueueEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="castlevania-applet-events-")
        directory = Path(cls.work.name)
        runtime = Path(__file__).resolve().parents[1] / "runtime"
        source = directory / "fixture.c"
        source.write_text(r'''
#include "threads.c"
#include "applet_host.c"
#include <stdatomic.h>
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
int runtime_front_focus(void){return 1;} /* current frontend logical policy, no Cocoa claim */
void *runtime_symbol(const char *s){(void)s;runtime_fail("guest symbol must not run");}
void runtime_thread_init(void){runtime_fail("guest TLS must not run");}
void dm_thread_enter(uint64_t e,uint64_t a,uint64_t s,uint64_t *c){(void)e;(void)a;(void)s;(void)c;runtime_fail("guest entry must not run");}
_Noreturn void runtime_thread_leave(const uint64_t *c,void *a,void(*f)(void *)){(void)c;(void)a;(void)f;runtime_fail("guest leave must not run");}
int runtime_module_offset(uint64_t p,const char **n,uint64_t *o){(void)p;(void)n;(void)o;return 0;}
static void need(int ok,const char *why){if(!ok)runtime_fail(why);}
static thr_t main_thread;
static void register_host_thread(thr_t *t){
 memset(t,0,sizeof *t);pthread_cond_init(&t->cv,NULL);t->cur_core=-1;pthread_setspecific(g_keythr,t);
}
static int signaled(uint32_t readable){
 pthread_mutex_lock(&G);int bad=0,yes=sig_obj(readable,&bad);pthread_mutex_unlock(&G);need(!bad,"valid readable event");return yes;
}
static void close_handle(uint32_t h){uint64_t r[32]={h};need(svc_thread(0x16,r)&&!r[0],"close handle");}
static uint64_t wait_event(uint32_t h,int64_t ns){uint64_t r[32]={0,(uintptr_t)&h,1,(uint64_t)ns};need(svc_thread(0x18,r),"wait handled");if(!r[0])need(r[1]==0,"event wait index");return r[0];}
static unsigned handles_used(void){unsigned n=0;pthread_mutex_lock(&G);for(int i=1;i<MAX_H;i++)n+=g_h[i].type!=0;pthread_mutex_unlock(&G);return n;}
static uint32_t drain_initial(void){
 uint32_t r=runtime_oe_message_event(),m=0;need(signaled(r),"initial policy notification signals event");
 need(runtime_oe_try_pop_message(&m)&&m==15,"one initial focus notification");need(!signaled(r),"initial drain clears event");return r;
}
static _Atomic int entered,finished;
static uint32_t worker_handle,worker_message;
static void *blocking_pop_thread(void *arg){
 (void)arg;atomic_store(&entered,1);worker_message=pop();atomic_store(&finished,1);return NULL;
}
static void *native_wait_thread(void *arg){
 (void)arg;thr_t t;register_host_thread(&t);atomic_store(&entered,1);
 need(wait_event(worker_handle,1000000000)==0,"real native event waiter wakes");
 need(runtime_oe_try_pop_message(&worker_message),"waiter consumes queue message");
 pthread_setspecific(g_keythr,NULL);pthread_cond_destroy(&t.cv);atomic_store(&finished,1);return NULL;
}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 need(message_event==0&&head==tail,"constructors leave queue/event untouched");
 need(pthread_key_create(&g_keythr,NULL)==0,"thread key");g_cores_on=0;register_host_thread(&main_thread);
 if(!strcmp(mode,"prequeue")){
  runtime_oe_push_message(44);uint32_t r=runtime_oe_message_event(),m;
  need(runtime_oe_try_pop_message(&m)&&m==44,"preexisting message preserved");need(signaled(r),"initial focus still queued");
  need(runtime_oe_try_pop_message(&m)&&m==15,"initial notification follows existing messages");need(!signaled(r),"drained event clear");return 0;
 }
 uint32_t r=drain_initial(),m=0;
 if(!strcmp(mode,"initial")){
  uint32_t other=runtime_oe_message_event();need(other!=r,"each query gets own handle");
  need(!runtime_oe_try_pop_message(&m),"no duplicate initial status");
  need(handles_used()==3,"one writable and two readable handles");close_handle(r);close_handle(other);need(handles_used()==1,"only retained writable remains");return 0;
 }
 if(!strcmp(mode,"level")){
  runtime_oe_push_message(1);runtime_oe_push_message(2);need(signaled(r),"queued messages signal");
  need(wait_event(r,0)==0&&wait_event(r,0)==0,"manual event wait does not drain signal");
  need(runtime_oe_try_pop_message(&m)&&m==1&&signaled(r),"partial drain remains signaled");
  need(runtime_oe_try_pop_message(&m)&&m==2&&!signaled(r),"last pop clears signal");
  need(wait_event(r,0)==R_TIMEOUT,"empty queue wait times out");return 0;
 }
 if(!strcmp(mode,"shared")){
  unsigned char(*high_pop)(uint32_t*)=runtime_applet_override("_ZN2nn2oe25TryPopNotificationMessageEPj");
  runtime_oe_push_message(51);runtime_oe_push_message(52);need(high_pop(&m)&&m==51&&signaled(r),"high-level consumes same queue");
  need(runtime_oe_try_pop_message(&m)&&m==52&&!signaled(r),"IPC drain clears same event");
  need(!high_pop(&m),"message cannot be consumed twice");return 0;
 }
 if(!strcmp(mode,"copies")){
  uint32_t other=runtime_oe_message_event();close_handle(r);runtime_oe_push_message(7);need(signaled(other),"copy survives other close");
  need(runtime_oe_try_pop_message(&m)&&m==7&&!signaled(other),"copies share signal state");close_handle(other);
  for(unsigned i=0;i<10000;i++){uint32_t h=runtime_oe_message_event();close_handle(h);}
  pthread_mutex_lock(&G);event_t *e=h_peek(message_event,O_EVENT_W);need(e&&e->refs==1,"copy refs bounded after close");pthread_mutex_unlock(&G);
  need(handles_used()==1,"copy slots reclaimed");return 0;
 }
 if(!strcmp(mode,"rights")){
  uint64_t regs[32]={r};need(svc_thread(0x11,regs)&&regs[0]==R_BAD_HANDLE,"read copy cannot signal");
  need(wait_event(message_event,0)==R_BAD_HANDLE,"write handle cannot wait");
  runtime_event_signal(message_event);need(signaled(r),"owner signal");runtime_event_clear(message_event);need(!signaled(r),"owner clear");return 0;
 }
 if(!strcmp(mode,"bad-clear")){runtime_event_clear(r);return 3;}
 if(!strcmp(mode,"null-output")){runtime_oe_try_pop_message(NULL);return 3;}
 if(!strcmp(mode,"overflow")){for(unsigned i=0;i<33;i++)runtime_oe_push_message(i);return 3;}
 if(!strcmp(mode,"capacity")){
  for(unsigned i=0;i<32;i++)runtime_oe_push_message(100+i);
  for(unsigned i=0;i<32;i++)need(runtime_oe_try_pop_message(&m)&&m==100+i,"full queue preserves FIFO");
  need(!signaled(r)&&!runtime_oe_try_pop_message(&m),"full queue fully drained");return 0;
 }
 if(!strcmp(mode,"blocking")||!strcmp(mode,"native-wait")){
  pthread_t worker;worker_handle=r;
  need(!pthread_create(&worker,NULL,!strcmp(mode,"blocking")?blocking_pop_thread:native_wait_thread,NULL),"native worker");
  while(!atomic_load(&entered))sched_yield();usleep(10000);need(!atomic_load(&finished),"worker waits until queue/event signal");
  runtime_oe_push_message(77);need(!pthread_join(worker,NULL),"worker joined");
  need(atomic_load(&finished)&&worker_message==77&&!signaled(r),"native waiter/pop drains and clears");return 0;
 }
 if(!strcmp(mode,"race")){
  /* Repeated native wait versus push/pop handoffs, without any guest entry. */
  for(unsigned i=0;i<200;i++){
   atomic_store(&entered,0);atomic_store(&finished,0);pthread_t worker;worker_handle=r;
   need(!pthread_create(&worker,NULL,native_wait_thread,NULL),"native worker");
   while(!atomic_load(&entered))sched_yield();runtime_oe_push_message(i+1000);
   need(!pthread_join(worker,NULL)&&worker_message==i+1000&&!signaled(r),"no lost wake/message across handoff");
  }return 0;
 }
 return 5;
}
''')
        cls.binary = directory / "applet-events"
        result = subprocess.run([
            "/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O2",
            "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
            "-DGAME_CASTLEVANIA=1", "-I"+str(runtime),
            "-I"+str(runtime.parent / "third_party/d2r_gfx/gfx/nvn/include"), str(source),
            "-Wl,-dead_strip", "-o", str(cls.binary),
        ], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def fixture(self, mode, failure=None):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin"}, timeout=10)
        if failure:
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn(failure, result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_event_publishes_exactly_one_logical_focus_status(self): self.fixture("initial")
    def test_event_created_after_messages_preserves_fifo(self): self.fixture("prequeue")
    def test_level_signal_clears_only_when_queue_drains(self): self.fixture("level")
    def test_high_level_and_ipc_consumers_share_one_queue(self): self.fixture("shared")
    def test_read_copies_share_state_and_close_reclaims_refs_and_slots(self): self.fixture("copies")
    def test_event_read_write_rights_preserved(self): self.fixture("rights")
    def test_clear_requires_owned_writable_end(self): self.fixture("bad-clear", "thread runtime failure")
    def test_null_output_fails_without_discarding_message(self): self.fixture("null-output", "output is NULL")
    def test_full_queue_preserves_all_32_messages(self): self.fixture("capacity")
    def test_overflow_fails_instead_of_losing_a_message(self): self.fixture("overflow", "queue full")
    def test_blocking_high_level_pop_clears_the_shared_event(self): self.fixture("blocking")
    def test_real_native_wait_synchronization_wakes(self): self.fixture("native-wait")
    def test_native_wait_signal_handoff_has_no_lost_message(self): self.fixture("race")


if __name__ == "__main__":
    unittest.main()
