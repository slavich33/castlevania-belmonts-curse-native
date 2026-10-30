"""Original native touch resolver/state/bounds tests; no SDK, game, GPU or device input."""
from pathlib import Path
import subprocess
import tempfile
import unittest


FIXTURE = r'''
#include "input.c"
#include <limits.h>
#include <unistd.h>
static unsigned char *failure_buffer;static size_t failure_bytes;
_Noreturn void runtime_fail(const char *message){
 if(failure_buffer){for(size_t i=0;i<failure_bytes;i++)if(failure_buffer[i]!=0xa5){fprintf(stderr,"FAIL: rejected call mutated buffer\n");exit(3);}
  if(touchSample){fprintf(stderr,"FAIL: rejected call mutated sample counter\n");exit(3);}}
 fprintf(stderr,"FAIL: %s\n",message);exit(2);
}
uint64_t runtime_now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
void runtime_survey_cancel_user(void){}
void runtime_autoload_user_input(void){}
int runtime_survey_command(const char *s){(void)s;runtime_fail("survey must not run");}
int runtime_controls_handle_key(unsigned c,unsigned m){(void)c;(void)m;return 0;}
int runtime_controls_active(void){return 0;}
void runtime_front_control_test(const char *s){(void)s;runtime_fail("frontend must not run");}
int runtime_handheld_mode(void){return 0;}
void runtime_gamepad_read(RuntimeGamepadState *p){memset(p,0,sizeof *p);}
uint64_t runtime_gamepad_held(void){return 0;}
void runtime_gamepad_clear(void){}
void *runtime_hid_feedback_override(const char *s){(void)s;return NULL;}
int runtime_hid_feedback_flag(const char *s,int v){(void)s;(void)v;runtime_fail("feedback must not run");}
void runtime_shortcut_help_toggle(void){runtime_fail("shortcut must not run");}
int runtime_output_mode_cycle(void){runtime_fail("output mode must not run");}
int runtime_aspect_toggle(void){runtime_fail("aspect must not run");}
void hle_bind_system_event(void *p,int n){(void)p;(void)n;runtime_fail("event must not run");}
void runtime_front_text_test(const char *a,const char *b){(void)a;(void)b;runtime_fail("text must not run");}
void runtime_front_request_close(void){runtime_fail("frontend close must not run");}
void runtime_dump_threads(void){runtime_fail("dump must not run");}
void runtime_hle_trace_set(int n){(void)n;runtime_fail("trace must not run");}
void runtime_frame_step_pin(double n){(void)n;runtime_fail("frame step must not run");}
void runtime_swkbd_selftest(void){runtime_fail("swkbd must not run");}
void dm_gfx_shot_at(long n,const char *s){(void)n;(void)s;runtime_fail("GPU must not run");}
void dm_gfx_window_shot(const char *s){(void)s;runtime_fail("GPU must not run");}
void dm_gfx_texdump_next(const char *s){(void)s;runtime_fail("GPU must not run");}
void dm_gfx_passdump_next(long n){(void)n;runtime_fail("GPU must not run");}
void dm_gfx_querylog_next(long n){(void)n;runtime_fail("GPU must not run");}
void dm_gfx_set_flag(const char *s,int n){(void)s;(void)n;runtime_fail("GPU must not run");}
void dm_gfx_anomdump(void){runtime_fail("GPU must not run");}
static void need(int ok,const char *s){if(!ok)runtime_fail(s);}
typedef int(*ReadTouch)(TouchScreenState16*,int);
typedef void(*InitTouch)(void);
static ReadTouch read_touch;static InitTouch init_touch;
typedef struct {_Alignas(8) uint8_t before[16];TouchScreenState16 states[16];uint8_t after[16];} Guarded;
static void reset(Guarded *g){memset(g,0xa5,sizeof *g);}
static void all_bytes(const void *p,size_t n,uint8_t expected,const char *why){const uint8_t *b=p;for(size_t i=0;i<n;i++)need(b[i]==expected,why);}
static void sample_ok(Guarded *g,uint64_t expected){
 need(g->states[0].sampling==expected&&expected>0,"monotonic sample number");
 all_bytes((uint8_t*)&g->states[0]+8,sizeof g->states[0]-8,0,"zero contact count/reserved/all16 touches");
 all_bytes(g->before,sizeof g->before,0xa5,"leading canary");all_bytes(g->after,sizeof g->after,0xa5,"trailing canary");
 all_bytes(g->states+1,sizeof g->states-sizeof g->states[0],0xa5,"untouched unused sample slots");
}
#define PER_THREAD 1000u
typedef struct {uint64_t samples[PER_THREAD];} Samples;
static void *native_reader(void *p){Samples *out=p;Guarded g;for(unsigned i=0;i<PER_THREAD;i++){reset(&g);need(read_touch(g.states,16)==1,"concurrent real resolver read");sample_ok(&g,g.states[0].sampling);out->samples[i]=g.states[0].sampling;}return NULL;}
static int order(const void *a,const void *b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}
static void *native_initializer(void *p){(void)p;for(unsigned i=0;i<1000;i++)init_touch();return NULL;}
int main(int argc,char **argv){
 need(argc==2,"fixture mode");const char *mode=argv[1];
 read_touch=(ReadTouch)runtime_input_override("_ZN2nn3hid20GetTouchScreenStatesILm16EEEiPNS0_16TouchScreenStateIXT_EEEi");
 init_touch=(InitTouch)runtime_input_override("_ZN2nn3hid21InitializeTouchScreenEv");
 need(read_touch&&init_touch,"exact imported entrypoints resolve");
 need(!runtime_input_override("_ZN2nn3hid20GetTouchScreenStatesILm15EEEiPNS0_16TouchScreenStateIXT_EEEi"),"unmeasured template not aliased");
 need(!runtime_input_override("_ZN2nn3hid20GetTouchScreenStatesILm16EEEiPNS0_16TouchScreenStateIXT_EEEi_extra"),"no prefix alias");
 need(sizeof(TouchScreenState16)==656&&offsetof(TouchScreenState16,count)==8&&offsetof(TouchScreenState16,touch)==16,"actual ABI");
 need(!touchReady&&!touchSample,"constructors do not initialize touch state");
 Guarded g;reset(&g);
 if(!strcmp(mode,"before-init")||!strcmp(mode,"zero-before-init")){
  failure_buffer=(void*)&g;failure_bytes=sizeof g;read_touch(g.states,!strcmp(mode,"before-init")?1:0);return 4;
 }
 if(!strcmp(mode,"legacy-singular")){
  void(*old)(TouchScreenState1*)=(void*)runtime_input_override("_ZN2nn3hid19GetTouchScreenStateILm1EEEvPNS0_16TouchScreenStateIXT_EEE");
  struct{uint64_t before;TouchScreenState1 state;uint64_t after;} one;memset(&one,0xa5,sizeof one);
  need(old!=NULL,"legacy singular remains resolved");old(&one.state);
  need(one.state.sampling==1&&one.before==0xa5a5a5a5a5a5a5a5ull&&one.after==one.before,"legacy56B write/canaries unchanged");
  all_bytes((uint8_t*)&one.state+8,sizeof one.state-8,0,"legacy no-contact contents unchanged");need(!touchReady&&!touchSample,"legacy call does not falsely initialize plural backend");return 0;
 }
 init_touch();need(touchReady&&!touchSample,"actual InitializeTouchScreen records ready only");
 if(!strncmp(mode,"null",4)||!strcmp(mode,"negative")||!strcmp(mode,"too-many")||!strcmp(mode,"int-max")||!strcmp(mode,"int-min")){
  int max=!strcmp(mode,"negative")?-1:!strcmp(mode,"too-many")?17:!strcmp(mode,"int-max")?INT_MAX:!strcmp(mode,"int-min")?INT_MIN:!strcmp(mode,"null-zero")?0:!strcmp(mode,"null-negative")?-1:1;
  failure_buffer=(void*)&g;failure_bytes=sizeof g;read_touch(!strncmp(mode,"null",4)?NULL:g.states,max);return 4;
 }
 if(!strcmp(mode,"zero")){
  need(read_touch(g.states,0)==0&&!touchSample,"zero returns no sample and does not advance counter");all_bytes(&g,sizeof g,0xa5,"zero does not write any byte");return 0;
 }
 if(!strcmp(mode,"one")||!strcmp(mode,"sixteen")||!strcmp(mode,"repeat")){
  need(read_touch(g.states,!strcmp(mode,"one")?1:16)==1,"one current sample returned");sample_ok(&g,1);
  if(!strcmp(mode,"repeat")){init_touch();reset(&g);need(read_touch(g.states,16)==1,"second sample");sample_ok(&g,2);}
  return 0;
 }
 if(!strcmp(mode,"parallel-init")){
  pthread_t ts[4];for(unsigned i=0;i<4;i++)need(!pthread_create(&ts[i],NULL,native_initializer,NULL),"native initializer");
  for(unsigned i=0;i<4;i++)need(!pthread_join(ts[i],NULL),"initializer join");
  need(!touchSample&&read_touch(g.states,1)==1,"idempotent concurrent initialization preserves counter");sample_ok(&g,1);return 0;
 }
 if(!strcmp(mode,"parallel")){
  Samples samples[4];pthread_t ts[4];for(unsigned i=0;i<4;i++)need(!pthread_create(&ts[i],NULL,native_reader,&samples[i]),"native reader");
  for(unsigned i=0;i<4;i++)need(!pthread_join(ts[i],NULL),"reader join");
  uint64_t values[4*PER_THREAD];memcpy(values,samples,sizeof values);qsort(values,4*PER_THREAD,sizeof values[0],order);
  for(unsigned i=0;i<4*PER_THREAD;i++)need(values[i]==i+1,"all serialized samples unique and contiguous");return 0;
 }
 if(!strcmp(mode,"controller-regression")){
  void(*npad_init)(void)=(void*)runtime_input_override("_ZN2nn3hid14InitializeNpadEv");
  int(*npad_read)(NpadState*,int,const uint32_t*)=(void*)runtime_input_override("_ZN2nn3hid13GetNpadStatesEPNS0_16NpadFullKeyStateEiRKj");
  void(*keyboard_init)(void)=(void*)runtime_input_override("_ZN2nn3hid18InitializeKeyboardEv");
  void(*keyboard_read)(KeyboardState*)=(void*)runtime_input_override("_ZN2nn3hid16GetKeyboardStateEPNS0_13KeyboardStateE");
  need(npad_init&&npad_read&&keyboard_init&&keyboard_read,"existing controller/keyboard entries remain resolved");
  npad_init();runtime_input_key_synthetic(38,1);uint32_t id=0;NpadState a,b;
  need(npad_read(&a,1,&id)==1&&a.buttons==1&&a.attributes==1,"real keyboard to Npad mapping");
  need(read_touch(g.states,16)==1,"touch read between pad reads");need(npad_read(&b,1,&id)==1&&b.sampling==a.sampling+1,"touch does not consume existing pad sampling counter");
  a.sampling=b.sampling;need(!memcmp(&a,&b,sizeof a),"pad buttons/sticks/attributes unchanged");
  keyboard_init();KeyboardState ka,kb;keyboard_read(&ka);need(read_touch(g.states,1)==1,"second touch read");keyboard_read(&kb);
  need(kb.sampling==ka.sampling+1,"touch does not consume keyboard sampling counter");ka.sampling=kb.sampling;need(!memcmp(&ka,&kb,sizeof ka),"keyboard contents unchanged");
  runtime_input_key_synthetic(38,0);need(npad_read(&b,1,&id)==1&&!b.buttons,"keyboard release still maps correctly");return 0;
 }
 runtime_fail("unknown fixture mode");
}
'''


class TouchScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-touch-tests-")
        work = Path(cls.temporary.name)
        runtime = Path(__file__).resolve().parents[1] / "runtime"
        source = work / "fixture.c"
        source.write_text(FIXTURE)
        common = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                  "-I"+str(runtime), "-I"+str(runtime.parent / "third_party/d2r_gfx/gfx/nvn/include"), str(source)]
        cls.binary, cls.normal = work / "touch-native", work / "touch-normal"
        for flags, binary in [(["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"], cls.binary), ([], cls.normal)]:
            result = subprocess.run(common+flags+["-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def invoke(self, mode, failure=None, normal=False):
        with tempfile.TemporaryDirectory(prefix="castlevania-touch-run-") as directory:
            root = Path(directory)
            result = subprocess.run([str(self.normal if normal else self.binary), mode], cwd=root,
                                    env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=10)
            self.assertEqual(list(root.iterdir()), [], "native input handler creates no files")
            self.assertEqual(result.returncode, 2 if failure else 0, result.stderr)
            self.assertEqual(result.stdout, "")
            if failure:
                self.assertIn(failure, result.stderr)
                self.assertNotIn("mutated", result.stderr)
            return result.stderr

    def test_initialized_capacity1_returns_one_zero_touch_sample_exact_bounds(self): self.invoke("one")
    def test_initialized_capacity16_writes_only_one_656byte_state(self): self.invoke("sixteen")
    def test_capacity0_leaves_buffer_and_sampling_untouched(self): self.invoke("zero")
    def test_read_before_initialization_fails_without_mutation(self): self.invoke("before-init", "before InitializeTouchScreen")
    def test_zero_capacity_still_requires_explicit_initialization(self): self.invoke("zero-before-init", "before InitializeTouchScreen")
    def test_null_output_fails(self): self.invoke("null", "output pointer")
    def test_null_zero_capacity_fails(self): self.invoke("null-zero", "output pointer")
    def test_null_guard_precedes_negative_capacity(self): self.invoke("null-negative", "output pointer")
    def test_negative_capacity_fails_without_mutation(self): self.invoke("negative", "capacity must be0..16")
    def test_capacity17_fails_without_clamping(self): self.invoke("too-many", "capacity must be0..16")
    def test_int_max_capacity_fails(self): self.invoke("int-max", "capacity must be0..16")
    def test_int_min_capacity_fails(self): self.invoke("int-min", "capacity must be0..16")
    def test_repeated_initialization_preserves_monotonic_samples(self): self.invoke("repeat")
    def test_four_native_readers_produce4000_unique_bounded_samples(self): self.invoke("parallel")
    def test_concurrent_initialization_is_idempotent(self): self.invoke("parallel-init")
    def test_singular1_behavior_and56byte_bounds_are_preserved(self): self.invoke("legacy-singular")
    def test_real_keyboard_npad_mapping_and_existing_sampling_remain_unchanged(self): self.invoke("controller-regression")
    def test_diagnostic_first_call_logs_are_bounded(self):
        text = self.invoke("parallel")
        self.assertEqual(text.count("InitializeTouchScreen:"), 1)
        self.assertEqual(text.count("GetTouchScreenStates<16>:"), 1)
        self.assertIn("samples=1 touches=0 state_bytes=656", text)
    def test_normal_compile_has_no_new_diagnostic_logs(self): self.assertEqual(self.invoke("repeat", normal=True), "")


if __name__ == "__main__":
    unittest.main()
