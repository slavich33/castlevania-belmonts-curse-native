"""Native regression for measured DSO deferral invariants, with original tiny fixtures.

The fixture models registration/deferred callbacks independently; it contains no
owned game/SDK code, flags, tables or binaries. The real header supplies every
host-side begin/end/completion decision. Actual integration belongs to loader.c.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConstructorProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="castlevania-ctor-protocol-")
        directory = Path(cls.temporary.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "castlevania_policy.h"
#if defined(FIXTURE_WRONG_PROFILE)
#undef CASTLEVANIA_GAME_VERSION
#define CASTLEVANIA_GAME_VERSION "1.2.0"
#endif
#include "castlevania_constructors.h"
#include <stdio.h>
#include <stdlib.h>

static void need(int condition,const char *message){if(!condition){fprintf(stderr,"FAIL: %s\n",message);exit(2);}}
typedef struct {const char *name;uint32_t registration_result;unsigned registrations,constructors;} Dso;
typedef struct {
    CvCtorProtocol protocol;
    Dso sdk,sub,main;
    Dso *pending[2];unsigned pending_count,owner_present,callbacks,ctor_count;
    const char *ctor_order[3];
    unsigned force_main_deferral;
} Fixture;
static Fixture fixture(void){Fixture f={0};f.sdk.name="sdk";f.sub.name="subsdk0";f.main.name="main";return f;}
static void original_tiny_dt_init(Fixture *,Dso *);
static uint32_t original_tiny_register(Fixture *f,Dso *d){
    d->registrations++;
    if(d==&f->main){
        if(f->force_main_deferral)return 1;
        f->owner_present=1;
        /* This fixture's ascending pending slots model independently measured
         * SDK slots2,3. Only the original owner callback path drains them. */
        for(unsigned i=0;i<f->pending_count;i++){
            Dso *pending=f->pending[i];need(pending->registration_result==1,"pending registration remains deferred1");
            need(!cv_ctor_finish(&f->protocol,f->main.registration_result,f->sub.registration_result,f->sdk.registration_result),"main barrier closed during deferred callback");
            original_tiny_dt_init(f,pending);f->callbacks++;
            need(pending->registration_result==1,"deferred callback leaves result1 unchanged");
        }
        return 2;
    }
    need(!f->owner_present&&f->pending_count<2,"fixture registration order/capacity");
    f->pending[f->pending_count++]=d;return 1;
}
static void original_tiny_dt_init(Fixture *f,Dso *d){
    if(!d->registration_result){
        d->registration_result=original_tiny_register(f,d);
        if(d->registration_result==1)return;
    }
    if(d==&f->main)need(!cv_ctor_finish(&f->protocol,2,1,1),"main return barrier stays closed even after owner result2 until DT_INIT returns");
    need(f->ctor_count<3,"fixture repeated constructor");f->ctor_order[f->ctor_count++]=d->name;d->constructors++;
}
static void pass(Fixture *f,Dso *d){
    need(cv_ctor_begin(&f->protocol,d->name,d->registration_result),"real header accepts measured fresh transition start");
    original_tiny_dt_init(f,d);
    need(cv_ctor_end(&f->protocol,d->name,d->registration_result),"real header accepts measured first-pass result");
}
static void defer_pair(Fixture *f){pass(f,&f->sdk);pass(f,&f->sub);need(!f->sdk.constructors&&!f->sub.constructors&&!f->callbacks,"first passes register only and do not run deferred constructors");}
int main(int argc,char **argv){
    need(argc==2,"fixture mode");const char *mode=argv[1];Fixture f=fixture();
    if(!strcmp(mode,"profile")){need(!cv_ctor_profile()&&!cv_ctor_begin(&f.protocol,"sdk",0),"wrong title version rejected");return 0;}
    if(!strcmp(mode,"deferred")){
        defer_pair(&f);need(!cv_ctor_finish(&f.protocol,0,1,1),"no completion before original main");pass(&f,&f.main);
        need(f.sdk.registration_result==1&&f.sub.registration_result==1&&f.main.registration_result==2,"authentic final results are main/sub/sdk2/1/1");
        need(f.sdk.registrations==1&&f.sub.registrations==1&&f.main.registrations==1,"callbacks do not repeat registration helper");
        need(f.callbacks==2&&f.sdk.constructors==1&&f.sub.constructors==1&&f.main.constructors==1,"deferred callbacks and main constructors execute once");
        need(!strcmp(f.ctor_order[0],"sdk")&&!strcmp(f.ctor_order[1],"subsdk0")&&!strcmp(f.ctor_order[2],"main"),"owner drains ascending registration slots before own constructor");
        need(cv_ctor_finish(&f.protocol,2,1,1),"main normal return completes whole pass");return 0;
    }
    if(!strcmp(mode,"main-deferred")){
        defer_pair(&f);f.force_main_deferral=1;need(cv_ctor_begin(&f.protocol,"main",0),"main begin");original_tiny_dt_init(&f,&f.main);
        need(!cv_ctor_end(&f.protocol,"main",f.main.registration_result)&&!cv_ctor_finish(&f.protocol,1,1,1),"unsafe main0to1 never completes");return 0;
    }
    if(!strcmp(mode,"all-two")){
        defer_pair(&f);pass(&f,&f.main);need(!cv_ctor_finish(&f.protocol,2,2,2),"naive universal state2 must be rejected");return 0;
    }
    if(!strcmp(mode,"order")){need(!cv_ctor_begin(&f.protocol,"main",0)&&!cv_ctor_begin(&f.protocol,"subsdk0",0),"non-SDK first rejected");pass(&f,&f.sdk);need(!cv_ctor_begin(&f.protocol,"main",0),"cannot skip subsdk0");return 0;}
    if(!strcmp(mode,"repeat")){pass(&f,&f.sdk);need(!cv_ctor_begin(&f.protocol,"sdk",1)&&!cv_ctor_begin(&f.protocol,"sdk",0),"no explicit SDK retry regardless of supplied flag");return 0;}
    if(!strcmp(mode,"missing")){pass(&f,&f.sdk);need(!cv_ctor_finish(&f.protocol,2,1,1),"final values cannot hide missing module calls");return 0;}
    if(!strcmp(mode,"unknown")){need(!cv_ctor_begin(&f.protocol,"other",0)&&!cv_ctor_begin(&f.protocol,NULL,0),"unknown/missing name rejected");return 0;}
    if(!strcmp(mode,"initial-flags")){for(uint32_t i=1;i<4;i++)need(!cv_ctor_begin(&f.protocol,"sdk",i),"every first pass requires fresh0");return 0;}
    if(!strcmp(mode,"bad-nonmain-result")){need(cv_ctor_begin(&f.protocol,"sdk",0),"SDK begin");for(uint32_t i=0;i<4;i++)if(i!=1)need(!cv_ctor_end(&f.protocol,"sdk",i),"only measured first-pass nonmain1 accepted");return 0;}
    if(!strcmp(mode,"bad-main-result")){defer_pair(&f);need(cv_ctor_begin(&f.protocol,"main",0),"main begin");for(uint32_t i=0;i<4;i++)if(i!=2)need(!cv_ctor_end(&f.protocol,"main",i),"only measured first-pass main2 accepted");return 0;}
    if(!strcmp(mode,"overlap")){need(cv_ctor_begin(&f.protocol,"sdk",0),"begin once");need(!cv_ctor_begin(&f.protocol,"sdk",0)&&!cv_ctor_begin(&f.protocol,"subsdk0",0),"nested init rejected");return 0;}
    if(!strcmp(mode,"unpaired-end")){need(!cv_ctor_end(&f.protocol,"sdk",1),"cannot finish before begin");need(cv_ctor_begin(&f.protocol,"sdk",0),"SDK begin");need(!cv_ctor_end(&f.protocol,"subsdk0",1),"end must match in-flight module");return 0;}
    if(!strcmp(mode,"final-flags")){defer_pair(&f);pass(&f,&f.main);for(uint32_t i=0;i<4;i++){if(i!=2)need(!cv_ctor_finish(&f.protocol,i,1,1),"wrong main final flag rejected");if(i!=1)need(!cv_ctor_finish(&f.protocol,2,i,1)&&!cv_ctor_finish(&f.protocol,2,1,i),"wrong deferred final flag rejected");}return 0;}
    if(!strcmp(mode,"extra-pass")){defer_pair(&f);pass(&f,&f.main);need(!cv_ctor_begin(&f.protocol,"main",2)&&!cv_ctor_end(&f.protocol,"main",2),"completed protocol rejects extra passes");return 0;}
    if(!strcmp(mode,"invalid-state")){CvCtorProtocol bad={4,0};need(!cv_ctor_begin(&bad,"sdk",0)&&!cv_ctor_end(&bad,"sdk",1)&&!cv_ctor_finish(&bad,2,1,1),"invalid phase rejected");bad=(CvCtorProtocol){0,2};need(!cv_ctor_begin(&bad,"sdk",0)&&!cv_ctor_end(&bad,"sdk",1),"invalid in-flight state rejected");need(!cv_ctor_begin(NULL,"sdk",0)&&!cv_ctor_end(NULL,"sdk",1)&&!cv_ctor_finish(NULL,2,1,1),"null protocol rejected");return 0;}
    return 5;
}
''')
        cls.binaries = {}
        for name, defines in (("default", []), ("diagnostic", ["-DCASTLEVANIA_DIAGNOSTIC_BOOT=1"]),
                              ("wrong-profile", ["-DFIXTURE_WRONG_PROFILE=1"])):
            binary = directory / name
            command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=c11", "-O1",
                       "-Wall", "-Wextra", "-Werror", "-DGAME_CASTLEVANIA=1", *defines,
                       "-I"+str(ROOT / "runtime"), str(source), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            cls.binaries[name] = binary

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fixture(self, mode, binary="default"):
        result = subprocess.run([str(self.binaries[binary]), mode], capture_output=True, text=True,
                                env={"PATH": "/usr/bin:/bin"}, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_original_tiny_dso_model_defers_then_executes_callbacks_once_without_changing_result1(self):self.fixture("deferred")
    def test_main_completion_barrier_also_holds_in_diagnostic_build(self):self.fixture("deferred", "diagnostic")
    def test_unsafe_main_deferral_cannot_complete(self):self.fixture("main-deferred")
    def test_naive_all_modules_state2_is_rejected(self):self.fixture("all-two")
    def test_reordered_or_skipped_modules_are_rejected(self):self.fixture("order")
    def test_explicit_deferred_module_retry_is_rejected(self):self.fixture("repeat")
    def test_missing_module_cannot_hide_behind_final_flag_values(self):self.fixture("missing")
    def test_unknown_module_is_rejected(self):self.fixture("unknown")
    def test_all_first_calls_require_fresh_zero(self):self.fixture("initial-flags")
    def test_unmeasured_nonmain_results_are_rejected(self):self.fixture("bad-nonmain-result")
    def test_unmeasured_main_results_are_rejected(self):self.fixture("bad-main-result")
    def test_overlapping_init_calls_are_rejected(self):self.fixture("overlap")
    def test_end_requires_matching_inflight_begin(self):self.fixture("unpaired-end")
    def test_every_wrong_final_flag_is_rejected(self):self.fixture("final-flags")
    def test_completed_protocol_rejects_extra_calls(self):self.fixture("extra-pass")
    def test_invalid_or_null_protocol_is_rejected(self):self.fixture("invalid-state")
    def test_different_game_version_profile_is_rejected(self):self.fixture("profile", "wrong-profile")


if __name__ == "__main__":
    unittest.main()
