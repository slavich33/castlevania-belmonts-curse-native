"""Offline native APM/CMIF tests using the real services.c operation-mode policy."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import castlevania_policy as policy

class NativeApmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=tempfile.TemporaryDirectory(prefix="castlevania-apm-tests-");directory=Path(cls.work.name)
        source=directory/"fixture.c"
        source.write_text(r'''
#include "ipc.c"
#include "apm_host.c"
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(2);}
void runtime_trace_guest(uint64_t a,uint64_t b){(void)a;(void)b;}
int runtime_core_away(void){return 0;}
void runtime_core_back(int *a){(void)a;}
static void *handles[128];static unsigned nhandles;
uint32_t runtime_handle_new(int session,void *o){(void)session;apm_need(++nhandles<128,"fixture handles");handles[nhandles]=o;return nhandles;}
void *runtime_handle_get(uint32_t h,int session){(void)session;return h<128?handles[h]:NULL;}
void *runtime_handle_take_session(uint32_t h){void *o=runtime_handle_get(h,1);if(h<128)handles[h]=NULL;return o;}
static void request(uint32_t *m,unsigned cmd,unsigned type,const void *data,unsigned size,unsigned pid){
 memset(m,0,256);m[0]=type;uint32_t *p=m+2;
 if(pid){m[1]=1u<<31;*p++=1;*p++=0;*p++=0;}
 uint32_t *payload=(uint32_t *)(((uintptr_t)p+15)&~(uintptr_t)15);payload[0]=CMIF_IN_MAGIC;payload[2]=cmd;
 if(size)memcpy(payload+4,data,size);
 memset((uint8_t *)(payload+4)+size,0xa5,16);
 m[1]|=(uint32_t)(((uint8_t *)(payload+4)+size+16-(uint8_t *)p+3)/4);
}
static void output_ok(const uint32_t *m){apm_need(m[4]==CMIF_OUT_MAGIC&&m[6]==0,"CMIF success response");}
static IpcSession *open_session(IpcSession *manager,uint32_t *m){
 request(m,0,6,NULL,0,0);dispatch(manager,m);
 apm_need((m[1]>>31)&&((m[2]>>5)&15)==1,"APM moved interface handle");
 IpcSession *s=runtime_handle_get(m[3],1);apm_need(s&&s->handler==apm_session,"real APM ISession");return s;
}
static void set(IpcSession *s,uint32_t *m,uint32_t mode,uint32_t config){uint32_t args[2]={mode,config};request(m,0,6,args,8,0);dispatch(s,m);output_ok(m);}
static uint32_t get(IpcSession *s,uint32_t *m,uint32_t mode){request(m,1,6,&mode,4,0);dispatch(s,m);output_ok(m);return m[8];}
int main(int argc,char **argv){
 apm_need(argc==2,"fixture mode");const char *mode=argv[1];
 if(!strcmp(mode,"constructors-only")){apm_need(nservices==1&&!strcmp(services[0].name,"apm"),"pre-main registration only");return 0;}
 _Alignas(16) uint32_t m[64];IpcSession manager={.name="apm",.handler=apm_manager};
 if(!strcmp(mode,"mode")||!strcmp(mode,"bad-operation")){request(m,1,6,NULL,0,0);dispatch(&manager,m);output_ok(m);printf("mode=%u\n",m[8]);return 0;}
 if(!strcmp(mode,"manager-unknown")||!strcmp(mode,"manager-overclock")){
  request(m,!strcmp(mode,"manager-overclock")?6:2,6,NULL,0,0);dispatch(&manager,m);return 4;}
 if(!strcmp(mode,"manager-pid")){request(m,0,6,NULL,0,1);dispatch(&manager,m);return 4;}
 if(!strcmp(mode,"control-pointer")){request(m,3,5,NULL,0,0);dispatch(&manager,m);output_ok(m);apm_need((m[8]&0xffff)==0x8000,"generic pointer size");return 0;}
 IpcSession *s=open_session(&manager,m);
 if(!strcmp(mode,"open"))return 0;
 if(!strcmp(mode,"session-unknown")||!strcmp(mode,"session-overclock")){
  request(m,!strcmp(mode,"session-overclock")?2:8,6,NULL,0,0);dispatch(s,m);return 4;}
 if(!strcmp(mode,"unset")){(void)get(s,m,0);return 4;}
 if(!strcmp(mode,"invalid-mode")){set(s,m,2,0x10000);return 4;}
 if(!strcmp(mode,"invalid-negative-mode")){set(s,m,UINT32_MAX,0x10000);return 4;}
 if(!strcmp(mode,"invalid-config")){set(s,m,0,0xdeadbeef);return 4;}
 if(!strcmp(mode,"zero-config")){set(s,m,0,0);return 4;}
 if(!strcmp(mode,"wrong-transport")){uint32_t args[2]={0,0x10000};request(m,0,16,args,8,0);dispatch(s,m);return 4;}
 set(s,m,0,0x10000);set(s,m,1,0x92220007);
 if(!strcmp(mode,"profiles")){apm_need(get(s,m,0)==0x10000&&get(s,m,1)==0x92220007,"independent normal/boost profiles");return 0;}
 if(!strcmp(mode,"shared")){IpcSession *other=open_session(&manager,m);apm_need(get(other,m,0)==0x10000,"shared process profile");set(other,m,1,0x20003);apm_need(get(s,m,1)==0x20003,"shared profile update");return 0;}
 if(!strcmp(mode,"clone")){request(m,2,5,NULL,0,0);dispatch(s,m);IpcSession *clone=runtime_handle_get(m[3],1);runtime_ipc_session_closed(s);apm_need(get(clone,m,0)==0x10000,"clone remains live");return 0;}
 if(!strcmp(mode,"mode-after-set")){request(m,1,6,NULL,0,0);dispatch(&manager,m);output_ok(m);printf("mode=%u\n",m[8]);return 0;}
 return 5;
}
''')
        cls.binary=directory/"apm-fixture"
        command=["/usr/bin/xcrun","clang","-arch","arm64","-std=gnu11","-O2","-Wall","-Wextra","-Werror","-Wno-deprecated-declarations","-DGAME_CASTLEVANIA=1","-DCASTLEVANIA_DIAGNOSTIC_BOOT=1","-I"+str(policy.ROOT/"runtime"),"-I"+str(policy.ROOT/"third_party/d2r_gfx/gfx/nvn/include"),str(source),str(policy.ROOT/"runtime/services.c"),"-Wl,-dead_strip","-framework","CoreFoundation","-o",str(cls.binary)]
        result=subprocess.run(command,capture_output=True,text=True)
        if result.returncode:raise RuntimeError(result.stderr)
    @classmethod
    def tearDownClass(cls):cls.work.cleanup()
    def fixture(self,mode,operation="docked",failure=None):
        with tempfile.TemporaryDirectory() as directory:
            run=policy.create_run(Path(directory));root=Path(run["root"])
            (root/".castlevania-loader-run").rename(root/".castlevania-host-run")
            log=root/"logs/native-host.log";log.touch(mode=0o600);env=policy.child_environment(run)
            env["CASTLEVANIA_LOG_FILE"]=str(log);env["CASTLEVANIA_OPERATION_MODE"]=operation
            with log.open("ab") as stream:result=subprocess.run([str(self.binary),mode],cwd=root,env=env,stdout=subprocess.PIPE,stderr=stream,text=True)
            text=log.read_text()
            if failure:self.assertNotEqual(result.returncode,0,text);self.assertIn(failure,text)
            else:self.assertEqual(result.returncode,0,text)
            return result.stdout
    def test_pre_main_registration_needs_no_run_or_env(self):
        with tempfile.TemporaryDirectory() as d:
            result=subprocess.run([str(self.binary),"constructors-only"],cwd=d,env={"PATH":"/usr/bin:/bin"},capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(list(Path(d).iterdir()),[])
    def test_open_returns_real_moved_session(self):self.fixture("open")
    def test_docked_policy_reports_boost(self):self.assertEqual(self.fixture("mode"),"mode=1\n")
    def test_handheld_policy_reports_normal(self):self.assertEqual(self.fixture("mode","handheld"),"mode=0\n")
    def test_profiles_round_trip_independently(self):self.fixture("profiles")
    def test_sessions_share_this_process_profiles(self):self.fixture("shared")
    def test_clone_survives_original_session_close(self):self.fixture("clone")
    def test_setting_inactive_boost_profile_does_not_change_handheld_mode(self):self.assertEqual(self.fixture("mode-after-set","handheld"),"mode=0\n")
    def test_get_before_set_is_explicit_gate(self):self.fixture("unset",failure="before Set is unmeasured")
    def test_bad_operation_policy_rejected(self):self.fixture("bad-operation","invalid",failure="must be docked or handheld")
    def test_bad_mode_rejected(self):self.fixture("invalid-mode",failure="Normal0 or Boost1")
    def test_negative_mode_rejected(self):self.fixture("invalid-negative-mode",failure="Normal0 or Boost1")
    def test_unknown_config_rejected(self):self.fixture("invalid-config",failure="configuration token unsupported")
    def test_zero_config_rejected(self):self.fixture("zero-config",failure="configuration token unsupported")
    def test_manager_unknown_command_rejected(self):self.fixture("manager-unknown",failure="command 2 not implemented")
    def test_manager_overclock_not_faked(self):self.fixture("manager-overclock",failure="command 6 not implemented")
    def test_session_unknown_command_rejected(self):self.fixture("session-unknown",failure="command 8 not implemented")
    def test_session_overclock_not_faked(self):self.fixture("session-overclock",failure="command 2 not implemented")
    def test_extra_pid_rejected(self):self.fixture("manager-pid",failure="unexpected request")
    def test_unsupported_transport_rejected(self):self.fixture("wrong-transport",failure="unexpected request")
    def test_cmif_control_is_not_an_apm_command(self):self.fixture("control-pointer")
if __name__=="__main__":unittest.main()
