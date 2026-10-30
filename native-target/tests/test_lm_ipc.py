"""Real native IPC/LM handlers with offline CMIF packets; no SDK/guest calls."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import castlevania_policy as policy

class NativeLmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="castlevania-lm-tests-")
        directory = Path(cls.work.name)
        source = directory / "fixture.c"
        source.write_text(r'''
#include "ipc.c"
#define CASTLEVANIA_LM_LOG_LIMIT 4096u
#include "lm_host.c"
pthread_key_t runtime_keys[8];
_Noreturn void runtime_fail(const char *m) {fprintf(stderr,"FAIL: %s\n",m);exit(2);}
void runtime_trace_guest(uint64_t a,uint64_t b){(void)a;(void)b;}
int runtime_core_away(void){return 0;}
void runtime_core_back(int *a){(void)a;}
static void *handles[128];static unsigned nhandles;
uint32_t runtime_handle_new(int session,void *o){(void)session;lm_need(++nhandles<128,"fixture handles");handles[nhandles]=o;return nhandles;}
void *runtime_handle_get(uint32_t h,int session){(void)session;return h<128?handles[h]:NULL;}
void *runtime_handle_take_session(uint32_t h){void *o=runtime_handle_get(h,1);if(h<128)handles[h]=NULL;return o;}
static void request(uint32_t *m,unsigned cmd,unsigned pid,unsigned shape,const void *data,unsigned size,const void *buffer,unsigned bytes){
 memset(m,0,256);m[0]=6;uint32_t *p=m+2;
 if(pid){m[1]=1u<<31;*p++=1;*p++=0;*p++=0;}
 uint64_t a=(uintptr_t)buffer;
 if(shape==1||shape==3||shape==4||shape==5){unsigned length=shape==4?0:bytes;m[0]|=1u<<16;p[0]=(uint32_t)(((a>>36)&63)<<6)|((uint32_t)((a>>32)&15)<<12)|(length<<16);p[1]=(uint32_t)a;p+=2;}
 if(shape==2||shape==3||shape==4||shape==5){unsigned length=shape==5?0:bytes;m[0]|=1u<<20;p[0]=length;p[1]=(uint32_t)a;p[2]=(uint32_t)(((a>>32)&15)<<28)|((uint32_t)((a>>36)&0x3fffff)<<2);p+=3;}
 uint32_t *payload=(uint32_t *)(((uintptr_t)p+15)&~(uintptr_t)15);payload[0]=CMIF_IN_MAGIC;payload[2]=cmd;
 if(size)memcpy(payload+4,data,size);
 /* Nonzero unassigned alignment slack is legal and must not be parsed as args. */
 memset((uint8_t *)(payload+4)+size,0xa5,16);
 m[1]|=(uint32_t)(((uint8_t *)(payload+4)+size+16-(uint8_t *)p+3)/4);
}
static void packet(uint8_t *p,unsigned flags,const uint8_t *body,unsigned size){
 memset(p,0,24+size);uint64_t untrusted_pid=999,tid=7;memcpy(p,&untrusted_pid,8);memcpy(p+8,&tid,8);p[16]=(uint8_t)flags;p[18]=1;memcpy(p+20,&size,4);memcpy(p+24,body,size);
}
int main(int argc,char **argv){
 lm_need(argc==2,"fixture mode");const char *mode=argv[1];
 _Alignas(16) uint32_t m[64];uint64_t placeholder=0;
 IpcSession service={.name="lm",.handler=lm_service};
 request(m,0,strcmp(mode,"missing-pid")!=0,0,&placeholder,8,NULL,0);dispatch(&service,m);
 lm_need((m[1]>>31)&&((m[2]>>5)&15)==1,"OpenLogger must return MOVE handle");
 IpcSession *logger=runtime_handle_get(m[3],1);lm_need(logger&&logger->handler==lm_logger,"ILogger session returned");
 if(!strcmp(mode,"open"))return 0;
 if(!strcmp(mode,"unknown")){request(m,2,0,0,NULL,0,NULL,0);dispatch(logger,m);return 4;}
 if(!strcmp(mode,"destination")||!strcmp(mode,"bad-destination")){
  unsigned mask=!strcmp(mode,"destination")?2:8;request(m,1,0,0,&mask,4,NULL,0);dispatch(logger,m);return 0;}
 uint8_t p[1024],body[]={2,5,'h','e','l','l','o'};unsigned count=sizeof body;
 packet(p,7,body,count);
 if(!strncmp(mode,"global-",7)){
  unsigned mask=0;request(m,1,0,0,&mask,4,NULL,0);dispatch(logger,m);
  /* Opening B after disabling A must not reset the shared destination. */
  request(m,0,1,0,&placeholder,8,NULL,0);dispatch(&service,m);
  IpcSession *other=runtime_handle_get(m[3],1);lm_need(other!=NULL,"second logger");
  request(m,0,0,1,NULL,0,p,24+count);dispatch(other,m);
  if(!strcmp(mode,"global-enable")){
   mask=2;request(m,1,0,0,&mask,4,NULL,0);dispatch(other,m);
   request(m,0,0,1,NULL,0,p,24+count);dispatch(logger,m);
  }
  return 0;
 }
 if(!strcmp(mode,"bad-length")){unsigned wrong=count+1;memcpy(p+20,&wrong,4);}
 if(!strcmp(mode,"bad-tlv")){body[1]=40;packet(p,7,body,count);}
 if(!strcmp(mode,"control-chars")){body[2]=0x1b;body[3]='\n';packet(p,7,body,count);}
 if(!strcmp(mode,"header-padding"))p[17]=0xa5;
 if(!strcmp(mode,"unreadable")){request(m,0,0,1,NULL,0,(void *)1,31);dispatch(logger,m);return 4;}
 if(!strcmp(mode,"continuation")){
  uint8_t first[]={2,5,'h','e'},second[]={'l','l','o'};packet(p,5,first,sizeof first);
  request(m,0,0,1,NULL,0,p,24+sizeof first);dispatch(logger,m);
  packet(p,6,second,sizeof second);request(m,0,0,2,NULL,0,p,24+sizeof second);dispatch(logger,m);return 0;
 }
 unsigned shape=!strcmp(mode,"alias")?2:!strcmp(mode,"ambiguous")?3:!strcmp(mode,"auto-alias")?4:!strcmp(mode,"auto-pointer")?5:1;
 unsigned times=!strcmp(mode,"limit")?100:1;
 for(unsigned i=0;i<times;i++){request(m,0,0,shape,NULL,0,p,24+count);dispatch(logger,m);}
 return 0;
}
''')
        cls.binary = directory / "lm-fixture"
        command = ["/usr/bin/xcrun", "clang", "-arch", "arm64", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                   "-Wno-deprecated-declarations", "-DGAME_CASTLEVANIA=1", "-DCASTLEVANIA_DIAGNOSTIC_BOOT=1",
                   "-I"+str(policy.ROOT / "runtime"), "-I"+str(policy.ROOT / "third_party/d2r_gfx/gfx/nvn/include"), str(source), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode: raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls): cls.work.cleanup()

    def run_fixture(self, mode, expected=None):
        with tempfile.TemporaryDirectory() as directory:
            run = policy.create_run(Path(directory)); root = Path(run["root"])
            (root / ".castlevania-loader-run").rename(root / ".castlevania-host-run")
            log = root / "logs/native-host.log";log.touch(mode=0o600)
            env = policy.child_environment(run);env["CASTLEVANIA_LOG_FILE"] = str(log)
            with log.open("ab") as stream:
                result = subprocess.run([str(self.binary), mode], cwd=root, env=env, stdout=subprocess.PIPE, stderr=stream)
            text = log.read_text();sink=root / "logs/guest-lm.log";data=sink.read_bytes() if sink.exists() else b""
            if expected:
                self.assertNotEqual(result.returncode,0,text);self.assertIn(expected,text)
            else:self.assertEqual(result.returncode,0,text)
            self.assertLessEqual(len(data),4096)
            if sink.exists():self.assertEqual(sink.stat().st_mode & 0o777,0o600)
            return data

    def test_open_logger_returns_real_moved_session(self):self.assertIn(b"open pid=",self.run_fixture("open"))
    def test_pointer_packet_persists_payload(self):self.assertIn(b"payload_hex=020568656c6c6f",self.run_fixture("pointer"))
    def test_alias_packet_persists_payload(self):self.assertIn(b"payload_hex=020568656c6c6f",self.run_fixture("alias"))
    def test_autoselect_with_empty_pointer_descriptor(self):self.assertIn(b"payload_hex=020568656c6c6f",self.run_fixture("auto-alias"))
    def test_autoselect_with_empty_alias_descriptor(self):self.assertIn(b"payload_hex=020568656c6c6f",self.run_fixture("auto-pointer"))
    def test_unspecified_header_padding_is_not_rejected(self):self.assertIn(b"payload_hex=020568656c6c6f",self.run_fixture("header-padding"))
    def test_continuation_chunk_is_validated_across_packets(self):
        data=self.run_fixture("continuation");self.assertIn(b"payload_hex=02056865",data);self.assertIn(b"payload_hex=6c6c6f",data)
    def test_set_destination_changes_real_sink_configuration(self):self.assertIn(b"set_destination=2",self.run_fixture("destination"))
    def test_destination_disable_is_shared_with_a_new_logger(self):
        data=self.run_fixture("global-disable")
        packets=[line for line in data.splitlines() if b"payload_hex=" in line]
        self.assertEqual(len(packets),1);self.assertTrue(packets[0].startswith(b"logger=2 "))
        self.assertIn(b"destination=0",packets[0]);self.assertIn(b"payload_hex=disabled",packets[0])
    def test_other_logger_can_enable_the_shared_destination(self):
        data=self.run_fixture("global-enable")
        packets=[line for line in data.splitlines() if b"payload_hex=" in line]
        self.assertEqual(len(packets),2)
        self.assertIn(b"payload_hex=disabled",packets[0])
        self.assertTrue(packets[1].startswith(b"logger=1 "));self.assertIn(b"destination=2",packets[1])
        self.assertIn(b"payload_hex=020568656c6c6f",packets[1])
    def test_control_characters_never_enter_host_text(self):
        data=self.run_fixture("control-chars");self.assertNotIn(b"\x1b",data);self.assertIn(b"02051b0a",data)
    def test_missing_pid_rejected(self):self.run_fixture("missing-pid","ClientProcessId")
    def test_ambiguous_autoselect_rejected(self):self.run_fixture("ambiguous","ambiguous AutoSelect")
    def test_unreadable_packet_rejected(self):self.run_fixture("unreadable","not readable")
    def test_payload_length_rejected(self):self.run_fixture("bad-length","payload length mismatch")
    def test_incomplete_tlv_tail_rejected(self):self.run_fixture("bad-tlv","incomplete data chunk")
    def test_unsupported_destination_rejected(self):self.run_fixture("bad-destination","destination mask unsupported")
    def test_unknown_ILogger_command_rejected(self):self.run_fixture("unknown","command 2 not implemented")
    def test_budget_exhaustion_fails_without_overrun(self):self.run_fixture("limit","log budget exhausted")

if __name__ == "__main__": unittest.main()
