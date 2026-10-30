/* Logical native-host APM state. No SDK initializer override, clock control,
 * CPU boost or overclock implementation. See provenance/APM_HOST_20261027.json. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

/* Application sessions share this process's requested configuration per mode.
 * No unmeasured default token is invented: Get before Set stops explicitly. */
typedef struct { uint32_t configuration[2]; unsigned configured[2]; } ApmState;
static ApmState apm_state;
static pthread_mutex_t apm_lock=PTHREAD_MUTEX_INITIALIZER;
int runtime_handheld_mode(void);

static void apm_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static uint32_t apm_u32(const uint8_t *p) {uint32_t v;memcpy(&v,p,4);return v;}
static void apm_shape(const IpcRequest *rq,unsigned bytes) {
    castlevania_check_host_scratch();
    apm_need((rq->type==4||rq->type==6)&&!rq->has_pid&&!rq->ncopy&&!rq->nmove&&
             !rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,"APM unexpected request transport/handles/buffers");
    /* CMIF transport's alignment slack is unspecified, not extra arguments. */
    apm_need(rq->data_size>=bytes&&rq->data_size<=bytes+20,"APM command argument size");
}
static uint32_t apm_mode(const IpcRequest *rq) {
    uint32_t mode=apm_u32(rq->data);
    apm_need(mode<=1,"APM performance mode must be Normal0 or Boost1");return mode;
}
static int apm_known_configuration(uint32_t value) {
    /* IDs explicitly recognized by this actual SDK's ApmCheckPerformanceList.
       They remain advisory tokens here, never claims about host MHz/voltage. */
    return (value>=0x10000&&value<=0x10002)||(value>=0x20000&&value<=0x20006)||
           (value>=0x92220007&&value<=0x9222000c);
}
static void apm_session(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    apm_need(session->state==&apm_state,"APM session state missing");
    switch(rq->cmd){
    case 0:{
        apm_shape(rq,8);uint32_t mode=apm_mode(rq),configuration=apm_u32(rq->data+4);
        if(!apm_known_configuration(configuration)){
            fprintf(stderr,"[castlevania-apm] unsupported configuration mode=%u token=%#x\n",mode,configuration);
            runtime_fail("APM configuration token unsupported");
        }
        pthread_mutex_lock(&apm_lock);apm_state.configuration[mode]=configuration;
        apm_state.configured[mode]=1;pthread_mutex_unlock(&apm_lock);
        fprintf(stderr,"[castlevania-apm] requested logical configuration mode=%u token=%#x; host OS manages clocks\n",mode,configuration);
        return;
    }
    case 1:{
        apm_shape(rq,4);uint32_t mode=apm_mode(rq),configuration;
        pthread_mutex_lock(&apm_lock);
        unsigned configured=apm_state.configured[mode];configuration=apm_state.configuration[mode];
        pthread_mutex_unlock(&apm_lock);
        if(!configured){fprintf(stderr,"[castlevania-apm] configuration mode=%u has not been set\n",mode);
            runtime_fail("APM configuration before Set is unmeasured");}
        IPC_OUT(rs,configuration);return;
    }
    default:ipc_unimplemented(session,rq); /* includes CPU overclock requests */
    }
}
static void apm_manager(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    switch(rq->cmd){
    case 0:
        apm_shape(rq,0);
        rs->move[rs->nmove++]=runtime_ipc_new_session("apm:ISession",apm_session,&apm_state,NULL);
        fprintf(stderr,"[castlevania-apm] opened logical application session\n");return;
    case 1:{
        apm_shape(rq,0);
        uint32_t mode=runtime_handheld_mode()?0u:1u; /* same policy as input/applet host */
        IPC_OUT(rs,mode);return;
    }
    default:ipc_unimplemented(session,rq);
    }
}
/* Pre-main only registers handlers; no env/profile/state/log reads or writes. */
__attribute__((constructor)) static void apm_register(void) {runtime_ipc_register("apm",apm_manager,NULL,NULL);}
