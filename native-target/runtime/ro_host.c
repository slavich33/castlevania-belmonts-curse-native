/* Measured ldr:ro process registration and authenticated immutable NRR registry.
 * No NRO is mapped/loaded. See RO_HOST and NRR_REGISTRATION provenance. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include "nrr_validate.h"
#include "mach_vm_compat.h"
#include <limits.h>
#include <mach/mach.h>

#define RO_CURRENT_PROCESS_HANDLE 0xffff8001u
#define RO_RESULT_INVALID_SESSION 0x80c16u /* module22, description1030 */
#define RO_MAX_NRRS 64u
typedef struct {
    uint64_t address,size;
    uint8_t *snapshot;
    RuntimeNrrValidated validated;
} RoNrrRegistration;
typedef struct {
    unsigned references,registered;
    pid_t host_pid;
    unsigned nrr_count;
    RoNrrRegistration nrrs[RO_MAX_NRRS];
} RoProcessRegistration;
static pthread_mutex_t ro_lock=PTHREAD_MUTEX_INITIALIZER;
static RoProcessRegistration *ro_registered;

static void ro_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static void *ro_open(void) {
    castlevania_check_host_scratch();
    RoProcessRegistration *state=calloc(1,sizeof *state);
    ro_need(state!=NULL,"RO session state allocation");state->references=1;return state;
}
static void ro_retain(void *opaque) {
    RoProcessRegistration *state=opaque;
    ro_need(state!=NULL,"RO retain missing state");
    pthread_mutex_lock(&ro_lock);
    ro_need(state->references&&state->references<UINT_MAX,"RO reference count overflow or dead state");
    state->references++;pthread_mutex_unlock(&ro_lock);
}
static void ro_close(void *opaque) {
    RoProcessRegistration *state=opaque;
    ro_need(state!=NULL,"RO close missing state");
    pthread_mutex_lock(&ro_lock);
    ro_need(state->references!=0,"RO release dead state");
    unsigned last=!--state->references;
    if(last&&state->registered){
        ro_need(ro_registered==state,"RO process registration ownership");
        ro_registered=NULL;state->registered=0;state->host_pid=0;
    }
    pthread_mutex_unlock(&ro_lock);
    if(last){for(unsigned i=0;i<state->nrr_count;i++)free(state->nrrs[i].snapshot);free(state);}
}
static void ro_shape(const IpcRequest *rq,unsigned bytes,unsigned copies) {
    ro_need((rq->type==4||rq->type==6)&&rq->has_pid==1&&rq->ncopy==copies&&
            !rq->nmove&&!rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,
            "RO unexpected transport/PID/handles/buffers");
    /* CMIF's alignment slack is not an additional argument and is unspecified. */
    ro_need(rq->data&&rq->data_size>=bytes&&rq->data_size<=bytes+20,"RO command argument size");
    uint64_t placeholder;memcpy(&placeholder,rq->data,8);
    ro_need(!placeholder,"RO ClientProcessId placeholder must be zero");
}
static void ro_register_process(RoProcessRegistration *state,const IpcRequest *rq,IpcResponse *rs) {
    ro_shape(rq,8,1);
    ro_need(rq->copy[0]==RO_CURRENT_PROCESS_HANDLE,
            "RO requires current-process COPY handle");
    /* ipc.c is in-process, not a Horizon kernel: it preserves wire PID bits.
     * Do not trust rq->pid as authenticated. The measured pseudo handle names
     * this native process; bind the registration to its actual host identity.
     * The pseudo handle is not an owned runtime handle and is never consumed. */
    pid_t host_pid=getpid();ro_need(host_pid>0,"RO host process identity");
    pthread_mutex_lock(&ro_lock);
    ro_need(state->references!=0,"RO request on dead state");
    if(state->registered||ro_registered){rs->result=RO_RESULT_INVALID_SESSION;}
    else {state->registered=1;state->host_pid=host_pid;ro_registered=state;}
    pthread_mutex_unlock(&ro_lock);
    /* Empty success means that this host registration exists, not that any
     * module, signature, NRR, mapping or future execution has been accepted. */
}
static void ro_register_nrr(RoProcessRegistration *state,const IpcRequest *rq) {
    ro_shape(rq,24,0);
    uint64_t address,size;memcpy(&address,rq->data+8,8);memcpy(&size,rq->data+16,8);
    ro_need(address&&!(address&0xfff)&&size&&!(size&0xfff)&&
            size<=RUNTIME_NRR_MAX_BYTES&&address<=UINT64_MAX-size,"RO NRR address/size bounds");
    pthread_mutex_lock(&ro_lock);
    ro_need(state->registered&&ro_registered==state&&state->host_pid==getpid(),"RO NRR requires live current-process registration");
    pthread_mutex_unlock(&ro_lock);
    uint8_t *snapshot=malloc((size_t)size);ro_need(snapshot!=NULL,"RO NRR snapshot allocation");
    mach_vm_size_t got=0;
    if(mach_vm_read_overwrite(mach_task_self(),address,size,(mach_vm_address_t)(uintptr_t)snapshot,&got)!=KERN_SUCCESS||got!=size){
        free(snapshot);runtime_fail("RO NRR snapshot is not fully readable");
    }
    RuntimeNrrValidated validated;
    const char *error=runtime_nrr_validate(snapshot,(size_t)size,CASTLEVANIA_TITLE_ID,&validated);
    if(error){free(snapshot);runtime_fail(error);}
    pthread_mutex_lock(&ro_lock);
    ro_need(state->registered&&ro_registered==state&&state->host_pid==getpid(),"RO NRR process registration changed");
    ro_need(state->nrr_count<RO_MAX_NRRS,"RO NRR registry capacity");
    for(unsigned i=0;i<state->nrr_count;i++)ro_need(state->nrrs[i].address!=address,"RO NRR address already registered");
    state->nrrs[state->nrr_count++]=(RoNrrRegistration){address,size,snapshot,validated};
    pthread_mutex_unlock(&ro_lock);
    /* Own the validated immutable original hash list. The caller's mutable
     * buffer is never an authorization source for future module operations.
     * No code memory has been mapped and no NRO has been loaded or executed. */
}
static void ro_service(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    castlevania_check_host_scratch();
    RoProcessRegistration *state=session->state;ro_need(state!=NULL,"RO session state missing");
    switch(rq->cmd){
    case 4:ro_register_process(state,rq,rs);return;
    case 2:ro_register_nrr(state,rq);return;
    default:ipc_unimplemented(session,rq);
    }
}
/* Registration only before main: no process lookup, state allocation, profile,
 * environment, file or log access. Generic retained sessions own state lifetime. */
__attribute__((constructor)) static void ro_register(void) {
    runtime_ipc_register_retained("ldr:ro",ro_service,ro_open,ro_retain,ro_close);
}
