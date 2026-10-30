/* Measured PCTL factory/Initialize lifecycle only. This establishes local IPC
 * objects, not any restriction, permission, entitlement or safety-level policy.
 * See provenance/PCTL_HOST_20261027.json. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

typedef struct { const char *factory_name,*service_name; } PctlFamily;
static const PctlFamily pctl_families[]={
    {"pctl","pctl:IParentalControlService"},
    {"pctl:s","pctl:s:IParentalControlService"},
    {"pctl:a","pctl:a:IParentalControlService"},
    {"pctl:r","pctl:r:IParentalControlService"}
};
/* Generic IPC clones borrow state. Keep bounded objects for process lifetime;
 * this is a host allocation budget, not a fabricated Horizon session limit. */
#define PCTL_OBJECTS 32u
typedef struct { const PctlFamily *family; unsigned initialized; } PctlObject;
static PctlObject pctl_objects[PCTL_OBJECTS];
static unsigned pctl_used;
static pthread_mutex_t pctl_lock=PTHREAD_MUTEX_INITIALIZER;

static void pctl_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static int pctl_known_family(const PctlFamily *family) {
    for(unsigned i=0;i<sizeof pctl_families/sizeof *pctl_families;i++)if(family==&pctl_families[i])return 1;
    return 0;
}
static void pctl_shape(const IpcRequest *rq,unsigned bytes,int pid) {
    castlevania_check_host_scratch();
    pctl_need((rq->type==4||rq->type==6)&&rq->has_pid==pid&&!rq->ncopy&&!rq->nmove&&
              !rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,
              "PCTL unexpected transport/PID/handles/buffers");
    /* CMIF alignment bytes are unspecified, not extra raw arguments. */
    pctl_need(rq->data_size>=bytes&&rq->data_size<=bytes+20,"PCTL command argument size");
    if(pid){uint64_t placeholder;memcpy(&placeholder,rq->data,8);
        pctl_need(!placeholder,"PCTL ClientProcessId placeholder must be zero");}
}
static void pctl_service(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    (void)rs;PctlObject *object=session->state;
    pctl_need(object&&pctl_known_family(object->family),"PCTL service state missing");
    if(rq->cmd!=1){castlevania_check_host_scratch();ipc_unimplemented(session,rq);}
    pctl_shape(rq,0,0);
    /* Per-object lifecycle only; never read/write host parental-control settings
     * or return a permission/restriction result. Such methods remain unsupported. */
    pthread_mutex_lock(&pctl_lock);object->initialized=1;pthread_mutex_unlock(&pctl_lock);
}
static void pctl_factory(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    const PctlFamily *family=session->state;
    pctl_need(pctl_known_family(family),"PCTL factory family missing");
    if(rq->cmd!=1){castlevania_check_host_scratch();ipc_unimplemented(session,rq);}
    pctl_shape(rq,8,1);
    pthread_mutex_lock(&pctl_lock);
    pctl_need(pctl_used<PCTL_OBJECTS,"PCTL host object budget exhausted");
    PctlObject *object=&pctl_objects[pctl_used++];object->family=family;
    pthread_mutex_unlock(&pctl_lock);
    /* Generic ipc.c converts this moved session into an object ID for domains. */
    rs->move[rs->nmove++]=runtime_ipc_new_session(family->service_name,pctl_service,object,NULL);
}
static void *pctl_open_family(unsigned index) {castlevania_check_host_scratch();return (void*)&pctl_families[index];}
static void *pctl_open(void) {return pctl_open_family(0);}
static void *pctl_s_open(void) {return pctl_open_family(1);}
static void *pctl_a_open(void) {return pctl_open_family(2);}
static void *pctl_r_open(void) {return pctl_open_family(3);}
/* Distinct named factories, no SM fallback hack or family capability widening.
 * All unmeasured capability-specific methods fail, regardless of the name. */
__attribute__((constructor)) static void pctl_register(void) {
    runtime_ipc_register("pctl",pctl_factory,pctl_open,NULL);
    runtime_ipc_register("pctl:s",pctl_factory,pctl_s_open,NULL);
    runtime_ipc_register("pctl:a",pctl_factory,pctl_a_open,NULL);
    runtime_ipc_register("pctl:r",pctl_factory,pctl_r_open,NULL);
}
