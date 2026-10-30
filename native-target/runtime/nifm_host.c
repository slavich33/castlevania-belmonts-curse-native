/* Measured nifm:u/CreateGeneralService transport only. Network status, interface
 * identity and requests require a Horizon bridge which is not implemented.
 * See provenance/NIFM_HOST_20261027.json. No SDK initializer is interposed. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

static void nifm_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static void nifm_general(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    (void)rs;castlevania_check_host_scratch();
    nifm_need(session->state==NULL,"NIFM unexpected GeneralService state");
    /* This policy describes bridge support, not the Mac's connectivity. Do not
     * manufacture disconnected/connected status, addresses or request results. */
    fprintf(stderr,"[castlevania-nifm] Horizon network bridge is unimplemented; no status or request result is available\n");
    ipc_unimplemented(session,rq);
}
static void nifm_factory(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    castlevania_check_host_scratch();
    nifm_need(session->state==NULL,"NIFM unexpected StaticService state");
    if(rq->cmd!=5)ipc_unimplemented(session,rq);
    nifm_need((rq->type==4||rq->type==6)&&rq->has_pid==1&&!rq->ncopy&&!rq->nmove&&
              !rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,
              "NIFM CreateGeneralService unexpected transport/PID/handles/buffers");
    /* CMIF alignment slack is unspecified; the sole raw argument is u64zero. */
    nifm_need(rq->data&&rq->data_size>=8&&rq->data_size<=28,"NIFM CreateGeneralService argument size");
    uint64_t reserved;memcpy(&reserved,rq->data,8);
    nifm_need(!reserved,"NIFM CreateGeneralService reserved argument must be zero");
    /* A genuine independent IpcSession; generic CMIF turns its MOVE handle into
     * a domain object for the measured SDK. With every RPC unsupported, no
     * network state exists to own or borrow across copies/clones. */
    rs->move[rs->nmove++]=runtime_ipc_new_session("nifm:IGeneralService",nifm_general,NULL,NULL);
    fprintf(stderr,"[castlevania-nifm] created application GeneralService; Horizon network bridge unimplemented\n");
}
static void *nifm_open(void) {castlevania_check_host_scratch();return NULL;}
/* Pre-main registration only: no profile/environment/process/network/file I/O. */
__attribute__((constructor)) static void nifm_register(void) {
    runtime_ipc_register("nifm:u",nifm_factory,nifm_open,NULL);
}
