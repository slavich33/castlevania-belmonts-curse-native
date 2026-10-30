/* Measured modern bsd:s registration/monitor control plane, with an explicit
 * offline diagnostic socket backend. No Mac connectivity or Horizon bridge is
 * claimed. See provenance/BSD_HOST_20261027.json for actual SDK wire differences. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include <limits.h>

#define BSD_ENETDOWN 100u /* Horizon wire uses Linux errno, not Darwin ENETDOWN50 */
#define BSD_TMEM_MAX (64u*1024u*1024u) /* diagnostic metadata/resource cap */
typedef struct {
    uint32_t version,tcp_tx,tcp_rx,tcp_tx_max,tcp_rx_max,udp_tx,udp_rx,efficiency;
} BsdConfig;
typedef struct {
    uint64_t host_pid;
    unsigned references,monitors;
    BsdConfig config;
    IpcTransferMemory transfer;
} BsdClient;
typedef struct {unsigned references,monitor;BsdClient *client;} BsdSessionState;
static pthread_mutex_t bsd_lock=PTHREAD_MUTEX_INITIALIZER;
static BsdClient *bsd_registered;
_Static_assert(sizeof(BsdConfig)==32,"measured BSD config wire size");

static void bsd_need(int condition,const char *message){if(!condition)runtime_fail(message);}
static void *bsd_open(void){
    castlevania_check_host_scratch();BsdSessionState *state=calloc(1,sizeof *state);
    bsd_need(state!=NULL,"BSD session state allocation");state->references=1;return state;
}
static void bsd_retain(void *opaque){
    BsdSessionState *state=opaque;bsd_need(state!=NULL,"BSD retain missing state");
    pthread_mutex_lock(&bsd_lock);bsd_need(state->references&&state->references<UINT_MAX,"BSD invalid state reference count");
    state->references++;pthread_mutex_unlock(&bsd_lock);
}
static void bsd_close(void *opaque){
    BsdSessionState *state=opaque;bsd_need(state!=NULL,"BSD close missing state");BsdClient *dead=NULL;
    pthread_mutex_lock(&bsd_lock);bsd_need(state->references!=0,"BSD release dead state");
    unsigned last=!--state->references;
    if(last&&state->client){
        BsdClient *client=state->client;bsd_need(bsd_registered==client&&client->references,"BSD client ownership");
        if(state->monitor){bsd_need(client->monitors!=0,"BSD monitor ownership");client->monitors--;}
        if(!--client->references){bsd_need(!client->monitors,"BSD live monitor without client reference");bsd_registered=NULL;dead=client;}
    }
    pthread_mutex_unlock(&bsd_lock);if(dead)free(dead);if(last)free(state);
}
static void bsd_shape(const IpcRequest *rq,unsigned bytes,int pid,unsigned copies){
    bsd_need((rq->type==4||rq->type==6)&&rq->has_pid==pid&&rq->ncopy==copies&&!rq->nmove&&
             !rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,"BSD unexpected transport/PID/handles/buffers");
    bsd_need(rq->data&&rq->data_size>=bytes&&rq->data_size<=bytes+20,"BSD command argument size");
}
static void bsd_register_client(BsdSessionState *state,const IpcRequest *rq,IpcResponse *rs){
    bsd_shape(rq,48,1,1);BsdConfig config;uint64_t placeholder,size;
    memcpy(&config,rq->data,32);memcpy(&placeholder,rq->data+32,8);memcpy(&size,rq->data+40,8);
    bsd_need(!placeholder,"BSD RegisterClient process placeholder must be zero");
    bsd_need(config.version==10,"BSD unsupported config version (measured version10 required)");
    bsd_need(config.efficiency>=1&&config.efficiency<=8&&
             (!config.tcp_tx_max||config.tcp_tx_max>=config.tcp_tx)&&
             (!config.tcp_rx_max||config.tcp_rx_max>=config.tcp_rx),"BSD config buffer bounds");
    IpcTransferMemory *object=runtime_handle_get(rq->copy[0],0);
    bsd_need(object!=NULL,"BSD COPY handle is not live transfer memory");
    /* COPY does not consume the caller's handle. The generic core currently
     * owns only this descriptor; retain its validated metadata by value, never
     * its freed pointer. The offline backend neither accesses nor pins backing
     * memory and does not claim a Horizon shared-memory mapping. */
    IpcTransferMemory transfer;memcpy(&transfer,object,sizeof transfer);
    bsd_need(transfer.addr&&!(transfer.addr&0xfff)&&size&&!(size&0xfff)&&size<=BSD_TMEM_MAX&&
             size==transfer.size&&transfer.addr<=UINT64_MAX-size&&transfer.perm==0,"BSD transfer-memory bounds/size/permission");
    uint64_t required=(uint64_t)(config.tcp_tx_max?config.tcp_tx_max:config.tcp_tx)+
        (config.tcp_rx_max?config.tcp_rx_max:config.tcp_rx)+config.udp_tx+config.udp_rx;
    required=((required+4095)&~UINT64_C(4095))*config.efficiency;
    bsd_need(required&&required<=size,"BSD transfer memory smaller than buffer configuration");
    BsdClient *client=calloc(1,sizeof *client);bsd_need(client!=NULL,"BSD client state allocation");
    client->host_pid=(uint64_t)getpid();bsd_need(client->host_pid!=0,"BSD host process identity");
    client->references=1;client->config=config;client->transfer=transfer;
    pthread_mutex_lock(&bsd_lock);
    bsd_need(state->references&&!state->client&&!bsd_registered,"BSD native process already registered");
    state->client=client;bsd_registered=client;pthread_mutex_unlock(&bsd_lock);
    /* This actual SDK consumes a u32 status and requires0, not a generated PID.
     * Success is published only after a real registration exists. */
    uint32_t status=0;IPC_OUT(rs,status);
}
static void bsd_start_monitor(BsdSessionState *state,const IpcRequest *rq){
    bsd_shape(rq,8,1,0);uint64_t placeholder;memcpy(&placeholder,rq->data,8);
    bsd_need(!placeholder,"BSD StartMonitoring process placeholder must be zero");
    pthread_mutex_lock(&bsd_lock);BsdClient *client=bsd_registered;
    bsd_need(state->references&&!state->client&&client&&client->host_pid==(uint64_t)getpid(),"BSD monitor requires live current-process registration");
    bsd_need(client->references<UINT_MAX&&client->monitors<UINT_MAX,"BSD monitor reference overflow");
    client->references++;client->monitors++;state->client=client;state->monitor=1;
    pthread_mutex_unlock(&bsd_lock);
    /* Logical control-plane attachment retains the registered process until
     * this monitor's final close. It does not start network health callbacks. */
}
static void bsd_handler(IpcSession *session,const IpcRequest *rq,IpcResponse *rs){
    castlevania_check_host_scratch();BsdSessionState *state=session->state;
    bsd_need(state!=NULL,"BSD session state missing");
    switch(rq->cmd){
    case 0:bsd_register_client(state,rq,rs);return;
    case 1:bsd_start_monitor(state,rq);return;
    case 2:case 3:{
        bsd_shape(rq,12,0,0);pthread_mutex_lock(&bsd_lock);
        bsd_need(state->references&&state->client&&state->client==bsd_registered&&!state->monitor,"BSD socket requires a registered client session");
        pthread_mutex_unlock(&bsd_lock);
        fprintf(stderr,"[castlevania-bsd] socket refused by offline diagnostic backend; no Horizon network bridge\n");
        int32_t result=-1;uint32_t error=BSD_ENETDOWN;IPC_OUT(rs,result);IPC_OUT(rs,error);return;
    }
    default:ipc_unimplemented(session,rq);
    }
}
/* Registration only; no pre-main allocation, identity, environment or network IO.
 * Only the measured endpoint is exposed, not the inherited unvalidated bsd:u. */
__attribute__((constructor)) static void register_bsd(void){
    runtime_ipc_register_retained("bsd:s",bsd_handler,bsd_open,bsd_retain,bsd_close);
}
