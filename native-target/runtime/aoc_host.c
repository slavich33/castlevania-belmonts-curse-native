/* Native aoc:u discovery for this prepared base-game-only host. No DLC is
 * installed, owned/mounted through this adapter, purchased or fabricated.
 * See provenance/AOC_HOST_20261027.json for measured wire scope and limits. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

/* Immutable empty inventory. This service never installs/unmounts content, so
 * its list-changed event stays unsignaled. Clones borrow process-lifetime state. */
typedef struct { uint32_t list_changed_event; } AocState;
static AocState aoc_state;
static pthread_mutex_t aoc_lock=PTHREAD_MUTEX_INITIALIZER;

static void aoc_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static uint32_t aoc_u32(const uint8_t *p) {uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t aoc_u64(const uint8_t *p) {uint64_t v;memcpy(&v,p,8);return v;}
static void aoc_shape(const IpcRequest *rq,unsigned bytes,unsigned output_buffers) {
    castlevania_check_host_scratch();
    aoc_need((rq->type==4||rq->type==6)&&rq->has_pid==1&&!rq->ncopy&&!rq->nmove&&
             !rq->nx&&!rq->na&&rq->nb==output_buffers&&!rq->nw&&!rq->nc,
             "AOC unexpected transport/PID/handles/buffers");
    /* CMIF transport alignment bytes are unspecified, not extra arguments. */
    aoc_need(rq->data_size>=bytes&&rq->data_size<=bytes+20,"AOC command argument size");
    aoc_need(!aoc_u64(rq->data+bytes-8),"AOC ClientProcessId placeholder must be zero");
}
static void aoc_service(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    aoc_need(session->state==&aoc_state,"AOC service state missing");
    switch(rq->cmd){
    case 2:{ /* CountAddOnContent(ClientProcessId) -> u32 count. */
        aoc_shape(rq,8,0);uint32_t count=0;IPC_OUT(rs,count);return;
    }
    case 3:{ /* ListAddOnContent(u32 offset,u32 count,ClientProcessId,B<u32>). */
        aoc_shape(rq,16,1);uint32_t count=aoc_u32(rq->data+4);
        const IpcBuffer *out=&rq->b[0];
        aoc_need(out->size>=(uint64_t)count*4&&(!out->size||out->addr)&&
                 out->addr<=UINT64_MAX-out->size,"AOC list output buffer bounds");
        /* Every offset has zero results. No entries exist to write: preserve
         * the caller's buffer rather than fabricating or zero-filling indices. */
        uint32_t written=0;IPC_OUT(rs,written);return;
    }
    case 10: /* GetAddOnContentListChangedEventWithProcessId -> readable COPY. */
        aoc_shape(rq,8,0);
        pthread_mutex_lock(&aoc_lock);
        if(!aoc_state.list_changed_event)aoc_state.list_changed_event=runtime_event_new();
        rs->copy[rs->ncopy++]=runtime_event_readable(aoc_state.list_changed_event);
        pthread_mutex_unlock(&aoc_lock);return;
    default:
        castlevania_check_host_scratch();ipc_unimplemented(session,rq);
    }
}
static void *aoc_open(void) {castlevania_check_host_scratch();return &aoc_state;}
/* Registration only; no profile, environment, inventory or events before main. */
__attribute__((constructor)) static void aoc_register(void) {runtime_ipc_register("aoc:u",aoc_service,aoc_open,NULL);}
