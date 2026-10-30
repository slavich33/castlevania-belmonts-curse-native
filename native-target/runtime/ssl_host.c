/* Measured ssl:s service-interface version declaration only. Version3 is an
 * IPC interface revision, not a TLS protocol or certificate/connection result.
 * No TLS context, network connection or trust decision is implemented here. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include <limits.h>

typedef struct { unsigned references; uint32_t interface_version; } SslManager;
static pthread_mutex_t ssl_lock=PTHREAD_MUTEX_INITIALIZER;
static void ssl_need(int condition,const char *message){if(!condition)runtime_fail(message);}
static void *ssl_open(void){
    castlevania_check_host_scratch();
    SslManager *state=calloc(1,sizeof *state);ssl_need(state!=NULL,"SSL manager allocation");
    state->references=1;return state;
}
static void ssl_retain(void *opaque){
    SslManager *state=opaque;ssl_need(state!=NULL,"SSL retain missing manager");
    pthread_mutex_lock(&ssl_lock);
    ssl_need(state->references&&state->references<UINT_MAX,"SSL manager reference overflow or dead state");
    state->references++;pthread_mutex_unlock(&ssl_lock);
}
static void ssl_close(void *opaque){
    SslManager *state=opaque;ssl_need(state!=NULL,"SSL close missing manager");
    pthread_mutex_lock(&ssl_lock);ssl_need(state->references!=0,"SSL release dead manager");
    unsigned last=!--state->references;pthread_mutex_unlock(&ssl_lock);if(last)free(state);
}
static void ssl_service(IpcSession *session,const IpcRequest *rq,IpcResponse *rs){
    (void)rs;castlevania_check_host_scratch();
    SslManager *state=session->state;ssl_need(state!=NULL,"SSL manager state missing");
    if(rq->cmd!=5)ipc_unimplemented(session,rq);
    ssl_need(rq->type==6&&!rq->has_pid&&!rq->ncopy&&!rq->nmove&&
             !rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,
             "SSL SetInterfaceVersion unexpected transport/PID/handles/buffers");
    /* The measured domain CMIF header declares20 bytes:16 header+4 argument.
     * ipc.c removes that header and bounds data_size to exactly4, no slack. */
    ssl_need(rq->data&&rq->data_size==4,"SSL SetInterfaceVersion requires exact u32 argument");
    uint32_t version;memcpy(&version,rq->data,4);
    ssl_need(version==3,"SSL interface version unsupported (measured version3 required)");
    pthread_mutex_lock(&ssl_lock);ssl_need(state->references!=0,"SSL request on dead manager");
    state->interface_version=version;pthread_mutex_unlock(&ssl_lock);
    /* Repeated3 is idempotent. Empty Result0 records this declaration only;
     * every context/connection/certificate/handshake method remains a gate. */
}
/* Before main, registration only: no manager allocation, profile/environment,
 * process, network, Apple TLS object, certificate, keychain or log access. */
__attribute__((constructor)) static void ssl_register(void){
    runtime_ipc_register_retained("ssl:s",ssl_service,ssl_open,ssl_retain,ssl_close);
}
