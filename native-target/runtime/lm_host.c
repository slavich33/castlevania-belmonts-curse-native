/* Native diagnostic implementation of lm/ILogService and ILogger.
 * Protocol reference: Atmosphere libstratosphere lm interfaces (see provenance).
 * Written independently: no SDK initializer override and no transport bypass. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"
#include "mach_vm_compat.h"
#include <mach/mach.h>
#include <errno.h>
#include <inttypes.h>

#ifndef CASTLEVANIA_LM_LOG_LIMIT
#define CASTLEVANIA_LM_LOG_LIMIT (4u*1024u*1024u)
#endif
#define LM_PACKET_LIMIT 65535u
#define LM_MESSAGE_LIMIT 65536u
#define LM_LOGGERS 64u
#define LM_STREAMS 16u
/* State is process-lifetime and bounded: the generic IPC clone protocol borrows
 * session state. Do not free/reuse a logger while such a clone may still exist. */
typedef struct {
    uint64_t tid,key,value,left;
    unsigned open,phase,shift,total;
} LmStream;
typedef struct { uint64_t pid; unsigned id; LmStream streams[LM_STREAMS]; } LmLogger;
static LmLogger lm_loggers[LM_LOGGERS];
static unsigned lm_used;
/* LM destinations are service-global, shared by every logger and its clones. */
static unsigned lm_destination=1; /* TargetManager, the actual LM default. */
static int lm_fd=-1;
static pthread_mutex_t lm_lock=PTHREAD_MUTEX_INITIALIZER;

static void lm_need(int condition,const char *message) { if(!condition)runtime_fail(message); }
static uint32_t lm_u32(const uint8_t *p) {uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t lm_u64(const uint8_t *p) {uint64_t v;memcpy(&v,p,8);return v;}
static void lm_args(const IpcRequest *rq,unsigned bytes) {
    /* CMIF alignment slack has unspecified bytes, not additional arguments. */
    lm_need(rq->data_size>=bytes&&rq->data_size<=bytes+20,"LM command argument size");
    lm_need(!rq->ncopy&&!rq->nmove&&!rq->nb&&!rq->nw&&!rq->nc,"LM unexpected handles/output buffers");
}
static void lm_sink(void) {
    if(lm_fd>=0)return;
    castlevania_check_host_scratch();
    const char *logs=castlevania_run_directory("CASTLEVANIA_LOG_DIR","logs");
    int dir=open(logs,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    lm_need(dir>=0,"LM log directory open");
    lm_fd=openat(dir,"guest-lm.log",O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW|O_CLOEXEC,0600);close(dir);
    struct stat st;
    lm_need(lm_fd>=0&&!fstat(lm_fd,&st)&&S_ISREG(st.st_mode)&&st.st_uid==getuid()&&
            (st.st_mode&0777)==0600&&st.st_nlink==1,"LM log must be an owned regular 0600 file");
}
static void lm_write(const char *line,size_t bytes) {
    lm_sink();struct stat st;
    lm_need(!fstat(lm_fd,&st)&&st.st_size>=0&&(uint64_t)st.st_size+bytes<=CASTLEVANIA_LM_LOG_LIMIT,
            "LM diagnostic log budget exhausted");
    for(size_t done=0;done<bytes;){ssize_t n=write(lm_fd,line+done,bytes-done);
        if(n<0&&errno==EINTR)continue;
        lm_need(n>0,"LM log write failed");done+=(size_t)n;}
    lm_need(fsync(lm_fd)==0,"LM log flush failed");
}
static LmStream *lm_stream(LmLogger *logger,uint64_t tid,unsigned flags) {
    LmStream *free_slot=NULL,*stream=NULL;
    for(unsigned i=0;i<LM_STREAMS;i++){
        LmStream *s=&logger->streams[i];if(s->open&&s->tid==tid)stream=s;
        if(!s->open&&!free_slot)free_slot=s;
    }
    if(flags&1){lm_need(!stream,"LM head interrupts an unfinished message");
        lm_need(free_slot!=NULL,"LM too many concurrent log streams");
        stream=free_slot;memset(stream,0,sizeof *stream);stream->tid=tid;stream->open=1;}
    lm_need(stream!=NULL,"LM continuation without message head");return stream;
}
static void lm_chunks(LmStream *stream,const uint8_t *p,size_t bytes,unsigned flags) {
    lm_need(bytes<=LM_MESSAGE_LIMIT-stream->total,"LM logical message budget exceeded");stream->total+=(unsigned)bytes;
    /* ULEB128 key/length and chunk values may continue in the next packet. */
    for(size_t i=0;i<bytes;i++){
        if(stream->phase==2){if(!--stream->left)stream->phase=0;continue;}
        unsigned v=p[i];
        lm_need(stream->shift<64&&(stream->shift!=63||(v&0x7e)==0),"LM ULEB128 overflow");
        stream->value|=(uint64_t)(v&127)<<stream->shift;
        if(v&128){stream->shift+=7;continue;}
        uint64_t value=stream->value;stream->value=0;stream->shift=0;
        if(stream->phase==0){stream->key=value;stream->phase=1;}
        else {lm_need(value<=LM_MESSAGE_LIMIT,"LM chunk length exceeds budget");stream->left=value;stream->phase=value?2:0;}
    }
    if(flags&2){lm_need(stream->phase==0&&!stream->shift,"LM tail has incomplete data chunk");stream->open=0;}
}
static void lm_log(LmLogger *logger,const IpcRequest *rq) {
    lm_args(rq,0);lm_need(!rq->has_pid&&rq->nx<=1&&rq->na<=1,"LM Log request shape");
    const IpcBuffer *buffer=NULL;
    if(rq->nx&&rq->x[0].size)buffer=&rq->x[0];
    if(rq->na&&rq->a[0].size){lm_need(!buffer,"LM ambiguous AutoSelect buffers");buffer=&rq->a[0];}
    lm_need(buffer&&buffer->size>=24&&buffer->size<=LM_PACKET_LIMIT&&buffer->addr&&
            buffer->addr<=UINT64_MAX-buffer->size,"LM packet buffer bounds");
    size_t size=(size_t)buffer->size;uint8_t *packet=malloc(size);lm_need(packet!=NULL,"LM packet snapshot allocation");
    mach_vm_size_t got=0;
    lm_need(mach_vm_read_overwrite(mach_task_self(),buffer->addr,size,(mach_vm_address_t)(uintptr_t)packet,&got)==KERN_SUCCESS&&got==size,
            "LM packet buffer is not readable");
    uint64_t tid=lm_u64(packet+8);unsigned flags=packet[16],severity=packet[18],verbosity=packet[19];
    uint32_t payload=lm_u32(packet+20);
    lm_need(payload==size-24,"LM packet payload length mismatch");
    /* Byte17 is ABI padding, with unspecified contents. */
    lm_need(!(flags&~7u)&&(flags&4)&&severity<=4,"LM packet flags/severity unsupported");
    pthread_mutex_lock(&lm_lock);
    LmStream *stream=lm_stream(logger,tid,flags);lm_chunks(stream,packet+24,payload,flags);
    /* Override untrusted packet pid with the opener's single-process host pid.
       Preserve payload losslessly, escaped as hex; fragments remain separate. */
    size_t capacity=256+2u*payload;char *line=malloc(capacity);lm_need(line!=NULL,"LM log line allocation");
    int n=snprintf(line,capacity,"logger=%u pid=%" PRIu64 " tid=%" PRIu64 " flags=%u severity=%u verbosity=%u destination=%u payload_bytes=%u payload_hex=",
                   logger->id,logger->pid,tid,flags,severity,verbosity,lm_destination,payload);
    lm_need(n>0&&(size_t)n<capacity,"LM log line bounds");size_t used=(size_t)n;
    if(lm_destination){static const char hex[]="0123456789abcdef";
        for(unsigned i=0;i<payload;i++){line[used++]=hex[packet[24+i]>>4];line[used++]=hex[packet[24+i]&15];}}
    else {memcpy(line+used,"disabled",8);used+=8;}
    line[used++]='\n';lm_write(line,used);free(line);pthread_mutex_unlock(&lm_lock);free(packet);
}
static void lm_logger(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    (void)rs;LmLogger *logger=session->state;lm_need(logger!=NULL,"LM logger state missing");
    switch(rq->cmd){
    case 0:lm_log(logger,rq);return;
    case 1:{lm_args(rq,4);lm_need(!rq->has_pid&&!rq->nx&&!rq->na,"LM SetDestination request shape");
        unsigned mask=lm_u32(rq->data);lm_need(mask==0xffff||!(mask&~7u),"LM destination mask unsupported");
        pthread_mutex_lock(&lm_lock);char line[100];
        int n=snprintf(line,sizeof line,"logger=%u set_destination=%u host_sink=guest-lm.log\n",logger->id,mask);
        lm_write(line,(size_t)n);lm_destination=mask;pthread_mutex_unlock(&lm_lock);return;}
    default:ipc_unimplemented(session,rq);
    }
}
static void lm_service(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    if(rq->cmd!=0)ipc_unimplemented(session,rq);
    lm_args(rq,8);lm_need(rq->has_pid&&!rq->nx&&!rq->na&&lm_u64(rq->data)==0,"LM OpenLogger requires ClientProcessId placeholder/PID descriptor");
    pthread_mutex_lock(&lm_lock);lm_need(lm_used<LM_LOGGERS,"LM diagnostic logger budget exhausted");
    LmLogger *logger=&lm_loggers[lm_used++];logger->id=lm_used;logger->pid=(uint64_t)getpid();
    char line[100];int n=snprintf(line,sizeof line,"logger=%u open pid=%" PRIu64 " host_sink=guest-lm.log\n",logger->id,logger->pid);
    lm_write(line,(size_t)n);pthread_mutex_unlock(&lm_lock);
    rs->move[rs->nmove++]=runtime_ipc_new_session("lm:ILogger",lm_logger,logger,NULL);
}
__attribute__((constructor)) static void lm_register(void) {runtime_ipc_register("lm",lm_service,NULL,NULL);}
