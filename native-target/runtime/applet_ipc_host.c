/* Minimal native application applet IPC. SDK initialization executes normally;
 * this adapts its measured appletOE requests to the existing host applet policy.
 * See provenance/APPLET_IPC_HOST_20261027.json for wire scope and limitations. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

/* Shared-queue bridge in applet_host.c. Every returned readable event is a new
 * copy handle to that queue's service-owned event, never an unrelated signal. */
uint32_t runtime_oe_message_event(void);
int runtime_oe_try_pop_message(uint32_t *message);

typedef struct {
    unsigned operation_notification,performance_notification,resume_notification;
    unsigned focus_handling[3],out_of_focus_suspending;
    unsigned foreground_acquired,running_notified;
    unsigned exit_to_library_at_next_program;
    uint32_t suspended_tick_event,gpu_error_event;
    unsigned gpu_error_detected;
    uint32_t cpu_boost_requested;
    unsigned cpu_boost_requested_valid;
} AppletIpcState;
static AppletIpcState applet_ipc_state;
static pthread_mutex_t applet_ipc_lock=PTHREAD_MUTEX_INITIALIZER;

/* Called by real host GPU failure paths, including host callback threads. A
 * failure before cmd130 is retained without allocating an event before use.
 * This is a sticky failure notification, never a simulated device-loss toggle. */
void runtime_applet_signal_gpu_error(void) {
    pthread_mutex_lock(&applet_ipc_lock);
    applet_ipc_state.gpu_error_detected=1;
    if(applet_ipc_state.gpu_error_event)runtime_event_signal(applet_ipc_state.gpu_error_event);
    pthread_mutex_unlock(&applet_ipc_lock);
}

static void applet_need(int condition,const char *message) {if(!condition)runtime_fail(message);}
static void applet_shape(const IpcRequest *rq,unsigned bytes,int opening) {
    castlevania_check_host_scratch();
    applet_need((rq->type==4||rq->type==6)&&rq->has_pid==opening&&rq->ncopy==(unsigned)opening&&
                !rq->nmove&&!rq->nx&&!rq->na&&!rq->nb&&!rq->nw&&!rq->nc,
                "applet unexpected transport/PID/handles/buffers");
    /* CMIF alignment slack has unspecified bytes; domain requests have exact data. */
    applet_need(rq->data_size>=bytes&&rq->data_size<=bytes+20,"applet command argument size");
}
static void applet_state_check(const IpcSession *session) {
    applet_need(session->state==&applet_ipc_state,"applet interface state missing");
}
static uint8_t applet_focus(void) {
    int focus=runtime_front_focus();
    applet_need(focus>=1&&focus<=3,"host applet focus policy is not a protocol FocusState");
    return (uint8_t)focus;
}
static void applet_unavailable(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    (void)rs;applet_state_check(session);castlevania_check_host_scratch();ipc_unimplemented(session,rq);
}
static void applet_common(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    applet_state_check(session);applet_shape(rq,rq->cmd==66?4u:0u,0);
    switch(rq->cmd){
    case 0: /* GetEventHandle: COPY a manual-clear readable message-queue event. */
        rs->copy[rs->ncopy++]=runtime_oe_message_event();return;
    case 1:{
        uint32_t message;
        if(!runtime_oe_try_pop_message(&message)){rs->result=0x680u;return;}
        IPC_OUT(rs,message);return;
    }
    case 5:{uint8_t mode=runtime_handheld_mode()?0u:1u;IPC_OUT(rs,mode);return;}
    case 6:{uint32_t mode=runtime_handheld_mode()?0u:1u;IPC_OUT(rs,mode);return;}
    case 9:{uint8_t focus=applet_focus();IPC_OUT(rs,focus);return;}
    case 66:{ /* SetCpuBoostMode(u32): this applet API accepts Normal0/FastLoad1. */
        uint32_t mode;memcpy(&mode,rq->data,4);
        applet_need(mode<=1,"applet CpuBoostMode must be Normal0 or FastLoad1");
        pthread_mutex_lock(&applet_ipc_lock);applet_ipc_state.cpu_boost_requested=mode;
        applet_ipc_state.cpu_boost_requested_valid=1;pthread_mutex_unlock(&applet_ipc_lock);
        /* Advisory host loading intent only. macOS manages clocks; no GPU
         * throttling, achieved performance or performance-change event is implied. */
        return;
    }
    case 900:
        /* RequestExitToLibraryApplet at a future ExecuteNextProgram. Record
         * the request; executing another program remains unsupported. */
        pthread_mutex_lock(&applet_ipc_lock);applet_ipc_state.exit_to_library_at_next_program=1;
        pthread_mutex_unlock(&applet_ipc_lock);return;
    default:ipc_unimplemented(session,rq);
    }
}
static void applet_self(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    applet_state_check(session);
    unsigned bytes=rq->cmd==13?3u:1u;
    switch(rq->cmd){
    case 11: case 12: case 13: case 14: case 16:
        applet_shape(rq,bytes,0);
        for(unsigned i=0;i<bytes;i++)applet_need(rq->data[i]<=1,"applet policy argument is not a bool");
        pthread_mutex_lock(&applet_ipc_lock);
        if(rq->cmd==11)applet_ipc_state.operation_notification=rq->data[0];
        else if(rq->cmd==12)applet_ipc_state.performance_notification=rq->data[0];
        else if(rq->cmd==14)applet_ipc_state.resume_notification=rq->data[0];
        else if(rq->cmd==16)applet_ipc_state.out_of_focus_suspending=rq->data[0];
        else for(unsigned i=0;i<3;i++)applet_ipc_state.focus_handling[i]=rq->data[i];
        pthread_mutex_unlock(&applet_ipc_lock);
        /* These are the logical notification/suspension preferences for this
         * process. Current host policy keeps it foreground and operation mode
         * is fixed per run; enabling resume notifications neither resumes this
         * process nor fabricates a resume message, suspended tick or event. */
        return;
    case 91:
        applet_shape(rq,0,0);
        /* The existing host never enters a logical suspended state. This
         * separate event remains unsignaled until such a counter transition
         * is actually implemented; it is not the CommonStateGetter event. */
        pthread_mutex_lock(&applet_ipc_lock);
        if(!applet_ipc_state.suspended_tick_event)applet_ipc_state.suspended_tick_event=runtime_event_new();
        rs->copy[rs->ncopy++]=runtime_event_readable(applet_ipc_state.suspended_tick_event);
        pthread_mutex_unlock(&applet_ipc_lock);return;
    default:applet_shape(rq,0,0);ipc_unimplemented(session,rq);
    }
}
static void applet_window(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    applet_state_check(session);applet_shape(rq,0,0);
    switch(rq->cmd){
    case 1:{
        /* Same one-process ARUID as applet_host.c's existing direct adapter. */
        uint64_t aruid=1;IPC_OUT(rs,aruid);return;
    }
    case 10:
        applet_need(applet_focus()==1,"host applet is not in focus for foreground rights");
        pthread_mutex_lock(&applet_ipc_lock);applet_ipc_state.foreground_acquired=1;
        pthread_mutex_unlock(&applet_ipc_lock);return;
    default:ipc_unimplemented(session,rq);
    }
}
static void applet_functions(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    applet_state_check(session);applet_shape(rq,0,0);
    switch(rq->cmd){
    case 40:{
        pthread_mutex_lock(&applet_ipc_lock);applet_ipc_state.running_notified=1;
        pthread_mutex_unlock(&applet_ipc_lock);
        uint8_t running=1;IPC_OUT(rs,running);return;
    }
    case 130: /* GetGpuErrorDetectedSystemEvent: readable COPY, manual-clear. */
        pthread_mutex_lock(&applet_ipc_lock);
        if(!applet_ipc_state.gpu_error_event)applet_ipc_state.gpu_error_event=runtime_event_new();
        if(applet_ipc_state.gpu_error_detected)runtime_event_signal(applet_ipc_state.gpu_error_event);
        rs->copy[rs->ncopy++]=runtime_event_readable(applet_ipc_state.gpu_error_event);
        pthread_mutex_unlock(&applet_ipc_lock);return;
    default:ipc_unimplemented(session,rq);
    }
}
static void applet_proxy(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    applet_state_check(session);applet_shape(rq,0,0);
    IpcHandler handler=NULL;const char *name=NULL;
    switch(rq->cmd){
    case 0:handler=applet_common;name="applet:ICommonStateGetter";break;
    case 1:handler=applet_self;name="applet:ISelfController";break;
    case 2:handler=applet_window;name="applet:IWindowController";break;
    case 3:name="applet:IAudioController";break;
    case 4:name="applet:IDisplayController";break;
    case 11:name="applet:ILibraryAppletCreator";break;
    case 20:handler=applet_functions;name="applet:IApplicationFunctions";break;
    case 1000:name="applet:IDebugFunctions";break;
    default:ipc_unimplemented(session,rq);
    }
    /* Opening the SDK's interface is supported; unmeasured methods on the
     * audio/display/library/debug objects still fail with their exact command. */
    rs->move[rs->nmove++]=runtime_ipc_new_session(name,handler?handler:applet_unavailable,&applet_ipc_state,NULL);
}
static void applet_oe(IpcSession *session,const IpcRequest *rq,IpcResponse *rs) {
    if(rq->cmd!=0)ipc_unimplemented(session,rq);
    applet_shape(rq,8,1);
    uint64_t reserved;memcpy(&reserved,rq->data,8);
    applet_need(!reserved&&rq->copy[0]==0xffff8001u,
                "OpenApplicationProxy requires reserved0 and current-process COPY handle");
    rs->move[rs->nmove++]=runtime_ipc_new_session("applet:IApplicationProxy",applet_proxy,&applet_ipc_state,NULL);
    fprintf(stderr,"[castlevania-applet] opened application proxy; shared host focus/queue policy\n");
}
/* Registration only; no events, profile or environment access before main. */
__attribute__((constructor)) static void applet_ipc_register(void) {
    runtime_ipc_register("appletOE",applet_oe,NULL,NULL);
}
