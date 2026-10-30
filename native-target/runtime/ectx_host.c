/* Context-writer connection for the measured SDK initializer. The real CMIF
 * session/domain lifetime is provided by ipc.c; no context-write protocol has
 * been measured or implemented. See provenance/ECTX_HOST_20261027.json. */
#include "runtime.h"
#include "ipc.h"
#include "castlevania_policy.h"
#include "castlevania_paths.h"

static void ectx_service(IpcSession *session, const IpcRequest *rq, IpcResponse *rs) {
    (void)rs;
    castlevania_check_host_scratch();
    ipc_unimplemented(session, rq);
}
static void *ectx_open(void) {
    castlevania_check_host_scratch();
    return NULL; /* No context data, log, event, or fabricated writer state. */
}
/* Only registry mutation before main. Opening allocates an actual IpcSession;
 * generic ConvertToDomain/clone/close owns and releases that transport state. */
__attribute__((constructor)) static void ectx_register(void) {
    runtime_ipc_register("ectx:aw", ectx_service, ectx_open, NULL);
}
