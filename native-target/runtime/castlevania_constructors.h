#pragma once
/* Read-only invariants for this measured v1.1.0 three-DSO startup. The musl
 * registration result1 means deferred, not failed or completed constructors.
 * Original main DT_INIT drains the deferred callbacks; this helper never calls
 * guest code, writes a guest flag, skips a module or runs an init array. */
#include "castlevania_policy.h"
#include <stdint.h>
#include <string.h>

typedef struct { unsigned phase,in_flight; } CvCtorProtocol;

static inline int cv_ctor_profile(void) {
    return CASTLEVANIA_TITLE_ID==0x0100ba4026e94000ULL&&
        !strcmp(CASTLEVANIA_GAME_VERSION,"1.1.0")&&!strcmp(CASTLEVANIA_GAME_DIR,"v110");
}
static inline const char *cv_ctor_module(unsigned phase) {
    static const char *const order[]={"sdk","subsdk0","main"};
    return phase<3?order[phase]:NULL;
}
/* Zero-initialize the protocol once. Call begin immediately before each
 * original DT_INIT, end only after it returns, and fail if either returns0. */
static inline int cv_ctor_begin(CvCtorProtocol *protocol,const char *module,uint32_t before) {
    if(!cv_ctor_profile()||!protocol||protocol->in_flight||protocol->phase>=3||
       !module||strcmp(module,cv_ctor_module(protocol->phase))||before!=0)return 0;
    protocol->in_flight=1;return 1;
}
static inline int cv_ctor_end(CvCtorProtocol *protocol,const char *module,uint32_t after) {
    if(!cv_ctor_profile()||!protocol||protocol->in_flight!=1||protocol->phase>=3||
       !module||strcmp(module,cv_ctor_module(protocol->phase))||
       after!=(protocol->phase==2?2u:1u))return 0;
    protocol->in_flight=0;protocol->phase++;return 1;
}
/* Only a normal main DT_INIT return closes the completion barrier. SDK/sub
 * callbacks execute inside main's original registration helper, keep result1,
 * and must not be retried or forced to2 by the host. */
static inline int cv_ctor_finish(const CvCtorProtocol *protocol,uint32_t main_state,
                                uint32_t sub_state,uint32_t sdk_state) {
    return cv_ctor_profile()&&protocol&&protocol->phase==3&&!protocol->in_flight&&
        main_state==2&&sub_state==1&&sdk_state==1;
}
