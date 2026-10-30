/* No Castlevania world/actor layout has been measured. Optional survey controls
 * remain unavailable; no legacy address or guest memory is consulted. */
#include "world_survey.h"
#include "castlevania_policy.h"
#include <stdlib.h>
#include <string.h>
_Atomic int runtime_survey_pending;
const int32_t runtime_survey_sync[2]={0,0};
void runtime_survey_init(Module *m) {
 (void)m;
 if(getenv("CASTLEVANIA_SURVEY"))runtime_fail("Castlevania world survey is not measured");
}
int runtime_survey_command(const char *line) {
 if(line && (!strncmp(line,"survey",6)||!strncmp(line,"warp",4)))runtime_fail("Castlevania world survey is unavailable");
 return 0;
}
void runtime_survey_tick(uint64_t frame) {
 (void)frame;
 if(atomic_load(&runtime_survey_pending))runtime_fail("Castlevania world survey is unavailable");
}
void runtime_survey_cancel_user(void) {atomic_store(&runtime_survey_pending,0);}
