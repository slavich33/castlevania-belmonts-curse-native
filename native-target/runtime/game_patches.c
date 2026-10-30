#include "game_patches.h"
#include "castlevania_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void runtime_game_patches(Module *m) {
 if(!m || strcmp(m->name,"main"))runtime_fail("Castlevania title patches require the main module");
 if(getenv("TOTK_PCHTXT") || getenv("CASTLEVANIA_PCHTXT"))runtime_fail("no measured Castlevania PCHTXT/title patch profile exists");
 fprintf(stderr,"[castlevania] no title-specific code patches applied\n");
}
/* Optional title-specific UI overrides are disabled; these are not guest-service
 * results or gameplay compatibility evidence. No guest addresses are accessed. */
void runtime_frame_step_pin(double ms) {if(ms!=0)runtime_fail("Castlevania frame-step override is not measured");}
void runtime_frame_step_update(uint64_t now_ns) {(void)now_ns;}
int runtime_output_res(unsigned *w,unsigned *h) {(void)w;(void)h;return 0;}
uint64_t runtime_output_res_extra_bytes(void) {return 0;}
uint64_t runtime_output_size_current(void) {return 0;}
int runtime_output_res_toggle(void) {return 0;}
int runtime_output_mode_cycle(void) {return 0;}
int runtime_render_configure(unsigned w,unsigned h,int quality) {(void)w;(void)h;(void)quality;return 0;}
uint64_t runtime_render_applied(void) {return 0;}
/* Host presentation queries remain available without importing a foreign
 * camera patch. Zero preserves the game's own aspect and reports no toggle. */
float runtime_aspect_now(void) {return 0;}
int runtime_aspect_toggle(void) {return 0;}
