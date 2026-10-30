#pragma once
/* Castlevania-only identity. Deliberately no GAME_ADDR fallback: any remaining
 * title-specific offset in a future host build must fail compilation. */
#include "castlevania_policy.h"
#define GAME_TITLE_ID CASTLEVANIA_TITLE_ID
#define GAME_NAME CASTLEVANIA_GAME_NAME
#define TOTK_GAME_VERSION CASTLEVANIA_GAME_VERSION
#define TOTK_GAME_DIR CASTLEVANIA_GAME_DIR
