#pragma once
/* Title identity and supported execution scope, independent of legacy hosts. */
#if !defined(GAME_CASTLEVANIA)
#error "Select GAME_CASTLEVANIA explicitly"
#endif
#if defined(GAME_ORI) || defined(TOTK_GAME_V112) || defined(TOTK_GAME_V121) || defined(TOTK_GAME_V143)
#error "Castlevania must not inherit another title's build profile"
#endif
#define CASTLEVANIA_TITLE_ID 0x0100ba4026e94000ULL
#define CASTLEVANIA_TITLE_ID_TEXT "0100BA4026E94000"
#define CASTLEVANIA_GAME_VERSION "1.1.0"
#define CASTLEVANIA_GAME_DIR "v110"
#define CASTLEVANIA_GAME_NAME "Castlevania: Belmont's Curse"
#define CASTLEVANIA_PROFILE_SUBDIR "MacNativeGames/CastlevaniaBelmont"
#define CASTLEVANIA_DISPLAY_SUITE "org.macnativegames.castlevania-belmont.display"
/* Measured API-version checks; these are not a claim about NVN features. */
#define CASTLEVANIA_NVN_REQUIRED_MAJOR 55
#define CASTLEVANIA_NVN_REQUIRED_MINOR_MIN 15
/* Off by default. This only enables the real diagnostic boot entry, subject to
 * the mandatory C-side scratch guard. It does not establish ABI compatibility. */
#ifndef CASTLEVANIA_DIAGNOSTIC_BOOT
#define CASTLEVANIA_DIAGNOSTIC_BOOT 0
#endif
#if CASTLEVANIA_DIAGNOSTIC_BOOT != 0 && CASTLEVANIA_DIAGNOSTIC_BOOT != 1
#error "CASTLEVANIA_DIAGNOSTIC_BOOT must be 0 or 1"
#endif
#define CASTLEVANIA_TITLE_PATCHES_IMPLEMENTED 0

/* ELF locals bind in their module. Other dynamic symbols bind to the first
 * definition in measured load order, including interposed weak SDK callbacks. */
static inline int castlevania_symbol_binds_locally(unsigned defined,unsigned binding) {
    return defined && binding == 0;
}
