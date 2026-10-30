# Castlevania: Belmont's Curse — Native Apple Silicon Port Research

Experimental **Castlevania: Belmont’s Curse native macOS / ARM64** host adaptation, with iOS as an unverified target. The source includes Horizon service replacements, IL2CPP/SDK startup integration, NVN-to-Metal rendering, input and bounded loader diagnostics.

## Verified scope

The committed research snapshot reached a black title-loading screen with a small gold quill on Apple silicon Mac. SDK startup, original `nnMain`, IL2CPP initialization, engine threads and Metal pipelines were observed. The game has not progressed to its menu or gameplay. A failed Addressables operation and an SDK full-path mount-query rejection remain unresolved.

This project is paused; publication does not resume probes or game execution. Build/run targets remain disabled in the preserved snapshot. iPhone gameplay and a distributable app are unverified.

## Source and reproduction

The code is under [`native-target`](native-target). See its [status](native-target/README.md), Makefile, profiles and scripts. Reproduction requires matching privately supplied game inputs and generated tables. No game binaries, assets, AOT images, shader programs, signing material, saves or runtime captures are distributed.

The host derives from the MacNativeGames Ori reference and D2R Mobile graphics/rewriter components. See [the preserved license](native-target/LICENSE) and [third-party notices](native-target/THIRD_PARTY_NOTICES.md).

По-русски: исследование нативного порта Castlevania: Belmont’s Curse для Apple Silicon / macOS, с целью iOS. Достигнут загрузочный экран; полноценная игра и версия для iPhone пока не подтверждены.
