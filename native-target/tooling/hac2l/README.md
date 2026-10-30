# hac2l: Castlevania 1.1.0, bounded host tooling

Назначение: проверить собственные base/update NSP через штатные sparse → AES-CTR → BKTR → IVFC views и подготовить один RomFS image с индексом. Эти инструменты не запускают guest/game/GPU code и не доказывают работоспособность native app.

## Точные public sources

- Atmosphere: `6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8`, официальный `Atmosphere-NX/Atmosphere`.
- Atmosphere tar.gz SHA256: `7df8ed32fceba0b4bb3a6f17a596b27118b98eb1c79fff414e166b2c9f890841` (6,780,177 B).
- hac2l: `603de9228dad2a0b6d6897e9dd7ca50a20485eba`, официальный `Atmosphere-NX/hac2l`, размещён в `tools/hac2l` внутри dependency tree.
- Единый patch от этих pristine sources: `hac2l-consolidated-public-20261027.patch`, SHA256 `36b1c1bd44b1813d3db0fb79c8b18c7be1d64451158d9533fcaf6a8adefd5b7d`.
- `hac2l-consolidated-public-20261027.json` содержит pristine/patched SHA256 всех 14 изменённых public files. Patch восстановлен reverse replay и проверен forward replay; 5 library originals совпадают с pinned Atmosphere archive; остальные9 pristine hac2l files отдельно сверены с official raw sources на exact pinned commit (`hac2l-upstream-source-verification-20261027.json`).

Для свежего public tree применить единый patch из корня Atmosphere: `patch --batch -p1 -i /absolute/path/hac2l-consolidated-public-20261027.patch`. Исторические отдельные patches повторно поверх него не применять.

## Что изменено

Совместимость Apple Clang/Mach-O: signed wake enum; dependent `template`; новые NPDM API names без изменения offsets/masks; Mach-O BigNum symbol prefixes (instruction text до/после одинаков); отложенная инициализация трёх host TLS contexts вместо слишком ранних global constructors.

Выбор `--basensp` принимает Application CNMT version 65536: требуется ровно один Program с exact ApplicationId и program index; selected version/storage/ProgramId должны совпасть. Старый upstream lookup искал только version0 и передавал пустой original storage в BKTR.

`PrintBytes` и `PrintKeys` отключены. Все key-loading diagnostics заменены постоянной строкой без исходного имени/значения. Все 26 штатных output destinations и keygen остаются запрещены. RSA/IVFC/storage algorithms не изменены.

## Build и controls

Существующие host dependencies: Apple Command Line Tools (clang++, ar, llvm-nm, ranlib), headers jpeg-turbo в `/opt/homebrew/opt/jpeg-turbo/include`.

`build_hac2l_safe_20261027.py` сохраняет точную make argv и SHA public build log. Включает Mac ARM64 release, explicit pinned GIT_HASH и native Apple tools. Build logs не содержат game/key input: helper их не принимает.

Helpers по умолчанию используют свой каталог как probe root. Для копии в local source repo задайте `CASTLEVANIA_PROBE_ROOT=/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/probe`: dependency source, binary, receipts остаются на внешнем task volume. Fixed RomFS output от этой настройки не меняется.

После любой пересборки выполнить `audit_hac2l_binary_20261027.py --receipt NEW_RECEIPT.json`, затем использовать фактический binary SHA из receipt. Controls: no args/help; отказ keygen/обычного output; отказ нового export flag без verification, в raw mode, с произвольным destination и вместе с keygen. Старый receipt никогда не перезаписывать.

Проверенный текущий binary SHA256: `48be3fc19a407741abf1828db97c17ea8d0e519ff5581ba15b281b1eb8b16121`. Это identity конкретного локального build; новый build должен получить собственный receipt.

## RAM-only bounded metadata

`run_bounded_listromfs_20261027.py` принимает явный protected keyset path; значения не печатает и не сохраняет. Title/console key defaults заменены `/dev/null`; NSP tickets загружаются только в RAM. Child core dumps и file writes запрещены. Лимиты: 180 s, общий stdout+stderr capture 8 MiB, admitted input reads 128 MiB.

Stdout/stderr читаются в раздельные RAM buffers до EOF, затем соединяются с явным newline. Это исправляет interleaving marker внутри одного bundle filename в старом r2 listing. Для путей использовать только `hac2l-bounded-merged-listromfs-20261027-r3.json`: 3101 files, decoded size 3,600,101,664 B, sparse/BKTR/IVFC true, 4/4 HeaderSign1, Program HeaderSign2 и NPDM signature PASS. Старые receipts сохранены как история; r2 path set superseded.

## Единственный image export

Отдельный `--probe-romfs-image` требует NSP+basensp, verify+enablehash+listromfs, retail/nonraw/nonupdated mode. C-side gate дополнительно проверяет exact title `0100BA4026E94000`, Program type, base/header/NPDM signatures, sparse original, BKTR, mounted IVFC, no compression и exact size.

Единственная запись: `/Volumes/NativeGamesResearch/CastlevaniaBelmont-native/prepared-v110/romfs/romfs.bin.partial`, `O_CREAT|O_EXCL|O_NOFOLLOW`, 0600, один раз. Parent directory новый и 0700. Буфер4 MiB. Каждое чтение идёт из того же штатного `ctx.sections[romfs_index]` после IVFC, затем fsync и exact byte count.

- Image/file-write cap: 3,600,101,664 B.
- Все aligned IVFC data/hash levels: 3,607,216,128 B.
- Admitted input read cap: 7,348,649,984 B = 2×all aligned IVFC levels +128 MiB metadata/cache allowance. Два budget wrappers — Program NCA и NSP.
- Child timeout900 s, RAM output cap8 MiB, core0. All26 standard outputs/keygen остаются закрыты.

`export_verified_romfs_20261027.py` проверяет source size/stat/SHA before/after, signatures/completion/caps, independent image SHA и 3101 relative index paths. Он сохраняет scalar/source/image hash checkpoints до index comparison. Готовые output directories никогда не перезаписывает.

Первый export полностью прочитан через IVFC, но его final comparison упал из-за старого interleaved metadata filename; scalar/hash values писались поздно и были потеряны. `recover_romfs_image_20261027.py` повторно не экспортирует данные: использует существующий exact image, новый r3 listing, немедленно сохраняет image SHA, сравнивает index и публикует final names без overwrite. Затем выполняет два свежих source SHA passes. Recovery receipt явно отличает original control-flow verification от повторного source audit.

Final schema `index.json`: `{status:'pass',romfs_size,romfs_sha256,files:[{path,offset,size}]}`. Paths relative без leading `/`; offsets absolute внутри `romfs.bin`. Asset tree не копируется.

В Git копируются только helper source, public patch, README и safe receipts из copy manifest. NSP/NCA, keys, RomFS image, game binaries/AOT outputs, objects, logs и raw keyed stdout туда не входят. На текущем этапе установка/первый кадр/gameplay не подтверждены.
