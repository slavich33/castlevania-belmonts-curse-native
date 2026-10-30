#!/usr/bin/env python3
"""Bind the Castlevania loader to verified v1.1.0 images; derived from pinned Ori prepare_runtime.py. Generated tables stay outside Git."""
import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'third_party/d2r'))
from relr import decode_relr
parser = argparse.ArgumentParser(description="Generate Castlevania tables from exact measured NSOs and completed AOT outputs")
parser.add_argument('--exefs', required=True, type=Path)
parser.add_argument('--rewritten', required=True, type=Path)
parser.add_argument('--profile', type=Path, default=ROOT / 'profiles/v110.json')
args = parser.parse_args()
GAME = ROOT
OUT = GAME / 'build'
OUT.mkdir(parents=True, exist_ok=True)
EXEFS = args.exefs.resolve()
REWRITTEN = args.rewritten.resolve()
PROFILE = json.loads(args.profile.read_text())
assert PROFILE['title_id'] == '0100BA4026E94000' and PROFILE['display_version'] == '1.1.0'
assert PROFILE['runtime_load_order'] == ['main', 'subsdk0', 'sdk']
EXPECTED = {name: row['sha256'] for name, row in PROFILE['source_modules'].items()}
for name, digest in EXPECTED.items():
    assert hashlib.sha256((EXEFS / name).read_bytes()).hexdigest() == digest, f'Unsupported Castlevania NSO: {name}'
REWRITER_SHA = hashlib.sha256((ROOT / 'third_party/d2r/patch_nso.py').read_bytes()).hexdigest()
assert (REWRITTEN / 'build_src.sha256').read_text().split()[0] == REWRITER_SHA, 'Rewriter differs from the completed AOT'
AOT = json.loads((REWRITTEN / 'rewrite-receipt.json').read_text())
assert AOT['state'] == 'static_AOT_rewrite_complete' and AOT['ruleset'] == 'native' and AOT['private_gates'] is False
assert AOT['rewriter_sha256'] == REWRITER_SHA and {row['module'] for row in AOT['modules']} == set(PROFILE['runtime_load_order'])
for module in AOT['modules']:
    assert module['exit_code'] == 0
    for artifact in module['outputs']:
        path = REWRITTEN / artifact['name']
        assert path.stat().st_size == artifact['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == artifact['sha256'], f'AOT output changed: {artifact["name"]}'
modules = []


def scan_ctor_flag(image, tags, layout, name):
    """Another game's compiler (games/by3/scripts/prepare_runtime.py): the first adrp + ldr w of the same register in
    DT_INIT's first 16 instructions is the constructor-state word the loader checks."""
    init = tags[12]
    words = [struct.unpack_from('<I', image, init + 4 * i)[0] for i in range(16)]
    for i, a in enumerate(words):
        if a & 0x9f000000 != 0x90000000: continue
        reg = a & 31
        for j in range(i + 1, len(words)):
            w = words[j]
            if w & 0xffc00000 == 0xb9400000 and (w >> 5) & 31 == reg:
                imm = ((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2)
                imm = (imm ^ (1 << 20)) - (1 << 20)
                flag = ((init + 4 * i) & ~4095) + (imm << 12) + ((w >> 10) & 0xfff) * 4
                assert layout['DATA_OFF'] <= flag < layout['KEY_PAGE_OFF'], f'{name}: ctor flag outside data'
                return flag
    raise ValueError(f'{name}: no constructor-state load in DT_INIT')


# Horizon load order (rtld is the host's): main, subsdk0..9, sdk; Ori has main, subsdk0, sdk
for name in PROFILE['runtime_load_order']:
    image = (REWRITTEN / f'{name}.patched.bin').read_bytes()
    digest, file_size = hashlib.sha256(image).hexdigest(), len(image)
    layout = {}
    for line in (REWRITTEN / f'{name}.fixups.tsv').read_text().splitlines():
        _, key, value = line.split()
        layout[key] = int(value, 0)
    pre = max(0, -layout['PATCH_OFF'])   # a module whose patch area is before its image (patch_nso.py PRE)
    image = image[pre:]
    mod0 = struct.unpack_from('<I', image, 4)[0]
    assert image[mod0:mod0 + 4] == b'MOD0'
    dyn = mod0 + struct.unpack_from('<i', image, mod0 + 4)[0]
    tags = {}
    for offset in range(dyn, dyn + 4096 * 16, 16):
        tag, value = struct.unpack_from('<qQ', image, offset)
        if tag == 0: break
        tags[tag] = value
    else: raise ValueError('Unterminated dynamic table')
    if 4 in tags:
        nsym = struct.unpack_from('<I', image, tags[4] + 4)[0]
    else:
        # Newer SDK modules carry GNU hash only. NSO's verified dynsym extent
        # supplies the exact count, as in prepare_modules.py's inventory gate.
        raw_header = (EXEFS / name).read_bytes()[:256]
        _, _, symbol_offset, symbol_size = struct.unpack_from('<IIII', raw_header, 0x90)
        assert layout['RO_OFF'] + symbol_offset == tags[6] and symbol_size % 24 == 0
        assert 0 < symbol_size <= layout['DATA_OFF'] - tags[6]
        nsym = symbol_size // 24
    assert tags[11] == 24 and tags[9] == 24 and tags[20] == 7
    symbols = []
    for i in range(nsym):
        no, info, other, section, value, size = struct.unpack_from('<IBBHQQ', image, tags[6] + 24 * i)
        end = image.index(0, tags[5] + no, tags[5] + tags[10])
        symbols.append(dict(name=image[tags[5] + no:end].decode(), value=value, size=size,
                            defined=bool(section), binding=info >> 4, type=info & 15))
    relocs = [dict(where=where, kind=1027, symbol=0, addend=addend)
              for where, addend in decode_relr(image, tags, layout['DATA_OFF'], layout['KEY_PAGE_OFF'])]
    relocated = {reloc['where'] for reloc in relocs}
    for address, size in [(tags[7], tags[8]), (tags[23], tags[2])]:
        assert size % 24 == 0
        for offset in range(address, address + size, 24):
            where, info, addend = struct.unpack_from('<QQq', image, offset)
            kind, si = info & 0xffffffff, info >> 32
            assert kind in [257, 1025, 1026, 1027] and si < nsym
            assert layout['DATA_OFF'] <= where <= layout['KEY_PAGE_OFF'] - 8
            assert kind != 1027 or 0 <= addend < layout['KEY_PAGE_OFF']
            assert where not in relocated, 'Duplicate RELR/RELA relocation'
            relocated.add(where)
            relocs.append(dict(where=where, kind=kind, symbol=si, addend=addend))
    gates = []
    for line in (REWRITTEN / f'{name}.gates.tsv').read_text().splitlines():
        ret, kind, arg, original = line.split()
        assert kind in ['cntpct', 'cntvct', 'svc']
        gates.append(dict(ret=int(ret, 0), timer=kind != 'svc', arg=int(arg), original=int(original, 0)))
    ctor_flag = scan_ctor_flag(image, tags, layout, name)
    modules.append(dict(name=name, sha256=digest, size=file_size, pre=pre, ctor_flag=ctor_flag, layout=layout, tags=tags,
                        symbols=symbols, relocs=relocs, gates=gates))

# Find main's ORIGINAL PLT stub addressing the relocated GetSystemTick slot.
main = modules[0]
target = '_ZN2nn2os13GetSystemTickEv'
slot = next(r['where'] for r in main['relocs'] if main['symbols'][r['symbol']]['name'] == target and r['kind'] == 1026)
image = (REWRITTEN / 'main.patched.bin').read_bytes()[main['pre']:]
plt = []
for address in range(0, main['layout']['TEXT_END'] - 12, 4):
    a, b, c, d = struct.unpack_from('<IIII', image, address)
    if a & 0x9f00001f != 0x90000010 or b & 0xffc003ff != 0xf9400211 or c & 0xffc003ff != 0x91000210 or d != 0xd61f0220: continue
    imm = ((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2)
    imm = (imm ^ (1 << 20)) - (1 << 20)
    referenced = (address & ~4095) + (imm << 12) + ((b >> 10) & 0xfff) * 8
    if referenced == slot and ((c >> 10) & 0xfff) == (slot & 0xfff): plt.append(address)
assert len(plt) == 1, f'PLT matches {plt}'
main['probe_plt'] = plt[0]
main['probe_slot'] = slot

lines = ['/* Generated locally from validated player images; do not commit. */']
for n, m in enumerate(modules):
    lines.append(f'static const Reloc reloc_{n}[] = {{')
    lines.extend(f'{{{r["where"]}ULL,{r["kind"]},{r["symbol"]},{r["addend"]}LL}},' for r in m['relocs'])
    lines.append('};')
    lines.append(f'static const Symbol symbol_{n}[] = {{')
    lines.extend('{' + f'{json.dumps(s["name"])},{s["value"]}ULL,{s["size"]}ULL,{int(s["defined"])},{s["binding"]},{s["type"]}' + '},' for s in m['symbols'])
    lines.append('};')
    lines.append(f'static const Gate gate_{n}[] = {{')
    lines.extend(f'{{{g["ret"] % (1 << 64)}ULL,{g["original"]}ULL,{g["timer"]!s},{g["arg"]}}},'.replace('True','1').replace('False','0') for g in m['gates'])
    if not m['gates']: lines.append('{0,0,0,0},')
    lines.append('};')
lines.append('static Module modules[] = {')
for n, m in enumerate(modules):
    l = m['layout']
    lines.append('{' + f'.name={json.dumps(m["name"])},.digest={json.dumps(m["sha256"])},.file_size={m["size"]}ULL,.text_end={l["TEXT_END"]}ULL,.ro_off={l["RO_OFF"]}ULL,.data_off={l["DATA_OFF"]}ULL,.patch_off={l["PATCH_OFF"] % (1 << 64)}ULL,.pre={m["pre"]}ULL,.key_off={l["KEY_PAGE_OFF"]}ULL,.symbols=symbol_{n},.nsym={len(m["symbols"])},.relocs=reloc_{n},.nreloc={len(m["relocs"])},.gates=gate_{n},.ngate={len(m["gates"])},.init={m["tags"].get(12,0)}ULL,.ctor_flag={m["ctor_flag"]}ULL,.init_array={m["tags"].get(25,0)}ULL,.init_size={m["tags"].get(27,0)}ULL' + '},')
lines.append('};')
lines.append(f'#define PROBE_PLT {main["probe_plt"]}ULL\n#define PROBE_SLOT {slot}ULL')
(OUT / 'runtime_tables.h').write_text('\n'.join(lines) + '\n')
# Details are evidence, not additional source code.
(GAME / 'analysis').mkdir(exist_ok=True)
(GAME / 'analysis/runtime-layout.json').write_text(json.dumps(modules, indent=2) + '\n')
print(json.dumps(dict(modules=len(modules), relocations=sum(len(m['relocs']) for m in modules), original_main_plt=hex(plt[0]), original_main_slot=hex(slot))))

receipt = {'state': 'measured_runtime_tables_generated', 'title_id': PROFILE['title_id'], 'display_version': PROFILE['display_version'], 'source_nso_hashes': EXPECTED, 'rewriter_sha256': REWRITER_SHA, 'runtime_tables_sha256': hashlib.sha256((OUT/'runtime_tables.h').read_bytes()).hexdigest(), 'runtime_layout_sha256': hashlib.sha256((GAME/'analysis/runtime-layout.json').read_bytes()).hexdigest(), 'load_order': [m['name'] for m in modules], 'modules': [{'name': m['name'], 'patched_sha256': m['sha256'], 'patched_bytes': m['size'], 'relocations': len(m['relocs']), 'symbols': len(m['symbols']), 'gates': len(m['gates']), 'init_offset': m['tags'].get(12,0), 'ctor_flag_offset': m['ctor_flag'], 'init_array_offset': m['tags'].get(25,0), 'init_array_bytes': m['tags'].get(27,0)} for m in modules], 'GetSystemTick_plt': main['probe_plt'], 'GetSystemTick_slot': main['probe_slot'], 'game_code_executed': False, 'constructors_executed': False, 'keys_read': False}
(OUT/'runtime-tables-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
