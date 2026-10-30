#!/usr/bin/env python3
"""Strict plain-NRO frontend for the unchanged NSO native rewriter.

The synthetic NSO is a private preparation container, never a replacement NRO.
It preserves the complete original flat image (including NRO/MOD0 headers),
segment addresses, BSS size and 32-byte module ID. No relocation or guest code
executes here. Unsupported layout/TLS metadata fails rather than being guessed.
"""
import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

MAX_IMAGE = 128 << 20
# Measured SDK/RTLD RoModule storage reaches its final u64 at +0xC8.
RO_MODULE_BYTES = 0xD0
SUPPORTED_TAGS = {0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 20,
                  23, 25, 26, 27, 28, 30, 0x6FFFFEF5, 0x6FFFFFF9, 0x6FFFFFFB}
SUPPORTED_RELOCS = {257, 1025, 1026, 1027}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_nro(raw):
    """Return bounded metadata for the explicitly supported, non-TLS subset."""
    require(0x80 <= len(raw) <= MAX_IMAGE, 'NRO file size outside bound')
    u32 = lambda off: struct.unpack_from('<I', raw, off)[0]
    require(raw[0x10:0x14] == b'NRO0', 'Expected NRO0')
    require(u32(0x14) == 0 and u32(0x1C) == 0, 'Unsupported NRO version/flags')
    require(u32(0x18) == len(raw), 'NRO declared size/trailing bytes mismatch')
    require(u32(0x3C) == 0 and u32(0x64) == 0 and raw[0x68:0x70] == bytes(8),
            'Unsupported additional/embedded NRO header')
    segments = []
    end = 0
    for i, name in enumerate(('text', 'ro', 'data')):
        off, size = struct.unpack_from('<II', raw, 0x20 + 8 * i)
        require(off == end and size > 0 and off % 0x1000 == size % 0x1000 == 0,
                'NRO segments must be nonempty contiguous page-aligned ranges')
        end = off + size
        require(end <= len(raw), 'NRO segment outside file')
        segments.append({'name': name, 'offset': off, 'size': size,
                         'sha256': sha256(raw[off:end])})
    bss = u32(0x38)
    require(end == len(raw) and bss % 0x1000 == 0 and end + bss <= MAX_IMAGE,
            'Invalid NRO BSS/image bound')
    ro, data = segments[1], segments[2]

    def span(off, size, lo=0, hi=None):
        hi = len(raw) if hi is None else hi
        require(lo <= off <= hi and 0 <= size <= hi - off, 'Metadata range outside initialized image')
        return raw[off:off + size]

    mod = u32(4)
    require(span(mod, 28, ro['offset'], data['offset'])[:4] == b'MOD0', 'Invalid MOD0 location/magic')
    names = ('dynamic', 'bss_start', 'bss_end', 'eh_start', 'eh_end', 'runtime_module')
    mod0 = {name: mod + struct.unpack_from('<i', raw, mod + 4 + 4 * i)[0]
            for i, name in enumerate(names)}
    require(data['offset'] <= mod0['bss_start'] <= mod0['bss_end'] <= end + bss,
            'MOD0 BSS outside writable image')
    require(mod0['runtime_module'] % 8 == 0 and
            mod0['bss_start'] <= mod0['runtime_module'] <= mod0['bss_end'] - RO_MODULE_BYTES and
            data['offset'] <= mod0['runtime_module'] <= end + bss - RO_MODULE_BYTES,
            'Invalid/incomplete MOD0 runtime module descriptor span')
    require(u32(0x60) % 8 == 0 and data['offset'] <= u32(0x60) <= end + bss - 8,
            'Invalid DSO-handle location')
    # BSS may start inside the initialized data tail; do not rewrite this ABI.
    tags = {}
    for i in range(4096):
        tag, value = struct.unpack('<qQ', span(mod0['dynamic'] + i * 16, 16,
                                             data['offset']))
        require(tag in SUPPORTED_TAGS, 'Unsupported dynamic tag (including TLS/RELR/NEEDED)')
        require(tag not in tags, 'Duplicate dynamic tag')
        tags[tag] = value
        if tag == 0:
            require(value == 0, 'Invalid DT_NULL')
            break
    else:
        raise ValueError('Unterminated dynamic table')
    require({0, 4, 5, 6, 10, 11}.issubset(tags) and tags[11] == 24, 'Missing ELF64 metadata')
    require(tags.get(30, 0) & ~0xA == 0 and tags.get(0x6FFFFFFB, 0) & ~1 == 0,
            'Unsupported dynamic flags (including static TLS)')
    strings = span(tags[5], tags[10], ro['offset'], data['offset'])
    header_str, header_str_size, header_sym, header_sym_size = struct.unpack_from('<IIII', raw, 0x70)
    require(ro['offset'] + header_str == tags[5] and header_str_size == tags[10] and
            ro['offset'] + header_sym == tags[6] and header_sym_size % 24 == 0,
            'NRO header/dynamic symbol/string metadata disagree')
    nbucket, nchain = struct.unpack('<II', span(tags[4], 8, ro['offset'], data['offset']))
    require(nbucket > 0 and nchain > 0 and nchain == header_sym_size // 24,
            'Invalid SysV hash/symbol count')
    hash_words = span(tags[4] + 8, (nbucket + nchain) * 4, ro['offset'], data['offset'])
    require(all(v < nchain for (v,) in struct.iter_unpack('<I', hash_words)), 'Invalid SysV hash index')
    if 0x6FFFFEF5 in tags:
        start = tags[0x6FFFFEF5]
        buckets, first, bloom, shift = struct.unpack('<4I', span(start, 16, ro['offset'], data['offset']))
        require(buckets > 0 and first <= nchain and bloom > 0 and bloom & (bloom - 1) == 0 and shift < 64,
                'Invalid GNU hash header')
        span(start + 16, bloom * 8 + buckets * 4 + (nchain - first) * 4, ro['offset'], data['offset'])
        bucket_words = span(start + 16 + bloom * 8, buckets * 4, ro['offset'], data['offset'])
        require(all(v == 0 or first <= v < nchain for (v,) in struct.iter_unpack('<I', bucket_words)),
                'Invalid GNU hash bucket')
    if 3 in tags:
        require(tags[3] % 8 == 0, 'Unaligned PLTGOT')
        span(tags[3], 24, data['offset'])
    if 14 in tags:
        require(tags[14] < len(strings) and strings.find(b'\0', tags[14]) >= 0, 'Invalid SONAME string')
    symbols = span(tags[6], nchain * 24, ro['offset'], data['offset'])
    imports = []
    for i in range(nchain):
        name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', symbols, i * 24)
        require(name < len(strings), 'Invalid dynamic string offset')
        stop = strings.find(b'\0', name)
        require(stop >= 0, 'Unterminated dynamic string')
        text = strings[name:stop].decode('utf-8', errors='strict')
        require(info & 15 != 6, 'ELF TLS symbols are unsupported')
        require(info & 15 in {0, 1, 2, 3, 4} and info >> 4 in {0, 1, 2} and other <= 3,
                'Unsupported symbol kind/binding/visibility (including IFUNC)')
        require(section < 0xFF00 or section == 0xFFF1, 'Unsupported reserved symbol section')
        if section == 0 and text:
            require(not any(t in text.lower() for t in ('tls_get_addr', 'tlv_get_addr', 'emutls', 'tlsdesc')),
                    'TLS helper import is unsupported')
            imports.append(text)
        if section not in (0, 0xFFF1):
            require(value <= end + bss and size <= end + bss - value, 'Defined symbol outside image')
    reloc_counts = {}
    ranges = []
    for address_tag, size_tag in ((7, 8), (23, 2)):
        require((address_tag in tags) == (size_tag in tags), 'Incomplete relocation metadata')
        if address_tag not in tags:
            continue
        require(tags.get(9, 24) == 24 and tags.get(20, 7) == 7 and tags[size_tag] % 24 == 0,
                'Only ELF64 RELA relocation tables are supported')
        start, length = tags[address_tag], tags[size_tag]
        require(all(start + length <= a or start >= a + n for a, n in ranges), 'Overlapping RELA tables')
        ranges.append((start, length))
        for target, info, _ in struct.iter_unpack('<QQq', span(start, length, ro['offset'], data['offset'])):
            kind, symbol = info & 0xFFFFFFFF, info >> 32
            require(kind in SUPPORTED_RELOCS, 'Unsupported relocation kind (including TLS)')
            require(symbol < nchain and data['offset'] <= target <= end + bss - 8,
                    'Invalid relocation symbol/target')
            require(kind != 1027 or symbol == 0, 'RELATIVE relocation must not name a symbol')
            reloc_counts[str(kind)] = reloc_counts.get(str(kind), 0) + 1
    require(tags.get(0x6FFFFFF9, 0) <= tags.get(8, 0) // 24, 'Invalid RELACOUNT')
    for fn in (12, 13):
        require(fn not in tags or 0 <= tags[fn] < ro['offset'] and tags[fn] % 4 == 0,
                'DT_INIT/FINI outside text')
    for ptr, size in ((25, 27), (26, 28)):
        require((ptr in tags) == (size in tags), 'Incomplete constructor array metadata')
        if ptr in tags:
            require(tags[size] % 8 == 0, 'Invalid constructor array size')
            span(tags[ptr], tags[size], data['offset'])
    # These encodings match the unchanged engine's bounded EH decoder.
    eh = span(mod0['eh_start'], mod0['eh_end'] - mod0['eh_start'], ro['offset'], data['offset'])
    require(len(eh) >= 12 and eh[:4] == bytes((1, 0x1B, 3, 0x3B)), 'Unsupported EH frame header encoding')
    count = struct.unpack_from('<I', eh, 8)[0]
    require(count <= (len(eh) - 12) // 8, 'EH table outside MOD0 range')
    return {'sha256': sha256(raw), 'size': len(raw), 'module_id': raw[0x40:0x60].hex(),
            'segments': segments, 'bss_size': bss, 'mod0_offset': mod, 'mod0': mod0,
            'symbol_count': nchain, 'imports': imports, 'relocation_counts': reloc_counts,
            'eh_fde_count': count, 'tls': 'no supported ELF TLS metadata present',
            'supported_layout': 'plain NRO0 v0 flags0; no embedded/trailing content'}


def make_nso(raw):
    metadata = parse_nro(raw)
    header = bytearray(0x100)
    header[:4] = b'NSO0'
    struct.pack_into('<I', header, 0xC, 0x38)  # uncompressed, all three hashes present
    for i, seg in enumerate(metadata['segments']):
        struct.pack_into('<III', header, 0x10 + i * 0x10, 0x100 + seg['offset'], seg['offset'], seg['size'])
        struct.pack_into('<I', header, 0x60 + i * 4, seg['size'])
        header[0xA0 + i * 32:0xC0 + i * 32] = bytes.fromhex(seg['sha256'])
    struct.pack_into('<I', header, 0x3C, metadata['bss_size'])
    header[0x40:0x60] = raw[0x40:0x60]
    # NSO ro-relative dynstr/dynsym metadata, useful to ordinary NSO inspectors.
    header[0x88:0x98] = raw[0x70:0x80]
    return bytes(header) + raw, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    with args.input.open('rb') as source:
        raw = source.read(MAX_IMAGE + 1)
    require(sha256(raw) == args.expected_sha256, 'Original NRO SHA256 mismatch')
    container, metadata = make_nso(raw)
    output = args.output.absolute()
    parent = output.parent.resolve(strict=True)
    require(all(not (p / '.git').exists() for p in (parent, *parent.parents)), 'Private output must be outside Git')
    output = parent / output.name
    with output.open('xb') as out:
        os.chmod(output, 0o600)
        out.write(container)
    require(output.read_bytes() == container, 'Container readback mismatch')
    print(json.dumps({'original_sha256': metadata['sha256'], 'container_sha256': sha256(container),
                      'bytes': len(container), 'runtime_verified': False}))


if __name__ == '__main__':
    main()
