#!/usr/bin/env python3
"""Replay only public source patches, then consolidate them; no game/key inputs."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
VENDOR = ROOT/'tooling/Atmosphere-6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8'
ORDER = ['hac2l-safe-bounded.patch','hac2l-macos-compile-compat.patch',
         'hac2l-budget-accuracy-20261027.patch','hac2l-verification-booleans-20261027.patch',
         'hac2l-dependent-template-20261027.patch','hac2l-npdm-api-compat-20261027.patch',
         'hac2l-macho-bignum-symbols-20261027.patch','hac2l-macos-context-TLS-init-20261027.patch',
         'hac2l-macos-buffer-TLS-init-20261027.patch','hac2l-selected-base-version-20261027.patch',
         'hac2l-selected-base-identity-20261027.patch','hac2l-single-RomFS-allowlist-20261027.patch']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    work = ROOT/'tooling/public-patch-replay-20261027'
    if work.exists():
        raise ValueError('Refusing existing public replay directory')
    work.mkdir()
    pristine = work/'pristine'
    pristine.mkdir()
    normalized, touched = [], set()
    for index, name in enumerate(ORDER):
        patch = (ROOT/name).read_text()
        patch = re.sub(r'^(---|\+\+\+) ([ab])/source/', r'\1 \2/tools/hac2l/source/', patch, flags=re.M)
        for filename in re.findall(r'^\+\+\+ b/(.+)$',patch,re.M):
            relative = Path(filename)
            if relative.is_absolute() or '..' in relative.parts or relative.parts[0] not in ('libraries','tools'):
                raise ValueError('Unexpected public patch path')
            touched.add(filename)
        destination = work/(str(index)+'.patch')
        destination.write_text(patch)
        normalized.append(destination)
    for name in touched:
        destination = pristine/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(VENDOR/name,destination)
    for patch in reversed(normalized):
        result = subprocess.run(['patch','--batch','--no-backup-if-mismatch','-p1','-R','-i',str(patch)],cwd=pristine,capture_output=True)
        if result.returncode:
            raise ValueError('Public source reverse replay failed')
    public = ROOT/'hac2l-consolidated-public-20261027.patch'
    if public.exists():
        raise ValueError('Refusing existing consolidated patch')
    differences, rows = [], []
    with tarfile.open(ROOT/'tooling/Atmosphere-source.tar.gz','r:gz') as archive:
        members = {member.name.split('/',1)[1]:member for member in archive.getmembers() if '/' in member.name and member.isfile()}
        for name in sorted(touched):
            before, after = (pristine/name).read_bytes(), (VENDOR/name).read_bytes()
            if name.startswith('libraries/'):
                original = archive.extractfile(members[name]).read()
                if before != original:
                    raise ValueError('Atmosphere original differs from pinned archive')
            differences.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+name,tofile='b/'+name))
            rows.append({'path':name,'pristine_sha256':sha(before),'patched_sha256':sha(after),
                         'pinned_Atmosphere_archive_compared':name.startswith('libraries/')})
    public.write_text(''.join(differences))
    result = subprocess.run(['patch','--batch','--no-backup-if-mismatch','-p1','-i',str(public)],cwd=pristine,capture_output=True)
    if result.returncode or any((pristine/row['path']).read_bytes() != (VENDOR/row['path']).read_bytes() for row in rows):
        raise ValueError('Consolidated public patch forward replay differs')
    receipt = {'state':'consolidated_public_patch_reverse_and_forward_replay_passed',
               'Atmosphere_commit':'6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8',
               'Atmosphere_archive_sha256':'7df8ed32fceba0b4bb3a6f17a596b27118b98eb1c79fff414e166b2c9f890841',
               'hac2l_commit':'603de9228dad2a0b6d6897e9dd7ca50a20485eba',
               'ordered_patch_inputs':ORDER,'patch_sha256':sha(public.read_bytes()),'files':rows,
               'game_or_key_inputs_opened':False,'raw_keyed_tool_output_saved':False}
    (ROOT/'hac2l-consolidated-public-20261027.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'state':receipt['state'],'patch':str(public),'patch_sha256':receipt['patch_sha256'],'files':len(rows)},indent=2))


if __name__ == '__main__':
    main()
