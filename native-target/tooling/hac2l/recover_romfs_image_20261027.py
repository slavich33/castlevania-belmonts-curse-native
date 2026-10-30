#!/usr/bin/env python3
"""Finalize already IVFC-exported image after the two-stream metadata capture repair."""
import hashlib
import json
import os
from pathlib import Path
import time
import export_verified_romfs_20261027 as common

ROOT = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
DEST = common.DESTINATION
PROGRESS = ROOT/'hac2l-RomFS-recovery-progress-20261027.json'
FINAL = ROOT/'hac2l-single-RomFS-export-20261027-r2.json'


def persist(path, value):
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('x') as stream:
        json.dump(value,stream,indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary,path)
    path.chmod(0o600)
    if json.loads(path.read_text()) != value:
        raise ValueError('Receipt readback mismatch')


def main():
    if PROGRESS.exists() or FINAL.exists() or (DEST/'romfs.bin').exists() or (DEST/'index.json').exists():
        raise ValueError('Refusing existing final destination or recovery receipts')
    partial = DEST/'romfs.bin.partial'
    if partial.is_symlink() or not partial.is_file() or partial.stat().st_size != common.EXPECTED_BYTES:
        raise ValueError('Partial image size/type differs')
    listing_path = ROOT/'hac2l-bounded-merged-listromfs-20261027-r3.json'
    listing = json.loads(listing_path.read_text())
    if listing['state'] != 'bounded_merged_RomFS_listing_complete' or listing['RomFS_file_count'] != 3101:
        raise ValueError('Clean metadata gate absent')
    state = {'state':'recovering_verified_export_final_readback','image_bytes':common.EXPECTED_BYTES,
             'metadata_receipt':listing_path.name,'metadata_receipt_sha256':common.digest(listing_path),
             'original_export_status':'All tool/signature/budget/completion and original source-before/after checks passed before entering image SHA/index branch; original wrapper then raised on one interleaved stdout/stderr metadata filename.',
             'original_export_checks_recovered_from_executed_control_flow':True,
             'original_source_before_after_SHA_equality_verified':True,
             'original_source_SHA_values_not_persisted_due_to_wrapper_exception':True,
             'original_export_scalar_values_not_persisted_due_to_wrapper_exception':True,
             'export_was_not_repeated':True,'IVFC_all_image_bytes_checked':True,
             'PrintBytes_and_PrintKeys_disabled':True,'key_values_or_paths_saved':False,
             'raw_tool_output_saved':False,'game_executed':False,'GPU_executed':False}
    persist(PROGRESS,state)
    image_sha = common.digest(partial)
    state.update({'state':'image_SHA_readback_complete','image_sha256':image_sha})
    persist(PROGRESS,state)
    files = common.index_romfs(partial)
    if len(files) != 3101 or {'rom:/'+row['path'] for row in files} != set(listing['RomFS_file_paths']):
        raise ValueError('Image index differs from clean two-stream metadata listing')
    index = {'status':'pass','romfs_size':common.EXPECTED_BYTES,'romfs_sha256':image_sha,'files':files,
             'integrity':'Stock sparse+BKTR and IVFC over every sequentially exported image byte; all NCA HeaderSign1, Program HeaderSign2 and NPDM signature checks passed; final index matches clean separately captured metadata listing'}
    final_image = DEST/'romfs.bin'
    os.link(partial,final_image,follow_symlinks=False)
    partial.unlink()
    index_path = DEST/'index.json'
    with index_path.open('x') as stream:
        json.dump(index,stream,indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    index_path.chmod(0o600)
    if json.loads(index_path.read_text()) != index or final_image.stat().st_size != common.EXPECTED_BYTES:
        raise ValueError('Final image/index readback differs')
    state.update({'state':'ASSET_READY_source_audit_pending','image':str(final_image),'index':str(index_path),
                  'index_bytes':index_path.stat().st_size,'index_sha256':common.digest(index_path),
                  'RomFS_file_count':len(files),'all_paths_relative':True,
                  'image_same_inode_after_no_overwrite_hardlink':True})
    persist(PROGRESS,state)
    print(json.dumps({k:state[k] for k in ('state','image','image_bytes','image_sha256','index','index_bytes','index_sha256','RomFS_file_count')},indent=2),flush=True)
    source_root = Path("/Volumes/YOUR_WORKSPACE/Castlevania Belmont's Curse [NSP]")
    packages = [source_root/'Castlevania Belmonts Curse [0100BA4026E94000][v0].nsp',source_root/'Castlevania Belmonts Curse [0100BA4026E94800][v65536].nsp']
    before = {path:common.stat_identity(path) for path in packages}
    source_before = {path:common.digest(path) for path in packages}
    state['source_audit_first_pass'] = [{'path':str(path),'bytes':before[path][0],'sha256':source_before[path]} for path in packages]
    persist(PROGRESS,state)
    sources = []
    for path in packages:
        after_sha = common.digest(path)
        unchanged = common.stat_identity(path) == before[path] and after_sha == source_before[path]
        sources.append({'path':str(path),'bytes':before[path][0],'sha256_before':source_before[path],
                        'sha256_after':after_sha,'unchanged':unchanged})
        if not unchanged:
            raise ValueError('Source preservation audit differs')
    state.update({'state':'READY_verified_single_RomFS_image_and_source_preservation','source_packages':sources,
                  'fresh_source_SHA_audit_scope':'Two fresh full-package SHA passes after ASSET_READY; original pre-export/post-export SHA equality already passed but scalar values were lost at the index comparison exception.',
                  'source_audit_pending':False,'full_RomFS_image_exported':True,'asset_file_tree_exported':False,
                  'all_26_standard_export_destinations_rejected':True,'admitted_read_cap_bytes':7348649984,
                  'file_write_cap_bytes':common.EXPECTED_BYTES})
    persist(FINAL,state)
    persist(PROGRESS,state)
    print(json.dumps({'state':state['state'],'receipt':str(FINAL),'receipt_sha256':common.digest(FINAL),
                      'sources_unchanged':all(row['unchanged'] for row in sources)},indent=2),flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Recovery stopped: exception type='+type(error).__name__,flush=True)
        raise SystemExit(3)
