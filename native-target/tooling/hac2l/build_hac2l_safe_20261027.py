#!/usr/bin/env python3
"""Resume the pinned public hac2l host build. Takes no game/key inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(os.environ.get('CASTLEVANIA_PROBE_ROOT', str(Path(__file__).resolve().parent))).resolve()
SOURCE = ROOT/'tooling/Atmosphere-6b0c077b4c608a3a2ee712b8dc35fee87ceb62e8/tools/hac2l'
COMMAND = ['make', '-f', 'tool.mk', '-j4',
           'ATMOSPHERE_MAKEFILE_TARGET=macos_arm64_release',
           'ATMOSPHERE_BUILD_NAME=release', 'ATMOSPHERE_BOARD=generic_macos',
           'ATMOSPHERE_CPU=generic_arm64', 'ATMOSPHERE_GIT_BRANCH=source-checkpoint',
           'ATMOSPHERE_GIT_REVISION=6b0c077b4c608a3a',
           'ATMOSPHERE_GIT_HASH=6b0c077b4c608a3a',
           'AR=/Library/Developer/CommandLineTools/usr/bin/ar',
           'NM=/Library/Developer/CommandLineTools/usr/bin/llvm-nm',
           'RANLIB=/Library/Developer/CommandLineTools/usr/bin/ranlib',
           'LDFLAGS=$(CXXFLAGS) $(CXXWRAPS) $(CXXREQUIRED) -Wl,-map,$(notdir $@.map)',
           'SETTINGS=$(ATMOSPHERE_SETTINGS) -O2 -Wextra -Wno-error -Wno-mismatched-tags -Wno-unused-value -I/opt/homebrew/opt/jpeg-turbo/include']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--log', type=Path, required=True)
    ap.add_argument('--receipt', type=Path, required=True)
    a = ap.parse_args()
    if a.log.exists() or a.receipt.exists():
        raise ValueError('Refusing existing log/receipt')
    started = time.monotonic()
    with a.log.open('w') as log:
        code = subprocess.run(COMMAND, cwd=SOURCE, stdout=log,
                              stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL='C')).returncode
    result = {'state': 'public_tool_build_complete' if code == 0 else 'public_tool_build_incomplete',
              'exit_code': code, 'seconds': round(time.monotonic()-started, 3),
              'source': str(SOURCE), 'command': COMMAND,
              'log': str(a.log), 'log_sha256': hashlib.sha256(a.log.read_bytes()).hexdigest(),
              'game_or_key_data_opened': False}
    a.receipt.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
