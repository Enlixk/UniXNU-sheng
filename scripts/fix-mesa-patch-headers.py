#!/usr/bin/env python3
"""Add missing Git new-file metadata without changing patch hunks."""
import argparse
import json
from pathlib import Path
import re


def fix(root):
    pins = json.loads((root / 'scripts/data/adreno-compiler-inputs.json').read_text())
    count = 0
    for name in pins['patches']:
        path = root / name
        original = path.read_text()
        corrected, changes = re.subn(
            r'^(diff --git a/\S+ b/\S+\n)(--- /dev/null\n)',
            r'\1new file mode 100644\n\2', original, flags=re.M)
        if changes:
            path.write_text(corrected, newline='\n')
            print(f'{name}: added {changes} new-file mode headers', flush=True)
            count += changes
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    fix(args.root)
