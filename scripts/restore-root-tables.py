#!/usr/bin/env python3
"""Reconstruct block tables from exact root windows and pinned signed headers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def restore(image, report, policies, output):
    output.mkdir(parents=True, exist_ok=True)
    for window in report['windows']:
        name, size = window['name'], window['size']
        header = (policies / name / 'manifest.header.bin').read_bytes()
        if len(header) != 544 or header[:8] != b'VROOT01\0':
            raise ValueError(f'{name}: invalid signed header')
        block_bytes = struct.unpack_from('<I', header, 16)[0]
        expected_size, expected_count = struct.unpack_from('<QQ', header, 24)
        if block_bytes != 4096 or size != expected_size:
            raise ValueError(f'{name}: image geometry differs from signed policy')
        digest, table = hashlib.sha256(), bytearray()
        with image.open('rb') as source:
            source.seek(window['offset'])
            remaining = size
            while remaining:
                data = source.read(min(8 << 20, remaining))
                if not data:
                    raise ValueError(f'{name}: truncated image')
                digest.update(data)
                for at in range(0, len(data), block_bytes):
                    table.extend(hashlib.sha256(data[at:at + block_bytes]).digest())
                remaining -= len(data)
        if (digest.digest() != header[56:88] or
                digest.hexdigest() != window['sha256'] or
                len(table) != expected_count * 32 or
                hashlib.sha256(table).digest() != header[88:120]):
            raise ValueError(f'{name}: root bytes or block table differ from signed policy')
        path = output / f'{name}.vroot'
        path.write_bytes(header + table)
        print(f'{name}: restored and verified {expected_count} block hashes', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('policies', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    restore(args.image, json.loads(args.report.read_text()), args.policies, args.output)
