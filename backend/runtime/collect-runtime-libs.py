"""Collect dynamic dependencies of trusted release binaries during image build.

Never run ldd on untrusted inputs. This helper and Python stay in build stages.
"""
import argparse
from pathlib import Path
import shutil
import subprocess


def parse_ldd(text):
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if 'not found' in line:
            raise ValueError('unresolved native dependency: ' + line)
        if '=>' in line:
            value = line.split('=>', 1)[1].strip().split()[0]
        elif line.startswith('/'):
            value = line.split()[0]
        elif line.startswith('linux-vdso.'):
            continue
        else:
            raise ValueError('unexpected ldd output: ' + line)
        path = Path(value)
        if not path.is_absolute():
            raise ValueError('dependency path is not absolute')
        paths.append(path)
    if not paths:
        raise ValueError('empty native dependency closure')
    return paths


def copy_library(source, output):
    if not source.is_absolute():
        raise ValueError('source must be absolute')
    destination = output / source.relative_to('/')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        target = source.readlink()
        if destination.is_symlink():
            if destination.readlink() != target:
                raise ValueError('conflicting native symlink')
        elif destination.exists():
            raise ValueError('native symlink conflicts with file')
        else:
            destination.symlink_to(target)
        copy_library(target if target.is_absolute() else source.parent / target, output)
    else:
        if destination.is_symlink() or (destination.exists() and destination.read_bytes() != source.read_bytes()):
            raise ValueError('conflicting native dependency')
        shutil.copy2(source, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('binaries', nargs='+', type=Path)
    args = parser.parse_args()
    for binary in args.binaries:
        result = subprocess.run(['ldd', str(binary)], check=True, capture_output=True,
                                text=True, timeout=30)
        for library in parse_ldd(result.stdout):
            copy_library(library, args.output)


if __name__ == '__main__':
    main()
