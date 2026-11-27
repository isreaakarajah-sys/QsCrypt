#!/usr/bin/env python3
"""Manifests of file trees, in the format `fsprobe manifest` prints:
directories as `/path/`, files as `/path<TAB>size<TAB>sha256`, sorted.

  manifest.py walk ROOT [TOP...]          a mounted tree (Linux or Windows)
  manifest.py probe PROBE SPEC [TOP...]   what QsCrypt's own reader sees
  manifest.py diff A B                    exit 1 when they differ

TOP limits the output to those top-level names. Windows' own folders
(System Volume Information, $RECYCLE.BIN) are always left out.
"""
import hashlib
import os
import subprocess
import sys

SKIP = {"System Volume Information", "$RECYCLE.BIN"}


def keep(line, tops):
    top = line[1:].split("/", 1)[0].split("\t", 1)[0]
    if top in SKIP:
        return False
    return not tops or top in tops


def walk(root, tops):
    if os.name == "nt" and not root.startswith("\\\\?\\"):
        root = "\\\\?\\" + os.path.abspath(root)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        rel = "" if rel == "." else "/" + rel
        for d in dirnames:
            out.append(f"{rel}/{d}/")
        for f in filenames:
            p = os.path.join(dirpath, f)
            h = hashlib.sha256()
            size = 0
            with open(p, "rb") as fh:
                while True:
                    b = fh.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
                    size += len(b)
            out.append(f"{rel}/{f}\t{size}\t{h.hexdigest()}")
    return sorted(l for l in out if keep(l, tops))


def probe(exe, spec, tops):
    text = subprocess.run([exe, "manifest", spec], check=True, stdout=subprocess.PIPE).stdout.decode("utf-8")
    return sorted(l for l in text.splitlines() if l and keep(l, tops))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "walk":
        lines = walk(args[0], set(args[1:]))
    elif cmd == "probe":
        lines = probe(args[0], args[1], set(args[2:]))
    elif cmd == "diff":
        a = open(args[0], encoding="utf-8").read().splitlines()
        b = open(args[1], encoding="utf-8").read().splitlines()
        if a == b:
            print(f"same: {len(a)} entries")
            return 0
        sa, sb = set(a), set(b)
        for l in sorted(sa - sb)[:40]:
            print(f"- {l}")
        for l in sorted(sb - sa)[:40]:
            print(f"+ {l}")
        print(f"differ: {len(sa - sb)} only in {args[0]}, {len(sb - sa)} only in {args[1]}")
        return 1
    else:
        print(__doc__)
        return 2
    for l in lines:
        print(l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
