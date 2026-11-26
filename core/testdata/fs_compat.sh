#!/bin/bash
# File-system compatibility against Linux's own implementations:
#  1. images made and filled by mkfs + the kernel are read by QsCrypt;
#  2. QsCrypt writes into them, fsck must accept them and Linux must read
#     back exactly what was written;
#  3. QsCrypt formats new FAT/exFAT images, fsck and Linux must accept them.
set -euo pipefail
PROBE=${PROBE:-core/target/release/examples/fsprobe}
WORK=$(mktemp -d)
MNT=$WORK/mnt
mkdir -p "$MNT"
fail=0

manifest_linux() {
  (cd "$1" && find . -mindepth 1 | LC_ALL=C sort | while IFS= read -r p; do
    if [ -d "$p" ]; then printf '%s/\n' "${p#.}"; else printf '%s\t%s\t%s\n' "${p#.}" "$(stat -c %s "$p")" "$(sha256sum "$p" | cut -d' ' -f1)"; fi
  done) | LC_ALL=C sort
}

mount_img() { # image type
  case $2 in
    ntfs) sudo mount -t ntfs3 -o loop,uid=$(id -u),gid=$(id -g) "$1" "$MNT" 2>/dev/null || sudo ntfs-3g -o uid=$(id -u),gid=$(id -g) "$1" "$MNT" ;;
    fat) sudo mount -t vfat -o loop,uid=$(id -u),gid=$(id -g),utf8 "$1" "$MNT" ;;
    exfat) sudo mount -t exfat -o loop,uid=$(id -u),gid=$(id -g) "$1" "$MNT" ;;
  esac
}

populate() {
  local m=$1 t=$2
  mkdir -p "$m/dir1/sub" "$m/مجلد عربي/داخلي"
  echo "hello" > "$m/hello.txt"
  : > "$m/empty.bin"
  head -c 3000000 /dev/urandom > "$m/dir1/random.bin"
  head -c 777 /dev/urandom > "$m/مجلد عربي/ملف عربي طويل الاسم جداً.txt"
  head -c 100 /dev/urandom > "$m/مجلد عربي/داخلي/صغير.bin"
  for i in $(seq 1 300); do echo "file $i" > "$m/dir1/sub/f$i.txt"; done
  for i in $(seq 1 15); do head -c 65000 /dev/urandom >> "$m/dir1/frag_a.bin"; head -c 33000 /dev/urandom >> "$m/dir1/frag_b.bin"; sync; done
  if [ "$t" = ntfs ]; then truncate -s 9M "$m/sparse.bin"; printf 'tail' >> "$m/sparse.bin"; fi
  mkdir -p "$m/Mixed Case Dir"; echo x > "$m/Mixed Case Dir/README.Md"
  sync
}

check_read() { # type
  local t=$1 img=$WORK/$1.img
  truncate -s 96M "$img"
  case $t in
    fat) mkfs.fat -F 32 -n TESTVOL "$img" >/dev/null ;;
    exfat) mkfs.exfat -L TESTVOL "$img" >/dev/null ;;
    ntfs) mkntfs -Q -F -L TESTVOL "$img" >/dev/null 2>&1 ;;
  esac
  mount_img "$img" "$t"; populate "$MNT" "$t"; manifest_linux "$MNT" > "$WORK/$t.linux"; sudo umount "$MNT"
  "$PROBE" manifest "$img" > "$WORK/$t.qs"
  if diff -u "$WORK/$t.linux" "$WORK/$t.qs" > "$WORK/$t.diff"; then echo "PASS read $t ($(wc -l < "$WORK/$t.qs") entries)"; else echo "FAIL read $t"; head -40 "$WORK/$t.diff"; fail=1; fi
}

check_write() { # type
  local t=$1 img=$WORK/$1.img src=$WORK/src
  rm -rf "$src"; mkdir -p "$src/a/b" "$src/ملفات"
  head -c 1234567 /dev/urandom > "$src/a/b/big.bin"
  for i in $(seq 1 200); do echo "entry $i" > "$src/a/b/n$i.txt"; done
  echo "عربي" > "$src/ملفات/نص.txt"; : > "$src/empty"
  "$PROBE" write "$img" "$src" "/from-qscrypt"
  "$PROBE" churn "$img" "/churn"
  case $t in fat) fsck.fat -n "$img" > "$WORK/fsck" 2>&1 ;; exfat) fsck.exfat -n "$img" > "$WORK/fsck" 2>&1 ;; *) : > "$WORK/fsck" ;; esac || { echo "FAIL fsck after write $t"; cat "$WORK/fsck"; fail=1; }
  mount_img "$img" "$t"
  manifest_linux "$MNT/from-qscrypt" > "$WORK/w.linux"; manifest_linux "$src" > "$WORK/w.src"
  [ "$(ls "$MNT/churn" | wc -l)" = 80 ] || { echo "FAIL churn count $(ls "$MNT/churn" | wc -l)"; fail=1; }
  sudo umount "$MNT"
  if diff -u "$WORK/w.src" "$WORK/w.linux"; then echo "PASS write $t"; else echo "FAIL write $t"; fail=1; fi
}

check_format() { # type size
  local t=$1 img=$WORK/fmt-$1-$2.img
  "$PROBE" format "$img" "$2" "$t" "QSFORMAT"
  case $t in fat) fsck.fat -n "$img" > "$WORK/fsck" 2>&1 ;; exfat) fsck.exfat -n "$img" > "$WORK/fsck" 2>&1 ;; esac || { echo "FAIL fsck format $t $2"; cat "$WORK/fsck"; fail=1; return; }
  mount_img "$img" "$t"; populate "$MNT" "$t"; manifest_linux "$MNT" > "$WORK/f.linux"; sudo umount "$MNT"
  "$PROBE" manifest "$img" > "$WORK/f.qs" 2> "$WORK/f.info"
  if diff -u "$WORK/f.linux" "$WORK/f.qs" > /dev/null; then echo "PASS format $t $2 ($(cat "$WORK/f.info"))"; else echo "FAIL format $t $2"; diff -u "$WORK/f.linux" "$WORK/f.qs" | head -20; fail=1; fi
  rm -f "$img"
}

for t in fat exfat ntfs; do check_read $t; done
for t in fat exfat; do check_write $t; done
for s in 20000000 100000000 400000000; do check_format exfat $s; done
for s in 20000000 100000000 600000000; do check_format fat $s; done
exit $fail
