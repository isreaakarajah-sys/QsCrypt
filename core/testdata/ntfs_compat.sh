#!/bin/bash
# NTFS writing against Linux's two NTFS drivers (ntfs-3g and the kernel's
# ntfs3), on disks partitioned and formatted by mkntfs with several cluster
# sizes:
#  1. QsCrypt writes thousands of files, folders, renames, moves, deletions;
#  2. ntfs-3g and ntfs3 must see exactly what QsCrypt's model expects, and
#     ntfsfix must accept the volume;
#  3. Linux then writes into the same volume, and QsCrypt must still check
#     clean, read it all, and write again.
# The written disks are left as fixed VHDs in $OUT for the Windows job
# (chkdsk), with the manifest Windows must find.
set -euo pipefail
PROBE=${PROBE:-core/target/release/examples/fsprobe}
OUT=${OUT:-ntfs-out}
M="python3 core/testdata/manifest.py"
WORK=$(mktemp -d)
MNT=$WORK/mnt
mkdir -p "$MNT" "$OUT"
fail=0
TOPS="stress from-qscrypt churn linux"

pass() { echo "PASS $*"; }
bad() { echo "FAIL $*"; fail=1; }

attach() { sudo losetup -f --show -P "$1"; }

mount_drv() { # driver device ro|rw
  case $1 in
    ntfs-3g) sudo ntfs-3g -o "$3,uid=$(id -u),gid=$(id -g)" "$2" "$MNT" ;;
    ntfs3) sudo mount -t ntfs3 -o "$3,uid=$(id -u),gid=$(id -g)" "$2" "$MNT" ;;
  esac
}

round() { # name size_mib mkntfs-options...
  local name=$1 size=$2
  shift 2
  local img=$WORK/$name.img
  truncate -s "${size}M" "$img"
  printf 'label: dos\nstart=2048, type=7\n' | sfdisk -q "$img"
  local lo
  lo=$(attach "$img")
  sudo mkntfs -Q -F -L QSLINUX -p 2048 "$@" "${lo}p1" > /dev/null
  mount_drv ntfs-3g "${lo}p1" rw
  mkdir -p "$MNT/linux/sub"
  echo "from linux" > "$MNT/linux/hello.txt"
  head -c 300000 /dev/urandom > "$MNT/linux/sub/random.bin"
  for i in $(seq 1 150); do echo "linux $i" > "$MNT/linux/sub/l$i.txt"; done
  sudo umount "$MNT"
  sudo losetup -d "$lo"

  # 1. QsCrypt writes.
  "$PROBE" stress "$img@1" /stress 1500 "$size" keep 2> "$WORK/stress.log" || { bad "$name: stress"; tail -20 "$WORK/stress.log"; return; }
  "$PROBE" write "$img@1" core/crates/qscrypt-core/src /from-qscrypt
  "$PROBE" churn "$img@1" /churn
  "$PROBE" check "$img@1" > "$WORK/check" || { bad "$name: own check"; cat "$WORK/check"; }
  $M probe "$PROBE" "$img@1" $TOPS > "$WORK/ours"

  # 2. Linux reads it.
  lo=$(attach "$img")
  if sudo ntfsfix -n "${lo}p1" > "$WORK/fix" 2>&1; then pass "$name: ntfsfix"; else bad "$name: ntfsfix"; cat "$WORK/fix"; fi
  for drv in ntfs-3g ntfs3; do
    if ! mount_drv "$drv" "${lo}p1" ro 2> "$WORK/mnt.err"; then
      if [ "$drv" = ntfs3 ]; then echo "SKIP $name: ntfs3 not available ($(cat "$WORK/mnt.err"))"; continue; fi
      bad "$name: $drv mount"; cat "$WORK/mnt.err"; continue
    fi
    $M walk "$MNT" $TOPS > "$WORK/$drv"
    sudo umount "$MNT"
    if $M diff "$WORK/ours" "$WORK/$drv"; then pass "$name: $drv reads what QsCrypt wrote ($(wc -l < "$WORK/ours") entries)"; else bad "$name: $drv"; fi
  done

  # 3. Linux writes into it, QsCrypt carries on.
  mount_drv ntfs-3g "${lo}p1" rw
  mkdir -p "$MNT/stress/linux-added"
  for i in $(seq 1 200); do echo "added $i" > "$MNT/stress/linux-added/a$i.txt"; done
  rm -rf "$MNT/from-qscrypt/fs"
  mv "$MNT/churn/renamed 001.txt" "$MNT/churn/renamed by linux.txt"
  sudo umount "$MNT"
  sudo losetup -d "$lo"
  "$PROBE" check "$img@1" > "$WORK/check" || { bad "$name: own check after Linux wrote"; cat "$WORK/check"; }
  "$PROBE" churn "$img@1" /churn2
  "$PROBE" check "$img@1" > "$WORK/check" || { bad "$name: own check after writing again"; cat "$WORK/check"; }
  $M probe "$PROBE" "$img@1" $TOPS churn2 > "$WORK/ours2"
  lo=$(attach "$img")
  mount_drv ntfs-3g "${lo}p1" ro
  $M walk "$MNT" $TOPS churn2 > "$WORK/linux2"
  sudo umount "$MNT"
  sudo losetup -d "$lo"
  if $M diff "$WORK/ours2" "$WORK/linux2"; then pass "$name: round trip with Linux writes"; else bad "$name: round trip"; fi

  cp "$WORK/ours2" "$OUT/$name.manifest"
  qemu-img convert -q -f raw -O vpc -o subformat=fixed,force_size=on "$img" "$OUT/$name.vhd"
  rm -f "$img"
}

round mkntfs-4k 300
round mkntfs-1k 200 -c 1024
round mkntfs-64k 400 -c 65536
round mkntfs-4k-records 300 -s 4096 -c 4096
ls -la "$OUT"
exit $fail
