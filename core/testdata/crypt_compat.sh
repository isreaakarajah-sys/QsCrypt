#!/bin/bash
# Encryption compatibility against cryptsetup (an independent implementation):
#  - BitLocker images made by Windows (cryptsetup's test corpus) decrypt to
#    the same bytes as cryptsetup's own mapping;
#  - BitLocker and VeraCrypt volumes made by QsCrypt are accepted by
#    cryptsetup (metadata checks, key derivation, keyfiles, hidden volumes)
#    and the file systems inside pass fsck and mount.
set -uo pipefail
BDE=${BDE:-core/target/release/examples/bdeprobe}
VOL=${VOL:-core/target/release/examples/volprobe}
WORK=$(mktemp -d)
fail=0
mkdir -p "$WORK/mnt"

echo "== Windows-made BitLocker images"
curl -fsSL https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/tests/bitlk-images.tar.xz -o "$WORK/b.tar.xz" && tar xJf "$WORK/b.tar.xz" -C "$WORK"
CONF=$WORK/bitlk-images/images.conf
for img in "$WORK"/bitlk-images/bitlk-*.img; do
  name=$(basename "$img" .img)
  sect=$(awk -v n="[$name]" '$0==n{f=1;next} /^\[/{f=0} f' "$CONF")
  PW=$(echo "$sect" | sed -n 's/^PW=//p'); RP=$(echo "$sect" | sed -n 's/^RP=//p'); SUM=$(echo "$sect" | sed -n 's/^SHA256SUM=//p')
  for cred in "$PW" "$RP"; do
    [ -z "$cred" ] && continue
    got=$("$BDE" sum "$img" "$cred" 2> "$WORK/err") || true
    if [ -z "$SUM" ]; then echo "INFO $name: $(tail -1 "$WORK/err")"; continue; fi
    if [ "$got" = "$SUM" ]; then echo "PASS $name ($(tail -1 "$WORK/err"))"; else echo "FAIL $name with ${cred:0:6}...: $(tail -3 "$WORK/err")"; fail=1; fi
  done
done
img=$WORK/bitlk-images/bitlk-aes-xts-128.img
sect=$(awk '$0=="[bitlk-aes-xts-128]"{f=1;next} /^\[/{f=0} f' "$CONF")
"$BDE" explain "$img" "$(echo "$sect" | sed -n 's/^PW=//p')" "$(echo "$sect" | sed -n 's/^RP=//p')" || true
img=$WORK/bitlk-images/bitlk-togo-aes-xts-128.img
sect=$(awk '$0=="[bitlk-togo-aes-xts-128]"{f=1;next} /^\[/{f=0} f' "$CONF")
"$BDE" explain "$img" "$(echo "$sect" | sed -n 's/^PW=//p')" "$(echo "$sect" | sed -n 's/^RP=//p')" || true

echo "== BitLocker volumes made by QsCrypt"
for combo in "exfat xts128" "fat cbc128" "exfat xts256" "fat cbc256"; do
  set -- $combo
  img=$WORK/qs-$1-$2.img
  rp=$("$BDE" create "$img" 134217728 "$1" "QsCrypt-Password-1" "$2" 2> "$WORK/err") || { echo "FAIL create $combo: $(cat "$WORK/err")"; fail=1; continue; }
  sudo cryptsetup bitlkDump "$img" > "$WORK/dump" 2>&1 || { echo "FAIL bitlkDump $combo"; cat "$WORK/dump"; fail=1; continue; }
  for cred in "QsCrypt-Password-1" "$rp"; do
    printf '%s' "$cred" | sudo cryptsetup open --type bitlk --key-file=- "$img" qsbl 2> "$WORK/err" || { echo "FAIL cryptsetup open $combo: $(cat "$WORK/err")"; fail=1; continue; }
    case $1 in exfat) sudo fsck.exfat -n /dev/mapper/qsbl > "$WORK/fsck" 2>&1 ;; fat) sudo fsck.fat -n /dev/mapper/qsbl > "$WORK/fsck" 2>&1 ;; esac || { echo "FAIL fsck $combo"; cat "$WORK/fsck"; fail=1; }
    opts=ro; [ "$1" = fat ] && opts=ro,utf8
    sudo mount -o "$opts" /dev/mapper/qsbl "$WORK/mnt" && {
      hello=$(cat "$WORK/mnt/hello.txt"); n=$(stat -c %s "$WORK/mnt/مجلد/big.bin")
      [ "$hello" = "QsCrypt BitLocker" ] && [ "$n" = 5000000 ] && echo "PASS cryptsetup + mount $combo" || { echo "FAIL content $combo: $hello $n"; fail=1; }
      sudo umount "$WORK/mnt"; } || { echo "FAIL mount $combo"; fail=1; }
    sudo cryptsetup close qsbl
  done
  "$BDE" check "$img" "QsCrypt-Password-1" | grep -q "hello: QsCrypt BitLocker" && echo "PASS reopen $combo" || { echo "FAIL reopen $combo"; fail=1; }
done
sudo cryptsetup bitlkDump "$WORK/qs-exfat-xts128.img" || true

echo "== BitLocker inside a VHD (the container Windows mounts natively)"
for combo in "exfat xts128" "fat cbc256"; do
  set -- $combo
  img=$WORK/qs-$1-$2.vhd
  rp=$("$BDE" vhd "$img" 134217728 "$1" "QsCrypt-Password-1" "$2" 2> "$WORK/err") || { echo "FAIL vhd create $combo: $(cat "$WORK/err")"; fail=1; continue; }
  if qemu-img info -f vpc "$img" > "$WORK/qi" 2>&1 && grep -q "file format: vpc" "$WORK/qi"; then echo "PASS qemu-img accepts the VHD footer $combo"; else echo "FAIL qemu-img $combo"; cat "$WORK/qi"; fail=1; fi
  loop=$(sudo losetup -fP --show "$img"); sleep 1
  sudo cryptsetup bitlkDump "${loop}p1" > "$WORK/dump" 2>&1 || { echo "FAIL bitlkDump vhd $combo"; cat "$WORK/dump"; fail=1; }
  for cred in "QsCrypt-Password-1" "$rp"; do
    printf '%s' "$cred" | sudo cryptsetup open --type bitlk --key-file=- "${loop}p1" qsvhd 2> "$WORK/err" || { echo "FAIL open vhd $combo: $(cat "$WORK/err")"; fail=1; continue; }
    case $1 in exfat) sudo fsck.exfat -n /dev/mapper/qsvhd > "$WORK/fsck" 2>&1 ;; fat) sudo fsck.fat -n /dev/mapper/qsvhd > "$WORK/fsck" 2>&1 ;; esac || { echo "FAIL fsck vhd $combo"; cat "$WORK/fsck"; fail=1; }
    opts=ro; [ "$1" = fat ] && opts=ro,utf8
    sudo mount -o "$opts" /dev/mapper/qsvhd "$WORK/mnt" && {
      hello=$(cat "$WORK/mnt/hello.txt"); n=$(stat -c %s "$WORK/mnt/مجلد/big.bin")
      [ "$hello" = "QsCrypt BitLocker" ] && [ "$n" = 5000000 ] && echo "PASS VHD partition + cryptsetup + mount $combo" || { echo "FAIL vhd content $combo: $hello $n"; fail=1; }
      sudo umount "$WORK/mnt"; } || { echo "FAIL vhd mount $combo"; fail=1; }
    sudo cryptsetup close qsvhd
  done
  sudo losetup -d "$loop"
done

echo "== VeraCrypt volumes made by QsCrypt"
head -c 4096 /dev/urandom > "$WORK/kf.bin"
check_vc() { # label image password keyfile(or -) [hidden]
  local label=$1 img=$2 pw=$3 kf=$4 hidden=${5:-}
  local args=(--type tcrypt --veracrypt)
  [ "$kf" != "-" ] && args+=(--key-file "$kf")
  [ -n "$hidden" ] && args+=(--tcrypt-hidden)
  printf '%s\n' "$pw" | sudo cryptsetup open "${args[@]}" "$img" qsvc 2> "$WORK/err" || { echo "FAIL cryptsetup $label: $(cat "$WORK/err")"; fail=1; return; }
  sudo fsck -n /dev/mapper/qsvc > "$WORK/fsck" 2>&1 || { echo "FAIL fsck $label"; cat "$WORK/fsck"; fail=1; }
  sudo mount -o ro,utf8 /dev/mapper/qsvc "$WORK/mnt" 2>/dev/null || sudo mount -o ro /dev/mapper/qsvc "$WORK/mnt"
  mountpoint -q "$WORK/mnt" && { ls -la "$WORK/mnt"; cat "$WORK/mnt"/*.txt; echo; echo "PASS $label"; sudo umount "$WORK/mnt"; } || { echo "FAIL mount $label"; fail=1; }
  sudo cryptsetup close qsvc
}
"$VOL" create "$WORK/vc1.hc" 67108864 exfat "vc pass 1" AES - && check_vc "VeraCrypt AES exFAT" "$WORK/vc1.hc" "vc pass 1" -
"$VOL" create "$WORK/vc2.hc" 67108864 fat "vc pass 2" AES-Twofish-Serpent "$WORK/kf.bin" && check_vc "VeraCrypt cascade + keyfile" "$WORK/vc2.hc" "vc pass 2" "$WORK/kf.bin"
"$VOL" create "$WORK/vc3.hc" 100663296 fat "outer pass" Serpent - 33554432 "hidden pass" && {
  check_vc "VeraCrypt outer" "$WORK/vc3.hc" "outer pass" -
  check_vc "VeraCrypt hidden" "$WORK/vc3.hc" "hidden pass" - hidden; }
exit $fail
