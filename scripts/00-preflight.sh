#!/usr/bin/env bash
# List external physical disks so you can pick the SD card. Writes nothing.
source "$(dirname "$0")/lib.sh"

for tool in curl xz shasum openssl python3 diskutil; do
  command -v "$tool" >/dev/null || die "Missing tool: $tool"
done
ok "Required tools present"

disks=$(diskutil list external physical | awk '/^\/dev\/disk/ {sub("/dev/","",$1); print $1}')
[[ -n "$disks" ]] || die "No external disks found. Insert the SD card."

for d in $disks; do
  info_out=$(diskutil info "$d")
  name=$(awk -F': *' '/Device \/ Media Name/ {print $2}' <<<"$info_out")
  size=$(awk -F': *' '/Disk Size/ {print $2}' <<<"$info_out" | cut -d'(' -f1)
  layout=$(diskutil list "$d" | tail -n +3)
  echo
  echo "/dev/$d  [$name]  $size"
  echo "$layout"
  if grep -Eq 'boot|bootfs|RECOVERY|Linux' <<<"$layout"; then
    ok "Looks like a Raspberry Pi SD card"
  fi
  if grep -Eqi 'HYPERDISPLY|INSTANTVIEW' <<<"$name $layout"; then
    warn "USB display adapter drive — NOT the SD card"
  fi
done

echo
info "Put the SD card's id (e.g. disk5) in SD_DISK in $ENV_FILE."
