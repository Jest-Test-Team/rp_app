#!/usr/bin/env bash
# Write the cached Raspberry Pi OS image to the SD card. ERASES THE TARGET DISK.
# Usage: 02-flash-sd.sh DISK [--dry-run]     e.g. 02-flash-sd.sh disk5 --dry-run
source "$(dirname "$0")/lib.sh"
load_env SD_DISK

target=""; dry=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    /dev/*) target="${arg#/dev/}" ;;
    *) target="$arg" ;;
  esac
done
target="${target#r}"   # accept rdiskN too
[[ -n "$target" ]] || die "Usage: $0 DISK [--dry-run]   (run 00-preflight.sh to find it)"

# --- Safety gates -----------------------------------------------------------
[[ "$target" =~ ^disk[0-9]+$ ]] || die "'$target' is not a whole-disk id like disk5."
[[ "$target" == "$SD_DISK" ]] || die "$target does not match SD_DISK=$SD_DISK in $ENV_FILE."

info_out=$(diskutil info "$target" 2>/dev/null) || die "$target not found."
field() { awk -F': *' -v k="$1" '$1 ~ "^ *"k"$" {print $2; exit}' <<<"$info_out"; }

[[ "$(field 'Device Location')" == "External" ]] || die "$target is not an external disk."
[[ "$(field 'Removable Media')" == "Removable" ]] || die "$target is not removable media."
[[ "$(field 'Whole')" == "Yes" ]] || die "$target is not a whole disk."

root_disk=$(diskutil info / | awk -F': *' '/Part of Whole/ {print $2}')
[[ "$target" != "$root_disk" ]] || die "$target is the Mac's boot disk."

bytes=$(field 'Disk Size' | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/')
[[ "$bytes" =~ ^[0-9]+$ ]] || die "Cannot read size of $target."
((bytes < 64 * 1000 ** 3)) || die "$target is ≥ 64 GB — refusing (not a typical SD card)."

name=$(field 'Device / Media Name')
grep -Eqi 'HYPERDISPLY|INSTANTVIEW' <<<"$name" && die "$target is the USB display adapter, not the SD card."

image=$(cached_image)
[[ -n "$image" ]] || die "No image in $CACHE_DIR — run 01-download-image.sh first."

ok "All safety checks passed"
echo "    target: /dev/$target  [$name]  $((bytes / 1000000)) MB"
echo "    image:  $(basename "$image")"
diskutil list "$target" | tail -n +3 | sed 's/^/    /'

cmds=(
  "diskutil unmountDisk /dev/$target"
  "xz -dc '$image' | sudo dd of=/dev/r$target bs=4m status=progress"
  "sync"
)
if ((dry)); then
  info "Dry run — would execute:"
  printf '    %s\n' "${cmds[@]}"
  exit 0
fi

warn "EVERYTHING on /dev/$target will be erased."
confirm "Type the disk id ($target) to continue:" "$target"

diskutil unmountDisk "/dev/$target"
xz -dc "$image" | sudo dd of="/dev/r$target" bs=4m status=progress
sync
ok "Image written"

info "Waiting for /Volumes/bootfs to mount..."
for _ in $(seq 1 30); do
  [[ -d /Volumes/bootfs ]] && break
  sleep 1
  ((_ == 10)) && diskutil mountDisk "/dev/$target" >/dev/null 2>&1 || true
done
[[ -d /Volumes/bootfs ]] || die "bootfs did not mount — re-insert the card, then run 03-configure-boot.sh."
ok "/Volumes/bootfs mounted — next: ./scripts/03-configure-boot.sh"
