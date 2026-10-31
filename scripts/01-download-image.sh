#!/usr/bin/env bash
# Download the latest Raspberry Pi OS Lite (32-bit) image and verify its SHA-256.
source "$(dirname "$0")/lib.sh"
load_env IMAGE_URL

mkdir -p "$CACHE_DIR"
url=$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$IMAGE_URL") || die "Cannot resolve $IMAGE_URL"
file="$CACHE_DIR/$(basename "$url")"
info "Latest image: $(basename "$url")"

curl -fsSL -o "$file.sha256" "$url.sha256" || die "Cannot fetch checksum"
expected=$(awk '{print $1}' "$file.sha256")

verify() { [[ -f "$file" ]] && [[ "$(shasum -a 256 "$file" | awk '{print $1}')" == "$expected" ]]; }

if verify; then
  ok "Cached image already verified"
else
  info "Downloading to $file"
  curl -fL --progress-bar -o "$file" "$url" || die "Download failed"
  verify || die "Checksum mismatch — delete $file and retry"
  ok "Checksum OK"
fi
echo "$file"
