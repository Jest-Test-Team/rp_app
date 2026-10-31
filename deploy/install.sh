#!/usr/bin/env bash
# Install the rp edge security gateway binaries on a Raspberry Pi (or any
# Debian-based Linux), either from a GitHub release or from source.
#
#   install.sh [--release [TAG] | --from-source | --archive FILE] [options]
#
# Sources (pick one; default --release latest):
#   --release [TAG]      Download prebuilt binaries + SHA256SUMS and verify them.
#   --from-source        Build with cargo (cargo-zigbuild when cross-compiling for --host).
#   --archive FILE       Install from a local rp-<target>.tar.gz.
#
# Where:
#   --host USER@HOST     Deploy to a remote device over SSH instead of this machine.
#   --prefix DIR         Binary prefix (default /usr/local).
#   --root DIR           Install under DIR instead of / (image prep / tests; no sudo).
#
# Other:
#   --repo OWNER/NAME    GitHub repository (default $RP_REPO or Jest-Test-Team/rp_app).
#   --base-url URL       Release download base, e.g. a mirror or file:// (default GitHub).
#   --target TRIPLE      Override the detected Rust target triple.
#   --uninstall [--purge]  Remove installed binaries (and /etc/rp, /var/lib/rp with --purge).
#   --package-only OUT   Build/pack an archive for --target into OUT and exit (used by CI).
#   --dry-run            Print what would happen; change nothing.
#   -h, --help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINS=(rpctl rp-dns)

mode=release tag=latest host="" prefix=/usr/local root="" archive="" target=""
repo="${RP_REPO:-Jest-Test-Team/rp_app}" base_url="${RP_BASE_URL:-}"
uninstall=0 purge=0 dry=0 package_out=""

die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; }

# run CMD... — execute, or print in --dry-run mode.
run() {
  if ((dry)); then printf 'would: %s\n' "$*"; else "$@"; fi
}

while (($#)); do
  case "$1" in
    --release) mode=release; if [[ ${2-} && ${2-} != --* ]]; then tag=$2; shift; fi ;;
    --from-source) mode=source ;;
    --archive) mode=archive; archive=${2:?--archive needs a file}; shift ;;
    --host) host=${2:?--host needs USER@HOST}; shift ;;
    --prefix) prefix=${2:?}; shift ;;
    --root) root=${2:?}; shift ;;
    --repo) repo=${2:?}; shift ;;
    --base-url) base_url=${2:?}; shift ;;
    --target) target=${2:?}; shift ;;
    --uninstall) uninstall=1 ;;
    --purge) purge=1 ;;
    --package-only) package_out=${2:?--package-only needs an output dir}; shift ;;
    --dry-run) dry=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid --repo '$repo'"
[[ $tag == latest || $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] || die "invalid release tag '$tag'"
case "$target" in
  ""|armv7-unknown-linux-gnueabihf|aarch64-unknown-linux-gnu|x86_64-unknown-linux-gnu) ;;
  *) die "unsupported target '$target' (armv7-unknown-linux-gnueabihf, aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu)" ;;
esac
[[ $prefix =~ ^/[A-Za-z0-9/_.-]*$ ]] || die "invalid --prefix '$prefix'"
[[ -z $host || $host =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$|^[A-Za-z0-9._:-]+$ ]] || die "invalid --host '$host'"

triple_for() {
  case "$1" in
    armv7l|armv7|armhf) echo armv7-unknown-linux-gnueabihf ;;
    aarch64|arm64) echo aarch64-unknown-linux-gnu ;;
    x86_64|amd64) echo x86_64-unknown-linux-gnu ;;
    armv6l) die "ARMv6 (Pi 1 / Zero) is not supported" ;;
    *) die "unsupported architecture '$1'" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

asset_name() { echo "rp-$1.tar.gz"; }

release_url() {
  local file=$1
  if [[ -n $base_url ]]; then
    if [[ $tag == latest ]]; then echo "$base_url/latest/$file"; else echo "$base_url/$tag/$file"; fi
  elif [[ $tag == latest ]]; then
    echo "https://github.com/$repo/releases/latest/download/$file"
  else
    echo "https://github.com/$repo/releases/download/$tag/$file"
  fi
}

fetch() { # fetch URL DEST
  if [[ $1 == file://* ]]; then cp "${1#file://}" "$2"
  else curl -fsSL --retry 3 -o "$2" "$1"; fi
}

workdir() { mktemp -d "${TMPDIR:-/tmp}/rp-install.XXXXXX"; }

# Download and verify a release archive; prints its path.
download_release() {
  local triple=$1 dir file sums expected actual
  file=$(asset_name "$triple")
  if ((dry)); then
    printf 'would: download %s\nwould: verify against %s\n' "$(release_url "$file")" "$(release_url SHA256SUMS)" >&2
    echo "/dev/null"; return
  fi
  dir=$(workdir)
  log "downloading $(release_url "$file")" >&2
  fetch "$(release_url "$file")" "$dir/$file" || die "download failed: $(release_url "$file")"
  fetch "$(release_url SHA256SUMS)" "$dir/SHA256SUMS" || die "cannot fetch SHA256SUMS"
  sums="$dir/SHA256SUMS"
  expected=$(awk -v f="$file" '$2 == f || $2 == "*"f {print $1}' "$sums")
  [[ -n $expected ]] || die "$file is not listed in SHA256SUMS"
  actual=$(sha256_of "$dir/$file")
  [[ $expected == "$actual" ]] || die "checksum mismatch for $file (expected $expected, got $actual)"
  log "checksum OK" >&2
  echo "$dir/$file"
}

# Build from source and pack an archive for TRIPLE into OUTDIR; prints its path.
build_archive() {
  local triple=$1 outdir=$2 native stage bin_dir name
  command -v cargo >/dev/null || die "cargo not found; install Rust from https://rustup.rs"
  native=$(triple_for "$(uname -m)" 2>/dev/null || true)
  if [[ $triple == "$native" && $(uname -s) == Linux ]]; then
    run cargo build --release --locked --manifest-path "$SRC_DIR/Cargo.toml" --target "$triple" >&2
  else
    command -v cargo-zigbuild >/dev/null || die "cross-compiling needs cargo-zigbuild (cargo install cargo-zigbuild) and zig"
    run cargo zigbuild --release --locked --manifest-path "$SRC_DIR/Cargo.toml" --target "$triple" >&2
  fi
  bin_dir="$SRC_DIR/target/$triple/release"
  name="rp-$triple"
  if ((dry)); then echo "$outdir/$(asset_name "$triple")"; return; fi
  stage=$(workdir)
  mkdir -p "$stage/$name/bin" "$stage/$name/configs" "$outdir"
  for b in "${BINS[@]}"; do install -m 0755 "$bin_dir/$b" "$stage/$name/bin/$b"; done
  install -m 0644 "$SRC_DIR/configs/rp.example.toml" "$stage/$name/configs/"
  install -m 0755 "$SRC_DIR/deploy/install.sh" "$stage/$name/"
  # Owner is recorded as root (never the builder's account), and no macOS
  # xattrs / AppleDouble files (GNU tar on the device warns about them).
  local owner=(--uid 0 --gid 0 --uname root --gname root)
  tar --version 2>/dev/null | grep -q GNU && owner=(--owner=0 --group=0 --numeric-owner)
  COPYFILE_DISABLE=1 tar --no-xattrs "${owner[@]}" -C "$stage" -czf "$outdir/$(asset_name "$triple")" "$name"
  rm -rf "$stage"
  echo "$outdir/$(asset_name "$triple")"
}

as_root() { # run with sudo unless already root or installing under --root
  if [[ -n $root || $(id -u) == 0 ]]; then run "$@"; else run sudo "$@"; fi
}

install_archive() {
  local file=$1 dir src manifest etc state
  etc="$root/etc/rp" state="$root/var/lib/rp" manifest="$root/var/lib/rp/install-manifest.txt"
  if ((dry)); then
    for b in "${BINS[@]}"; do printf 'would: install %s -> %s\n' "$b" "$root$prefix/bin/$b"; done
    printf 'would: create %s (config kept if present) and %s\n' "$etc" "$state"
    return
  fi
  dir=$(workdir)
  tar -C "$dir" -xzf "$file"
  src=$(find "$dir" -mindepth 1 -maxdepth 1 -type d -name 'rp-*' | head -1)
  [[ -n $src && -d $src/bin ]] || die "archive layout not recognised: $file"
  as_root install -d -m 0755 "$root$prefix/bin" "$etc"
  as_root install -d -m 0700 "$state"
  : > "$dir/manifest"
  for b in "${BINS[@]}"; do
    [[ -f $src/bin/$b ]] || die "archive is missing bin/$b"
    as_root install -m 0755 "$src/bin/$b" "$root$prefix/bin/$b"
    echo "$prefix/bin/$b" >> "$dir/manifest"
  done
  as_root install -m 0644 "$src/configs/rp.example.toml" "$etc/rp.example.toml"
  if [[ ! -e $etc/rp.toml ]]; then
    as_root install -m 0644 "$src/configs/rp.example.toml" "$etc/rp.toml"
    log "created $etc/rp.toml — edit device.lan_cidrs before applying"
  else
    log "kept existing $etc/rp.toml"
  fi
  as_root install -m 0600 "$dir/manifest" "$manifest"
  rm -rf "$dir"
  log "installed: ${BINS[*]} -> $root$prefix/bin"
  cat <<EOF
Next steps:
  1. edit /etc/rp/rp.toml (device.wan_if, device.lan_cidrs)
  2. sudo rpctl preflight base
  3. sudo rpctl apply base --dry-run
  4. sudo rpctl apply base   && sudo rpctl confirm   (within the timeout)
EOF
}

do_uninstall() {
  local manifest="$root/var/lib/rp/install-manifest.txt" state_file="$root/var/lib/rp/state.json"
  if [[ -f $state_file ]] && grep -q '"rolled_back": false' "$state_file"; then
    log "warning: some modules are still applied; run 'sudo rpctl rollback <module>' first to restore system files"
  fi
  if [[ -f $manifest ]]; then
    while IFS= read -r f; do [[ -n $f ]] && as_root rm -f "$root$f"; done < "$manifest"
    as_root rm -f "$manifest"
  else
    for b in "${BINS[@]}"; do as_root rm -f "$root$prefix/bin/$b"; done
  fi
  if ((purge)); then as_root rm -rf "$root/etc/rp" "$root/var/lib/rp"; fi
  if ((purge)); then log "uninstalled and purged config/state"; else log "uninstalled (config in /etc/rp kept)"; fi
}

remote() { # remote CMD... over ssh; inputs are validated above, expansion is intentional
  # shellcheck disable=SC2029
  if ((dry)); then printf 'would: ssh %s %s\n' "$host" "$*"; else ssh "$host" "$@"; fi
}

deploy_remote() {
  local arch triple file rflags=()
  if [[ -n $target ]]; then triple=$target
  else
    arch=$(ssh "$host" uname -m) || die "cannot reach $host over ssh"
    triple=$(triple_for "$arch")
  fi
  log "remote $host target: $triple"
  if ((uninstall)); then
    ((purge)) && rflags+=(--purge)
    remote "sudo bash -s -- --uninstall ${rflags[*]-}" < "$0"; return
  fi
  case $mode in
    release) file=$(download_release "$triple") ;;
    source) file=$(build_archive "$triple" "$(workdir)") ;;
    archive) file=$archive ;;
  esac
  run scp -q "$file" "$0" "$host:/tmp/"
  remote "sudo bash /tmp/$(basename "$0") --archive /tmp/$(basename "$file") --prefix '$prefix' && rm -f /tmp/$(basename "$file") /tmp/$(basename "$0")"
}

main() {
  if [[ -n $package_out ]]; then
    [[ -n $target ]] || die "--package-only needs --target"
    build_archive "$target" "$package_out"; return
  fi
  if [[ -n $host ]]; then deploy_remote; return; fi
  [[ $(uname -s) == Linux || -n $root || $dry == 1 ]] || die "local install is Linux-only; use --host USER@PI to deploy from this machine"
  if ((uninstall)); then do_uninstall; return; fi
  local triple file
  triple=${target:-$(triple_for "$(uname -m)")}
  log "target: $triple"
  case $mode in
    release) file=$(download_release "$triple") ;;
    source) file=$(build_archive "$triple" "$(workdir)") ;;
    archive) [[ -f $archive ]] || die "archive not found: $archive"; file=$archive ;;
  esac
  install_archive "$file"
}

main
