# shellcheck shell=bash
# Shared helpers for the Pi flashing scripts. Source this file; do not run it.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${RP_ENV_FILE:-$REPO_DIR/local.env}"
CACHE_DIR="$REPO_DIR/.cache"

die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
warn() { printf '\033[33m! %s\033[0m\n' "$*" >&2; }
info() { printf '\033[36m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }

# confirm "question" "expected answer"
confirm() {
  local answer
  read -r -p "$1 " answer
  [[ "$answer" == "$2" ]] || die "Aborted (expected '$2')."
}

# load_env KEY [KEY...] — source local.env and require the listed keys.
load_env() {
  [[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE (copy local.env.example and fill it in)."
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  local key val missing=()
  for key in "$@"; do
    val="${!key-}"
    if [[ -z "$val" || "$val" == *CHANGE_ME* ]]; then missing+=("$key"); fi
  done
  ((${#missing[@]} == 0)) || die "Set these in $ENV_FILE: ${missing[*]}"
}

# yaml_str VALUE — emit VALUE as a double-quoted string (a JSON string is valid YAML).
yaml_str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

# Newest image in the cache (empty if none).
cached_image() {
  local f newest=""
  for f in "$CACHE_DIR"/*.img.xz; do
    [[ -f "$f" ]] || continue
    [[ -z "$newest" || "$f" -nt "$newest" ]] && newest="$f"
  done
  printf '%s' "$newest"
}
