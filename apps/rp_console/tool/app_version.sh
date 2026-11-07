#!/usr/bin/env bash
# Print `name=X.Y.Z` for the app build: from a release tag vX.Y.Z, else from
# pubspec.yaml (iOS needs a purely numeric CFBundleShortVersionString).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${1-}"
if [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  name="${BASH_REMATCH[1]}"
else
  name=$(sed -n 's/^version:[[:space:]]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' "$here/pubspec.yaml")
fi
[[ $name =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "cannot determine the app version" >&2; exit 1; }
echo "name=$name"
