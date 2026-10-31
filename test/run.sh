#!/usr/bin/env bash
# Run the Robot Framework suites.
#
#   test/run.sh                    # default tags: static unit cli installer security
#   test/run.sh integration        # one or more tags (requires-root suites need sudo)
#   test/run.sh all                # everything that can run here
#   RP_E2E_HOST=user@pi test/run.sh e2e
#
# Results go to test/results/ (gitignored).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
VENV="$HERE/.venv"

if [[ ! -x $VENV/bin/robot ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
fi

cargo build --workspace --quiet --manifest-path "$REPO/Cargo.toml"
rm -rf "$HERE/results/tmp"   # scratch dirs from the previous run

tags=("$@")
((${#tags[@]})) || tags=(static unit cli installer security)

args=(--outputdir "$HERE/results" --exclude perf --runemptysuite)
if [[ ${tags[0]} != all ]]; then
  for t in "${tags[@]}"; do args+=(--include "$t"); done
fi
[[ -n ${RP_E2E_HOST:-} ]] || args+=(--exclude requires-pi)
[[ ${RP_ALLOW_ROOT:-0} == 1 ]] || args+=(--exclude requires-root)

exec "$VENV/bin/robot" "${args[@]}" "$HERE/suites"
