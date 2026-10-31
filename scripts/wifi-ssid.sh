#!/usr/bin/env bash
# Pick a Wi-Fi network this Mac has saved and write it as WIFI_SSID in local.env.
# WIFI_PASSWORD is left untouched — fill it in yourself.
# Usage: wifi-ssid.sh            # interactive picker
#        wifi-ssid.sh "SSID"     # write this SSID directly
#        wifi-ssid.sh --list     # just list saved networks
source "$(dirname "$0")/lib.sh"
[[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE (copy local.env.example first)."

iface=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/ {getline; print $2; exit}')
[[ -n "$iface" ]] || die "No Wi-Fi interface found."

saved=()
while IFS= read -r line; do
  saved+=("${line#"${line%%[![:space:]]*}"}")
done < <(networksetup -listpreferredwirelessnetworks "$iface" | tail -n +2)
((${#saved[@]})) || die "No saved Wi-Fi networks on $iface."

show_list() {
  local i hint
  for i in "${!saved[@]}"; do
    hint=""
    [[ "${saved[$i]}" =~ 5G|5g ]] && hint="   (name suggests 5 GHz — Edimax can't use it)"
    printf '  %2d) %s%s\n' "$((i + 1))" "${saved[$i]}" "$hint"
  done
}

case "${1-}" in
  --list) show_list; exit 0 ;;
  "")
    info "Saved Wi-Fi networks (the Pi's Edimax dongle needs a 2.4 GHz one):"
    show_list
    read -r -p "Number: " n
    if ! [[ "$n" =~ ^[0-9]+$ ]] || ((n < 1 || n > ${#saved[@]})); then die "Invalid choice."; fi
    ssid="${saved[$((n - 1))]}"
    ;;
  *) ssid="$1" ;;
esac

# Rewrite WIFI_SSID with shell-safe quoting (local.env is sourced by bash).
WIFI_SSID_NEW="$ssid" python3 - "$ENV_FILE" <<'PY'
import os, re, shlex, sys
path = sys.argv[1]
new = "WIFI_SSID=" + shlex.quote(os.environ["WIFI_SSID_NEW"])
lines = open(path, encoding="utf-8").read().splitlines()
for i, line in enumerate(lines):
    if re.match(r"^WIFI_SSID=", line):
        lines[i] = new
        break
else:
    lines.append(new)
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY

# Prove the file still sources cleanly and round-trips the value.
(load_env WIFI_SSID; [[ "$WIFI_SSID" == "$ssid" ]] || die "Round-trip check failed.")
ok "WIFI_SSID='$ssid' saved to $ENV_FILE"
