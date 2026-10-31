#!/usr/bin/env bash
# Pick a Wi-Fi network this Mac has saved, read its password from the Keychain,
# and write WIFI_SSID / WIFI_PASSWORD into local.env.
# Usage: wifi-from-keychain.sh            # interactive picker
#        wifi-from-keychain.sh "SSID"     # use this saved network
#        wifi-from-keychain.sh --list     # just list saved networks
# macOS will show a Keychain dialog asking you to allow access to the password.
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
    [[ "${saved[$i]}" =~ 5G|5g|5GHz ]] && hint="   (name suggests 5 GHz — Edimax can't use it)"
    printf '  %2d) %s%s\n' "$((i + 1))" "${saved[$i]}" "$hint"
  done
}

ssid=""
case "${1-}" in
  --list) show_list; exit 0 ;;
  "")
    info "Saved Wi-Fi networks (the Pi's Edimax dongle needs a 2.4 GHz one):"
    show_list
    read -r -p "Number: " n
    [[ "$n" =~ ^[0-9]+$ ]] && ((n >= 1 && n <= ${#saved[@]})) || die "Invalid choice."
    ssid="${saved[$((n - 1))]}"
    ;;
  *)
    ssid="$1"
    printf '%s\n' "${saved[@]}" | grep -Fxq -- "$ssid" || warn "'$ssid' is not in this Mac's saved list; trying Keychain anyway."
    ;;
esac

info "Reading the password for '$ssid' from the Keychain (approve the macOS dialog)..."
pw=$(security find-generic-password -D "AirPort network password" -a "$ssid" -w 2>/dev/null) \
  || pw=$(security find-generic-password -s "$ssid" -w 2>/dev/null) \
  || die "No Keychain password for '$ssid' (or access was denied)."
[[ ${#pw} -ge 8 ]] || die "Password for '$ssid' is shorter than 8 characters — not a WPA2 personal network?"

# Rewrite the two keys with shell-safe quoting (local.env is sourced by bash).
WIFI_SSID_NEW="$ssid" WIFI_PASSWORD_NEW="$pw" python3 - "$ENV_FILE" <<'PY'
import os, re, shlex, sys
path = sys.argv[1]
vals = {"WIFI_SSID": os.environ["WIFI_SSID_NEW"], "WIFI_PASSWORD": os.environ["WIFI_PASSWORD_NEW"]}
lines = open(path, encoding="utf-8").read().splitlines()
for key, val in vals.items():
    new = f"{key}={shlex.quote(val)}"
    for i, line in enumerate(lines):
        if re.match(rf"^{key}=", line):
            lines[i] = new
            break
    else:
        lines.append(new)
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
chmod 600 "$ENV_FILE"

# Re-load to prove the file still sources cleanly and round-trips the values.
(
  load_env WIFI_SSID WIFI_PASSWORD
  [[ "$WIFI_SSID" == "$ssid" && "$WIFI_PASSWORD" == "$pw" ]] || die "Round-trip check failed."
)
ok "Saved WIFI_SSID='$ssid' and its password (${#pw} chars) to $ENV_FILE"
