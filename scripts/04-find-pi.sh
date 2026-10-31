#!/usr/bin/env bash
# After powering the Pi on, wait for it to join Wi-Fi and open SSH.
# Usage: 04-find-pi.sh [TIMEOUT_SECONDS]   (default 480 — first boot on a Pi 2 is slow)
source "$(dirname "$0")/lib.sh"
load_env PI_HOSTNAME

host="$PI_HOSTNAME.local"
timeout="${1:-480}"
deadline=$((SECONDS + timeout))

info "Waiting up to ${timeout}s for $host (ssh port 22)..."
while ((SECONDS < deadline)); do
  ip=$(ping -c1 -t2 "$host" 2>/dev/null | sed -nE 's/^PING [^(]+\(([0-9.]+)\).*/\1/p') || true
  if [[ -n "$ip" ]] && nc -z -G 2 "$ip" 22 2>/dev/null; then
    ok "$host is up at $ip with SSH open"
    echo "$ip"
    exit 0
  fi
  printf '.'
  sleep 5
done
echo
warn "$host did not answer within ${timeout}s."

# Fallback: look for Raspberry Pi / Edimax MAC prefixes in the ARP cache.
info "Scanning the ARP cache for Raspberry Pi or Edimax devices..."
subnet=$(ipconfig getifaddr en0 2>/dev/null | cut -d. -f1-3) || true
if [[ -n "$subnet" ]]; then
  for i in $(seq 1 254); do ping -c1 -t1 "$subnet.$i" >/dev/null 2>&1 & done
  wait
fi
found=0
while read -r line; do
  ip=$(sed -nE 's/.*\(([0-9.]+)\) at ([0-9a-f:]+).*/\1/p' <<<"$line")
  [[ -n "$ip" ]] || continue
  if nc -z -G 1 "$ip" 22 2>/dev/null; then ssh_state="ssh open"; else ssh_state="ssh closed"; fi
  echo "    $line  [$ssh_state]"
  found=1
done < <(arp -an | grep -Ei ' at (b8:27:eb|dc:a6:32|74:da:38|80:1f:02|00:1f:1f|08:be:ac)')
((found)) || die "No candidates. Check: 2.4 GHz SSID, WPA2, correct password in local.env."
info "Try: ./scripts/ssh-pi.sh <ip>"
