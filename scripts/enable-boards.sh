#!/usr/bin/env bash
# Turn on the ESP32 boards on the gateway, in a safe order. Run on the Pi:
#
#   sudo bash enable-boards.sh [--no-approver] [--watchdog SECONDS]
#
# 1. udev rule: /dev/rp-approver (ESP32-S3, native USB) and
#    /dev/rp-approver-backup (ESP32-WROOM behind a CH9102, pinned to its
#    serial number, detected here).
# 2. Enroll every board that answers as an approval key (rpctl approver
#    enroll), so keys exist *before* approvals require one.
# 3. Add [approver] (unless --no-approver) and [boards] to /etc/rp/rp.toml
#    (backup kept), check the config.
# 4. Apply the agent module (installs and starts rp-boards.service) and
#    restart the console API so it serves the board endpoints.
#
# Stops at the first problem; nothing after it is changed.
set -euo pipefail

approver=1
watchdog=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --no-approver) approver=0 ;;
    --watchdog) watchdog=${2:?}; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ $(id -u) == 0 ]] || { echo "run with sudo" >&2; exit 1; }
CFG=/etc/rp/rp.toml
RULES=/etc/udev/rules.d/99-rp-approver.rules
log() { printf '\n== %s\n' "$*"; }

log "1/4 udev rule"
wroom_serial=""
for d in /dev/ttyUSB*; do
  [[ -e $d ]] || continue
  props=$(udevadm info -q property -n "$d")
  if grep -q '^ID_VENDOR_ID=1a86$' <<<"$props" && grep -q '^ID_MODEL_ID=55d4$' <<<"$props"; then
    wroom_serial=$(sed -n 's/^ID_SERIAL_SHORT=//p' <<<"$props")
  fi
done
{
  echo '# rp hardware boards (scripts/enable-boards.sh). Root-only.'
  echo 'SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", SYMLINK+="rp-approver", MODE="0600", OWNER="root"'
  if [[ -n $wroom_serial ]]; then
    echo "SUBSYSTEM==\"tty\", ATTRS{idVendor}==\"1a86\", ATTRS{idProduct}==\"55d4\", ATTRS{serial}==\"$wroom_serial\", SYMLINK+=\"rp-approver-backup\", MODE=\"0600\", OWNER=\"root\""
  fi
} > "$RULES"
echo "wrote $RULES (WROOM serial: ${wroom_serial:-not found})"
udevadm control --reload
udevadm trigger --subsystem-match=tty
udevadm settle
ls -l /dev/rp-approver* || { echo "no board found: plug the ESP32 boards into the powered hub" >&2; exit 1; }

log "2/4 enroll the boards' keys"
for port in /dev/rp-approver /dev/rp-approver-backup; do
  [[ -e $port ]] || continue
  name=main; [[ $port == *backup ]] && name=backup
  rpctl approver info --port "$port"
  rpctl approver enroll --name "$name" --port "$port"
done
rpctl approver list
if ! rpctl approver list | grep -q ' active '; then
  echo "no key enrolled: not enabling approvals" >&2
  exit 1
fi

log "3/4 config"
cp -a "$CFG" "$CFG.before-boards.$(date +%s)"
if (( approver )) && ! grep -q '^\[approver\]' "$CFG"; then
  printf '\n[approver]\n' >> "$CFG"
  echo "added [approver]: approvals now need a 3 s press on an enrolled key"
fi
if ! grep -q '^\[boards\]' "$CFG"; then
  printf '\n[boards]\nwatchdog_seconds = %s\n' "$watchdog" >> "$CFG"
  echo "added [boards] (watchdog_seconds = $watchdog)"
fi
rpctl check

log "4/4 services"
rpctl apply agent
rpctl confirm 2>/dev/null || true
for s in rp-privd.service rp-api.service; do
  systemctl is-enabled --quiet "$s" 2>/dev/null && systemctl restart "$s" && echo "restarted $s"
done
sleep 3
systemctl --no-pager --lines=0 status rp-boards.service || true
echo
echo "done. Status: cat /var/lib/rp/boards/status.json"
echo "If all keys are lost: sudo rpctl approver bypass --minutes 15"
