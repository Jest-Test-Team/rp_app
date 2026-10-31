#!/bin/sh
# Runs ON THE PI at boot (via cloud-init bootcmd, see 03-configure-boot.sh --diag).
# Writes network diagnostics to the FAT boot partition so the Mac can read them
# without a network. Secrets (Wi-Fi PSK) are never printed.
OUT=/boot/firmware/rp-diag.txt

{
  echo "== early marker: cloud-init bootcmd ran at $(date -Is), uptime $(cut -d' ' -f1 /proc/uptime)s"
} >"$OUT"
sync

sleep 120

run() { echo; echo "== $*"; "$@" 2>&1 | sed -E 's/(psk|password)[=:].*/\1=<hidden>/I'; }

{
  echo "== full dump at $(date -Is)"
  run uname -a
  run cat /proc/device-tree/model
  run uptime
  run cloud-init status --long
  run lsusb
  run rfkill list
  run ip -br link
  run ip -4 addr
  run iw dev
  run nmcli -t general status
  run nmcli -f DEVICE,TYPE,STATE,CONNECTION device
  run nmcli -f NAME,TYPE,DEVICE,AUTOCONNECT connection show
  run nmcli -f SSID,CHAN,SIGNAL,SECURITY device wifi list
  run ls -l /etc/netplan /etc/NetworkManager/system-connections /run/NetworkManager/system-connections
  run sh -c "dmesg | grep -iE 'rtl|8192|8188|wlan|cfg80211|firmware|usb [0-9-]+:' | tail -80"
  run sh -c "journalctl -b -u NetworkManager -u wpa_supplicant --no-pager | tail -80"
  run sh -c "grep -iE 'warn|error|netplan|network' /var/log/cloud-init.log | tail -60"
  run systemctl is-active ssh NetworkManager wpa_supplicant
} >>"$OUT" 2>&1
sync
