#!/bin/sh
# Runs ON THE PI at boot (via cloud-init bootcmd, see 03-configure-boot.sh --diag).
#   pi-diag.sh early  — write a marker, then schedule the full dump in 120 s
#   pi-diag.sh        — full dump
# Writes network diagnostics to the FAT boot partition so the Mac can read them
# without a network. Secrets (Wi-Fi PSK) are never printed.
OUT=/boot/firmware/rp-diag.txt

run() { echo; echo "== $*"; "$@" 2>&1 | sed -E 's/(psk|password)[=:].*/\1=<hidden>/I'; }

if [ "${1-}" = early ]; then
  {
    echo "== early marker: cloud-init bootcmd ran at $(date -Is), uptime $(cut -d' ' -f1 /proc/uptime)s"
    run cat /proc/device-tree/model
    run uname -r
    run lsusb
    run ip -br link
    run sh -c "dmesg | grep -iE 'rtl|8192|8188|wlan|cfg80211|firmware' | tail -40"
  } >"$OUT" 2>&1
  sync
  # --no-block is essential: bootcmd runs before sysinit.target, and a blocking
  # systemd-run waits on a timer job that waits on cloud-init — a boot deadlock.
  systemd-run --no-block --on-active=120 --unit=rp-diag sh /boot/firmware/rp-diag.sh >>"$OUT" 2>&1
  sync
  exit 0
fi


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
