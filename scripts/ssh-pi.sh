#!/usr/bin/env bash
# SSH into the Pi. Clears the stale host key left by the previous OS install.
# Usage: ssh-pi.sh [HOST_OR_IP] [ssh args...]
source "$(dirname "$0")/lib.sh"
load_env PI_HOSTNAME PI_USER

host="${1:-$PI_HOSTNAME.local}"
shift || true

ssh-keygen -R "$host" >/dev/null 2>&1 || true
exec ssh -o StrictHostKeyChecking=accept-new "$PI_USER@$host" "$@"
