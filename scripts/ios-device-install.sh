#!/usr/bin/env bash
# Install the RP Security app on an iPhone attached to this Mac, signed with a
# free Apple ID ("Personal Team"). No paid Apple Developer account needed.
#
#   scripts/ios-device-install.sh --team TEAMID [--device ID] [--debug]
#
# Before the first run:
#   1. Install Xcode, open it once; Xcode › Settings › Accounts › add your Apple ID.
#   2. Connect the iPhone by cable, unlock it, tap "Trust This Computer";
#      enable Settings › Privacy & Security › Developer Mode (iOS 16+), restart.
#   3. TEAMID: Xcode › Settings › Accounts › your Apple ID › "(Personal Team)",
#      or the "(XXXXXXXXXX)" in `security find-identity -v -p codesigning`.
#
# Free-team signatures expire after 7 days: run this again to refresh.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

team="" device="" mode=--release
while (($#)); do
  case "$1" in
    --team) team=${2:?--team needs your Team ID}; shift ;;
    --device) device=${2:?}; shift ;;
    --debug) mode=--debug ;;
    -h|--help) sed -n '2,15{s/^# \{0,1\}//;p;}' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[[ $team =~ ^[A-Z0-9]{10}$ ]] || die "give --team with your 10-character Team ID (see --help)"
xcodebuild -version >/dev/null 2>&1 || die "full Xcode is required (App Store), then: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"

app="$(cd "$(dirname "$0")/../apps/rp_console" && pwd)"
signing="$app/ios/Flutter/Signing.xcconfig"
cat > "$signing" <<XC
// Written by scripts/ios-device-install.sh (gitignored): free Apple ID signing.
CODE_SIGN_STYLE = Automatic
DEVELOPMENT_TEAM = $team
CODE_SIGN_IDENTITY = Apple Development
CODE_SIGN_IDENTITY[sdk=iphoneos*] = Apple Development
XC
info "signing with team $team (automatic; Xcode registers the device and creates a 7-day profile)"

cd "$app"
flutter pub get >/dev/null
if [[ -z $device ]]; then
  device=$(flutter devices --machine | python3 -c '
import json, sys
ios = [d for d in json.load(sys.stdin) if d.get("targetPlatform") == "ios" and not d.get("emulator")]
print(ios[0]["id"] if ios else "")')
fi
[[ -n $device ]] || die "no iPhone found: connect it by cable, unlock it and trust this Mac (flutter devices)"

flutter build ios "$mode"
flutter install -d "$device" "$mode"
ok "installed on $device"
cat <<'TXT'
First launch: on the iPhone open Settings › General › VPN & Device Management,
tap your Apple ID under "Developer App" and choose Trust. The app then opens.
It keeps working for 7 days; run this script again to re-sign.
TXT
