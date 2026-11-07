#!/usr/bin/env bash
# iOS signing for the release workflow (macOS runner).
#
#   ios_ci_signing.sh setup               import IOS_* secrets into a throw-away keychain,
#                                         install the profile, write Signing.xcconfig and
#                                         $RUNNER_TEMP/ExportOptions.plist
#   ios_ci_signing.sh package VER MODE    MODE=signed: verify the exported IPA;
#                                         MODE=unsigned: zip the archive's app as an IPA
#   ios_ci_signing.sh cleanup             delete the keychain, profile and signing files
#
# Env: P12_B64, P12_PASSWORD, PROFILE_B64, BUNDLE_ID, RUNNER_TEMP. Secrets are
# never printed; the keychain password is random and only lives in this job.
set -euo pipefail
app="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="${RUNNER_TEMP:?}"
kc="$tmp/rp-signing.keychain-db"
profiles="$HOME/Library/MobileDevice/Provisioning Profiles"

plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$2" 2>/dev/null; }

setup() {
  umask 077
  printf '%s' "${P12_B64:?}" | base64 --decode > "$tmp/cert.p12"
  printf '%s' "${PROFILE_B64:?}" | base64 --decode > "$tmp/profile.mobileprovision"
  local kcpw; kcpw=$(openssl rand -hex 24)
  security create-keychain -p "$kcpw" "$kc"
  security set-keychain-settings -lut 3600 "$kc"
  security unlock-keychain -p "$kcpw" "$kc"
  security import "$tmp/cert.p12" -k "$kc" -f pkcs12 -P "${P12_PASSWORD-}" -T /usr/bin/codesign -T /usr/bin/security >/dev/null
  security set-key-partition-list -S apple-tool:,apple: -s -k "$kcpw" "$kc" >/dev/null
  local existing=()
  while IFS= read -r k; do existing+=("$k"); done < <(security list-keychains -d user | tr -d '" ')
  security list-keychains -d user -s "$kc" "${existing[@]}"
  rm -f "$tmp/cert.p12"

  security cms -D -i "$tmp/profile.mobileprovision" > "$tmp/profile.plist"
  local uuid name team appid task devices method identity
  uuid=$(plist UUID "$tmp/profile.plist")
  name=$(plist Name "$tmp/profile.plist")
  team=$(plist TeamIdentifier:0 "$tmp/profile.plist")
  appid=$(plist Entitlements:application-identifier "$tmp/profile.plist")
  task=$(plist Entitlements:get-task-allow "$tmp/profile.plist" || echo false)
  devices=$(plist ProvisionedDevices "$tmp/profile.plist" | grep -c '^ ' || true)
  case "$appid" in
    "$team.${BUNDLE_ID:?}" | "$team.*") ;;
    *) echo "::error::provisioning profile is for '$appid', not $team.$BUNDLE_ID"; exit 1 ;;
  esac
  if [ "$task" = true ]; then method=development; identity="Apple Development"
  elif plist ProvisionsAllDevices "$tmp/profile.plist" >/dev/null; then method=enterprise; identity="Apple Distribution"
  else method=ad-hoc; identity="Apple Distribution"; fi
  security find-identity -v -p codesigning "$kc" | grep -q "$identity" \
    || { echo "::error::the certificate is not an '$identity' identity for a $method profile"; exit 1; }
  mkdir -p "$profiles"
  cp "$tmp/profile.mobileprovision" "$profiles/$uuid.mobileprovision"

  cat > "$app/ios/Flutter/Signing.xcconfig" <<XC
CODE_SIGN_STYLE = Manual
DEVELOPMENT_TEAM = $team
CODE_SIGN_IDENTITY = $identity
CODE_SIGN_IDENTITY[sdk=iphoneos*] = $identity
PROVISIONING_PROFILE_SPECIFIER = $name
XC
  cat > "$tmp/ExportOptions.plist" <<XP
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>$method</string>
  <key>teamID</key><string>$team</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>$identity</string>
  <key>provisioningProfiles</key><dict><key>$BUNDLE_ID</key><string>$name</string></dict>
  <key>compileBitcode</key><false/>
  <key>stripSwiftSymbols</key><true/>
</dict></plist>
XP
  echo "$uuid" > "$tmp/profile.uuid"
  echo "signing: method=$method team=$team profile='$name' devices=$devices"
}

package() {
  local ver="${1:?}" mode="${2:?}" out
  mkdir -p dist
  if [ "$mode" = signed ]; then
    out="dist/rp-security-$ver.ipa"
    local ipas=("$app"/build/ios/ipa/*.ipa)
    cp "${ipas[0]}" "$out"
    rm -rf "$tmp/ipa" && mkdir "$tmp/ipa" && unzip -q "$out" -d "$tmp/ipa"
    local apps=("$tmp"/ipa/Payload/*.app) a
    a="${apps[0]}"
    codesign --verify --deep --strict --verbose=2 "$a"
    codesign -dv "$a" 2>&1 | grep -E '^(Identifier|TeamIdentifier|Authority)='
    security cms -D -i "$a/embedded.mobileprovision" > "$tmp/embedded.plist"
    [ "$(plist UUID "$tmp/embedded.plist")" = "$(cat "$tmp/profile.uuid")" ] \
      || { echo "::error::the IPA does not embed the configured provisioning profile"; exit 1; }
  else
    out="dist/rp-security-$ver-unsigned.ipa"
    local apps=("$app"/build/ios/archive/Runner.xcarchive/Products/Applications/*.app) a
    a="${apps[0]}"
    rm -rf "$tmp/Payload" && mkdir -p "$tmp/Payload" && cp -R "$a" "$tmp/Payload/"
    (cd "$tmp" && zip -qry "$OLDPWD/$out" Payload)
  fi
  local built=("$tmp"/ipa/Payload/*.app "$tmp"/Payload/*.app)
  local id=""
  for b in "${built[@]}"; do [ -f "$b/Info.plist" ] && id=$(plist CFBundleIdentifier "$b/Info.plist") && break; done
  [ "$id" = "$BUNDLE_ID" ] || { echo "::error::unexpected bundle identifier '$id'"; exit 1; }
  ls -la "$out"
}

cleanup() {
  security delete-keychain "$kc" 2>/dev/null || true
  [ -f "$tmp/profile.uuid" ] && rm -f "$profiles/$(cat "$tmp/profile.uuid").mobileprovision"
  rm -f "$tmp/cert.p12" "$tmp/profile.mobileprovision" "$tmp/profile.plist" "$tmp/ExportOptions.plist" \
    "$app/ios/Flutter/Signing.xcconfig"
}

"${1:?usage: setup | package VER MODE | cleanup}" "${@:2}"
