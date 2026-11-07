#!/usr/bin/env bash
# Store the iOS signing material for the release workflow as GitHub secrets
# (needs a paid Apple Developer account and `gh auth login`).
#
#   scripts/release-signing-secrets.sh --p12 cert.p12 --profile RP_AdHoc.mobileprovision
#
#   --p12      "Apple Distribution" certificate with its private key, exported from
#              Keychain Access (right-click › Export…); its password is prompted.
#   --profile  an Ad Hoc (or Development) provisioning profile for
#              com.jesttestteam.rp.rpConsole that lists your test iPhones' UDIDs.
#
# Sets IOS_DIST_CERT_P12_BASE64, IOS_DIST_CERT_PASSWORD, IOS_PROVISION_PROFILE_BASE64.
# Values go to gh over stdin: nothing appears on a command line or in history.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

p12="" profile=""
while (($#)); do
  case "$1" in
    --p12) p12=${2:?}; shift ;;
    --profile) profile=${2:?}; shift ;;
    -h|--help) sed -n '2,13{s/^# \{0,1\}//;p;}' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[[ -f $p12 && -f $profile ]] || die "give --p12 FILE and --profile FILE (see --help)"
command -v gh >/dev/null || die "GitHub CLI (gh) is required"

security cms -D -i "$profile" > /dev/null 2>&1 || die "$profile is not a provisioning profile"
read -r -s -p "Password of $(basename "$p12"): " pw; echo
openssl pkcs12 -in "$p12" -passin fd:3 -nokeys -legacy 3<<<"$pw" >/dev/null 2>&1 \
  || openssl pkcs12 -in "$p12" -passin fd:3 -nokeys 3<<<"$pw" >/dev/null 2>&1 \
  || die "wrong password, or not a PKCS#12 file"

base64 -i "$p12" | tr -d '\n' | gh secret set IOS_DIST_CERT_P12_BASE64
printf '%s' "$pw" | gh secret set IOS_DIST_CERT_PASSWORD
base64 -i "$profile" | tr -d '\n' | gh secret set IOS_PROVISION_PROFILE_BASE64
unset pw
ok "iOS signing secrets set; the next release builds a signed, installable IPA"
