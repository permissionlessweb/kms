#!/usr/bin/env bash
# Build the KMS Bluetooth scanner as a signed app bundle whose code
# identity stays the same across rebuilds, so the macOS Bluetooth
# permission (TCC) granted to "KMS Bluetooth" survives a rebuild.
#
# Signing:
#   KMS_SIGN_IDENTITY="<name>"  sign with that keychain identity (a local
#                               self-signed code-signing certificate works).
#   unset                       ad-hoc sign with an explicit designated
#                               requirement on the bundle id instead of the
#                               default cdhash requirement, which changes on
#                               every build.
#
# OUT defaults to build/BleScan.app. Do not rebuild the bundle a running
# console is using; set OUT to a scratch path to test.
set -euo pipefail
cd "$(dirname "$0")/.."
BUNDLE_ID="network.terp.kms.blescan"
OUT="${OUT:-build/BleScan.app}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/BleScan.app/Contents/MacOS"
cp scripts/BleScan-Info.plist "$TMP/BleScan.app/Contents/Info.plist"
swiftc -O -target arm64-apple-macosx14.0 -o "$TMP/BleScan.app/Contents/MacOS/ble-scan" scripts/ble-scan.swift
if [ -n "${KMS_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$KMS_SIGN_IDENTITY" --identifier "$BUNDLE_ID" "$TMP/BleScan.app"
else
  codesign --force --sign - --identifier "$BUNDLE_ID" \
    -r="designated => identifier \"$BUNDLE_ID\"" "$TMP/BleScan.app"
fi
codesign --verify --strict "$TMP/BleScan.app"
mkdir -p "$(dirname "$OUT")"
rm -rf "$OUT.new"
mv "$TMP/BleScan.app" "$OUT.new"
rm -rf "$OUT"
mv "$OUT.new" "$OUT"
echo "built $OUT"
codesign -d -r- "$OUT" 2>&1 | grep designated
