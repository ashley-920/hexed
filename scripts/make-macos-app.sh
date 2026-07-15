#!/usr/bin/env bash
# Build a double-clickable Hexed.app bundle for macOS.
#
# Usage:
#   ./scripts/make-macos-app.sh          # release build -> target/release/Hexed.app
#   ./scripts/make-macos-app.sh --install # also copy into /Applications
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# yara-x -> wasmtime needs the macOS SDK for its C build; ensure cc finds it.
export SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path 2>/dev/null)}"

VERSION="0.1.0"
APP="target/release/Hexed.app"

echo "==> building release binary"
cargo build --release -p hexed

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/hexed "$APP/Contents/MacOS/hexed"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# App icon from assets/logo.png (if present) -> AppIcon.icns
ICON_PLIST=""
if [[ -f assets/logo.png ]]; then
    echo "==> generating app icon"
    ICONSET="$(mktemp -d)/AppIcon.iconset"
    mkdir -p "$ICONSET"
    for s in 16 32 128 256 512; do
        sips -z "$s" "$s" assets/logo.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null 2>&1 || true
        sips -z "$((s * 2))" "$((s * 2))" assets/logo.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null 2>&1 || true
    done
    if iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
        ICON_PLIST='    <key>CFBundleIconFile</key><string>AppIcon</string>'
    fi
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Hexed</string>
    <key>CFBundleDisplayName</key><string>Hexed</string>
    <key>CFBundleIdentifier</key><string>dev.hexed.app</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleExecutable</key><string>hexed</string>
${ICON_PLIST}
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>10.15</string>
    <key>NSHighResolutionCapable</key><true/>
    <!-- Offer Hexed in Finder's "Open With" for any file. Rank "Alternate"
         means it never becomes a default handler / never hijacks associations. -->
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key><string>Any file</string>
            <key>CFBundleTypeRole</key><string>Viewer</string>
            <key>LSHandlerRank</key><string>Alternate</string>
            <!-- Cover every file. Several abstract UTIs are special-cased by
                 macOS: it lists a generic public.data-only handler in the menu
                 but REFUSES it at open time ("cannot open files in the X format")
                 for executables, text, source code, images, A/V, and archives.
                 Declare those umbrella types explicitly so "Open With -> Hexed"
                 actually opens them; public.content/data/item cover the rest
                 (documents & arbitrary blobs). -->
            <key>LSItemContentTypes</key>
            <array>
                <string>public.item</string>
                <string>public.content</string>
                <string>public.data</string>
                <string>public.executable</string>
                <string>public.text</string>
                <string>public.plain-text</string>
                <string>public.source-code</string>
                <string>public.image</string>
                <string>public.audiovisual-content</string>
                <string>public.archive</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
PLIST

# Ad-hoc code-sign so Gatekeeper lets a locally-built app run without
# "unidentified developer" friction. Harmless if codesign is unavailable.
codesign --force --deep --sign - "$APP" 2>/dev/null || echo "   (codesign skipped)"

echo "==> done: $APP"

if [[ "${1:-}" == "--install" ]]; then
    echo "==> copying to /Applications"
    rm -rf "/Applications/Hexed.app"
    cp -R "$APP" "/Applications/Hexed.app"
    echo "==> installed: /Applications/Hexed.app"
fi

echo
echo "Launch it with any of:"
echo "  open $APP"
echo "  open $APP --args /path/to/file.bin"
echo "  double-click it in Finder"
