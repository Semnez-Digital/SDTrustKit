#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT_DIR/rust/sd_trust_kit"
SWIFT_DIR="$ROOT_DIR/swift/SDTrustKit"
OUTPUT_DIR="${1:-$SWIFT_DIR/Frameworks}"
BUILD_DIR="${SD_TRUST_KIT_XCFRAMEWORK_BUILD_DIR:-$ROOT_DIR/build/xcframework}"
XCFRAMEWORK_NAME="CSDTrustKit.xcframework"

IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

TARGETS=(
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"
  "x86_64-apple-ios"
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
)

ensure_target() {
  local target="$1"
  local libdir
  libdir="$(rustc --print target-libdir --target "$target" 2>/dev/null || true)"
  if compgen -G "$libdir/libcore-*.rlib" >/dev/null; then
    return
  fi
  if command -v rustup >/dev/null 2>&1; then
    rustup target add "$target"
    return
  fi
  echo "error: Rust target '$target' is not installed and rustup is unavailable." >&2
  echo "Install rustup, then run: rustup target add ${TARGETS[*]}" >&2
  exit 1
}

build_staticlib() {
  local target="$1"
  echo "==> Building Rust staticlib for $target"
  case "$target" in
    *apple-ios*)
      env IPHONEOS_DEPLOYMENT_TARGET="$IPHONEOS_DEPLOYMENT_TARGET" \
        cargo rustc --manifest-path "$CRATE_DIR/Cargo.toml" --release --target "$target" --lib --crate-type staticlib
      ;;
    *apple-darwin)
      env MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
        cargo rustc --manifest-path "$CRATE_DIR/Cargo.toml" --release --target "$target" --lib --crate-type staticlib
      ;;
    *)
      cargo rustc --manifest-path "$CRATE_DIR/Cargo.toml" --release --target "$target" --lib --crate-type staticlib
      ;;
  esac
}

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

for target in "${TARGETS[@]}"; do
  ensure_target "$target"
  build_staticlib "$target"
done

HEADER_DIR="$BUILD_DIR/Headers"
mkdir -p "$HEADER_DIR"
cp "$CRATE_DIR/include/sd_trust_kit.h" "$HEADER_DIR/"
cat > "$HEADER_DIR/module.modulemap" <<'MODULEMAP'
module CSDTrustKit {
  header "sd_trust_kit.h"
  export *
}
MODULEMAP

IPHONEOS_LIB="$BUILD_DIR/libsd_trust_kit-ios.a"
SIMULATOR_LIB="$BUILD_DIR/libsd_trust_kit-ios-simulator.a"
MACOS_LIB="$BUILD_DIR/libsd_trust_kit-macos.a"

cp "$CRATE_DIR/target/aarch64-apple-ios/release/libsd_trust_kit.a" "$IPHONEOS_LIB"
lipo -create \
  "$CRATE_DIR/target/aarch64-apple-ios-sim/release/libsd_trust_kit.a" \
  "$CRATE_DIR/target/x86_64-apple-ios/release/libsd_trust_kit.a" \
  -output "$SIMULATOR_LIB"
lipo -create \
  "$CRATE_DIR/target/aarch64-apple-darwin/release/libsd_trust_kit.a" \
  "$CRATE_DIR/target/x86_64-apple-darwin/release/libsd_trust_kit.a" \
  -output "$MACOS_LIB"

xcrun strip -S -x "$IPHONEOS_LIB"
xcrun strip -S -x "$SIMULATOR_LIB"
xcrun strip -S -x "$MACOS_LIB"

rm -rf "$OUTPUT_DIR/$XCFRAMEWORK_NAME"
xcodebuild -create-xcframework \
  -library "$IPHONEOS_LIB" -headers "$HEADER_DIR" \
  -library "$SIMULATOR_LIB" -headers "$HEADER_DIR" \
  -library "$MACOS_LIB" -headers "$HEADER_DIR" \
  -output "$OUTPUT_DIR/$XCFRAMEWORK_NAME"

echo "==> Wrote $OUTPUT_DIR/$XCFRAMEWORK_NAME"
