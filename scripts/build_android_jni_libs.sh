#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT_DIR/rust/sd_trust_kit"
KOTLIN_DIR="$ROOT_DIR/kotlin/SDTrustKit/sdtrustkit"
OUTPUT_DIR="${1:-$KOTLIN_DIR/src/main/jniLibs}"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "error: cargo-ndk is required to build Android JNI libraries." >&2
  echo "Install it with: cargo install cargo-ndk" >&2
  exit 1
fi

if [[ -z "${ANDROID_NDK_HOME:-}" && -z "${ANDROID_NDK_ROOT:-}" ]]; then
  echo "error: ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point to an Android NDK." >&2
  exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

cargo ndk \
  -t armeabi-v7a \
  -t arm64-v8a \
  -t x86 \
  -t x86_64 \
  -o "$OUTPUT_DIR" \
  build \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --release \
  --features android-jni

echo "==> Wrote Android JNI libraries to $OUTPUT_DIR"
