#!/bin/sh
# Install innernet-provider on Linux or macOS.
#   curl -fsSL https://raw.githubusercontent.com/shakeelamjid/innernet-protocol/main/provider/install.sh | sh
# Optional: INNERNET_VERSION=provider-v0.1.0  INNERNET_BIN_DIR=$HOME/.local/bin
set -eu

REPO="shakeelamjid/innernet-protocol"
BIN_DIR="${INNERNET_BIN_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "this installer needs '$1'"; }

need curl
need uname
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SUM="shasum -a 256"
else die "this installer needs sha256sum or shasum"; fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

tag="${INNERNET_VERSION:-}"
if [ -z "$tag" ]; then
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" \
    | grep -o '"tag_name": *"provider-v[^"]*"' | head -n 1 | sed 's/.*"\(provider-v[^"]*\)"/\1/') || true
  [ -n "$tag" ] || die "no provider release published yet"
fi
case "$tag" in provider-v*) ;; *) die "bad version tag: $tag" ;; esac

asset="innernet-provider-$os-$arch"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset ($tag)"
curl -fsSL -o "$tmp/$asset" "$base/$asset" || die "download failed"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "checksum file download failed"

expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[ -n "$expected" ] || die "no checksum listed for $asset"
actual=$(cd "$tmp" && $SUM "$asset" | awk '{print $1}')
[ "$expected" = "$actual" ] || die "checksum mismatch: expected $expected, got $actual"
say "Checksum OK"

mkdir -p "$BIN_DIR"
install -m 0755 "$tmp/$asset" "$BIN_DIR/innernet-provider" 2>/dev/null \
  || { cp "$tmp/$asset" "$BIN_DIR/innernet-provider" && chmod 0755 "$BIN_DIR/innernet-provider"; }

say "Installed $BIN_DIR/innernet-provider"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "Add it to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
say "Next:  innernet-provider init"
