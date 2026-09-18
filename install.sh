#!/usr/bin/env bash
# Install CyberVault from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/darkstardevx/cybervault/main/install.sh | sh
#
# Supported: Linux (x86_64, aarch64) and macOS (x86_64, aarch64).
set -eu

REPO="darkstardevx/cybervault"
INSTALL_DIR="${CYBERVAULT_INSTALL_DIR:-$HOME/.local/bin}"

die() {
  echo "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH"
}

need curl
need tar

if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  die "need either 'shasum' or 'sha256sum' on PATH"
fi

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1"
  else
    shasum -a 256 -c "$1"
  fi
}

os="$(uname -s)"
case "$os" in
  Linux) platform="unknown-linux-gnu" ;;
  Darwin) platform="apple-darwin" ;;
  *) die "unsupported OS: $os (CyberVault supports Linux and macOS)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

target="${arch}-${platform}"
archive="cybervault-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/latest/download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Downloading ${archive}..."
curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
curl -fsSL "${base_url}/${archive}.sha256" -o "${tmp_dir}/${archive}.sha256"

echo "Verifying checksum..."
(cd "$tmp_dir" && sha256_check "${archive}.sha256")

echo "Installing to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
install -m 755 "${tmp_dir}/cybervault" "${INSTALL_DIR}/cybervault"

echo ""
echo "cybervault installed to ${INSTALL_DIR}/cybervault"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:" ;
     echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
echo "Run 'cybervault init' to create a vault, or 'cybervault --help' for more."
echo "Optional: install Keysmith too for the TUI's generate-in-place feature —"
echo "  curl -fsSL https://raw.githubusercontent.com/darkstardevx/keysmith/main/install.sh | sh"
