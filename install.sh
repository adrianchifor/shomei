#!/bin/sh
set -eu

case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) asset=shomei-macos-arm64 ;;
    Linux/x86_64) asset=shomei-linux-amd64 ;;
    Linux/aarch64|Linux/arm64) asset=shomei-linux-arm64 ;;
    *) printf 'Unsupported Shomei platform\n' >&2; exit 1 ;;
esac

release=https://github.com/adrianchifor/shomei/releases/latest/download
destination=$HOME/.local/bin
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

curl -fsSL "$release/$asset" -o "$tmp/$asset"
curl -fsSL "$release/SHA256SUMS" -o "$tmp/SHA256SUMS"
(
    cd "$tmp"
    awk -v asset="$asset" '$2 == asset { print; count++ } END { exit (count != 1) }' SHA256SUMS > checksum
    if command -v sha256sum >/dev/null; then
        sha256sum -c checksum
    else
        shasum -a 256 -c checksum
    fi
)
mkdir -p "$destination"
install -m 0755 "$tmp/$asset" "$destination/shomei"
printf 'Installed %s/shomei\n' "$destination"
