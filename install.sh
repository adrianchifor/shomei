#!/bin/sh
set -eu

case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) asset=shomei-macos-arm64 ;;
    Linux/x86_64) asset=shomei-linux-amd64 ;;
    Linux/aarch64|Linux/arm64) asset=shomei-linux-arm64 ;;
    *) printf 'Unsupported Shomei platform\n' >&2; exit 1 ;;
esac

repo=adrianchifor/shomei
release=https://github.com/$repo/releases/latest/download
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

# The checksum comes from the same release as the binary, so it only catches a
# damaged download. Build provenance shows that this repository's release
# workflow built the binary, which a replaced release asset cannot fake.
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if ! gh attestation verify "$tmp/$asset" --repo "$repo" \
        --signer-workflow "$repo/.github/workflows/release.yml" >/dev/null; then
        printf '%s\n' \
            "Build provenance check failed: $asset is not attested as built by $repo." \
            'Nothing was installed.' >&2
        exit 1
    fi
    printf 'Verified build provenance\n'
else
    printf '%s\n' \
        'Build provenance was not checked, only the checksum.' \
        'Install the GitHub CLI (gh) and sign in to verify it.' >&2
fi

mkdir -p "$destination"
install -m 0755 "$tmp/$asset" "$destination/shomei"
printf 'Installed %s/shomei\n' "$destination"
