# Shomei

Shomei is a Rust authentication proxy for HTTP and TCP backed by hardware-attested YubiKeys.

- **HTTP** supports browser WebAuthn and one-use CLI assertions, with encrypted session cookies for follow-up requests.
- **TCP** uses short-lived mTLS certificates. `shomei ssh` uses a certificate to tunnel OpenSSH to a fixed upstream.

All enrolled keys authenticate as `shomei`. The default policy requires a supported YubiKey 5 Series key with firmware 5.7.4 or later, PIN, and touch.

## Install

Release builds target Linux amd64 and arm64, and macOS arm64. Linux binaries require `libudev.so.1`. [Releases](https://github.com/adrianchifor/shomei/releases)

To build from source, use Rust 1.95 or newer. On Debian or Ubuntu, install `pkg-config`, `libudev-dev`, and `libclang-dev`.

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
```

## Local demos

Use Docker Compose, `jq`, and a USB YubiKey. Run the commands from the repository root. Both demos use `https://localhost:8443`, so run one at a time.

### Set up TLS and enroll a key

Install `mkcert` to generate a trusted localhost certificate. [mkcert](https://github.com/FiloSottile/mkcert)

```sh
umask 077
mkdir -p local/config local/deploy-state local/ssh-state
export CAROOT="$PWD/local/ca"
export SHOMEI_PROXY=https://localhost:8443
export SHOMEI_CA_FILE="$CAROOT/rootCA.pem"
export SHOMEI_UID="$(id -u)" SHOMEI_GID="$(id -g)"
mkcert -install
mkcert -ecdsa -cert-file local/config/tls.pem -key-file local/config/tls-key.pem localhost

shomei init --identity-file local/key.json
shomei get-id --identity-file local/key.json | jq -es 'select(length > 0)' > local/config/identities.next \
  && mv local/config/identities.next local/config/identities.json
```

Add `--set-pin` to `shomei init` if your YubiKey 5 has no FIDO2 PIN. For a YubiKey 4, add `--u2f` instead. Both demos enable attested, touch-only U2F for localhost.

### Approve a deploy

```sh
docker compose -f compose.deploy.yaml up --build --wait
```

Select **Deploy service** and approve with your YubiKey. Each approval sends `POST /api/deploy` to the private demo API, which increments its revision. [Open the deploy page](https://localhost:8443/_shomei/action)

The same API works from the CLI. Save the session cookie to read the revision later.

```sh
approval="$(shomei sign)" && curl --fail-with-body --cacert "$SHOMEI_CA_FILE" \
  -c local/session.txt -H "Authorization: Shomei $approval" -X POST "$SHOMEI_PROXY/api/deploy"
curl --fail-with-body --cacert "$SHOMEI_CA_FILE" -b local/session.txt "$SHOMEI_PROXY/status"
docker compose -f compose.deploy.yaml down
```

### SSH into Ubuntu

Use the public key that matches your OpenSSH identity.

```sh
sh fixtures/ssh/setup.sh "$HOME/.ssh/id_ed25519.pub"
docker compose -f compose.ssh.yaml up --build --wait
shomei ssh --proxy tls://localhost:9443 \
  --ssh-arg=-o --ssh-arg="UserKnownHostsFile=$PWD/local/ssh/known_hosts" \
  --ssh-arg=-o --ssh-arg=StrictHostKeyChecking=yes ubuntu@deploy -- id -un
```

Approve with your YubiKey. The command prints `ubuntu`. Omit `-- id -un` for an interactive shell. The Ubuntu SSH listener is private to the gateway network namespace. Port 9443 accepts mTLS connections from Shomei clients.

Stop the demo with `docker compose -f compose.ssh.yaml down`.

## Configure your own upstream

Copy `shomei.example.toml` to `local/config/shomei.toml`, set your origin and upstreams, and create `local/state`. Keep upstream listeners private and start the gateway with `docker compose up --build`. To run without Docker, set the file paths for your host and run `shomei serve path/to/shomei.toml`. [Example configuration](shomei.example.toml)

| Setting | Purpose |
| --- | --- |
| `origin` | Public HTTPS origin, including a nondefault port. Enroll keys for this origin. |
| `tls_cert`, `tls_key` | Gateway TLS certificate and private key. |
| `http_upstream` | HTTP or HTTPS origin to forward to. |
| `tcp.upstream` | Fixed TCP host and port. Set `tcp.ssh_host` to the alias used by `shomei ssh`. |
| `session_ttl_seconds` | HTTP session lifetime. Defaults to 600 seconds. |
| `tcp.cert_ttl_seconds` | mTLS certificate lifetime. Defaults to 300 seconds. Active relays close at expiry. |
| `[browser_action]` | Exposes an approval page and requires a fresh assertion for HTTP writes. |
| `[limits]` | Connection, request, and challenge limits. |

The identity file is a JSON array of public records from `shomei get-id`. Replace it atomically to reload the allowlist. Adding a key preserves existing grants. Removing or replacing a key revokes them. Restarting the proxy invalidates its session cookies.
