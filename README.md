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

Use Docker Compose and a USB YubiKey. Run the commands from the repository root. Both demos use `https://localhost:8443`, so run one at a time.

### Set up TLS and enroll a key

Install `mkcert` to generate a trusted localhost certificate. [mkcert](https://github.com/FiloSottile/mkcert)

```sh
umask 077
mkdir -p local/config local/deploy-state local/ssh-state "$HOME/.shomei"
export CAROOT="$PWD/local/ca"
export SHOMEI_PROXY=https://localhost:8443
export SHOMEI_CA_FILE="$CAROOT/rootCA.pem"
export SHOMEI_UID="$(id -u)" SHOMEI_GID="$(id -g)"
mkcert -install
mkcert -ecdsa -cert-file local/config/tls.pem -key-file local/config/tls-key.pem localhost
install -m 0600 "$CAROOT/rootCA.pem" "$HOME/.shomei/localhost-ca.pem"

shomei init
if [ ! -e local/config/identities.json ]; then
  shomei get-id > local/config/identities.next \
    && mv local/config/identities.next local/config/identities.json
fi
```

Add `--set-pin` to `shomei init` if your YubiKey 5 has no FIDO2 PIN. For a YubiKey 4, add `--u2f` instead. Both demos enable attested, touch-only U2F for localhost.

The CLI stores the public identity in `~/.shomei/identity.json`. `shomei init` defaults to `https://localhost:8443`. For another gateway, set `SHOMEI_PROXY` or pass `--proxy` during enrollment. `shomei sign` can use the saved origin. `sign` and `ssh` use `~/.shomei/localhost-ca.pem` for localhost unless you specify a CA with `--ca-file` or `SHOMEI_CA_FILE`.

Run `shomei clear` to delete the local identity after confirmation. Remove its entry from the gateway’s allowlist to revoke access.

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

`ubuntu` is the OpenSSH login user. `deploy` matches `tcp.ssh_host` in the gateway config, and `tcp.upstream` sets the actual SSH destination. In this demo that destination is `127.0.0.1:2222` inside the gateway network namespace. [SSH demo configuration](fixtures/ssh/shomei.toml)

Approve with your YubiKey. The command prints `ubuntu`. Omit `-- id -un` for an interactive shell.

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

Put one `shomei get-id` token per line in the identity file. Use `#` on its own line or after a token to label a key, for example `shomei-id-v1:… # alice`. All keys use the `shomei` account. Shomei decodes the compressed records in memory and verifies their hardware attestation. Existing JSON arrays also work. Use `shomei get-id --json` for JSON-based tooling. [Convert an existing allowlist](AGENTS.md#enroll-a-key)

Replace the identity file atomically to reload the allowlist. Adding a key preserves existing grants. Removing or replacing a key revokes them. Restarting the proxy invalidates its session cookies.

### Share a gateway across services

One Shomei gateway serves one public HTTPS origin and forwards HTTP to one upstream. Point `http_upstream` at a private router to serve multiple sites and APIs under that origin. For example, the router can send `/dashboard` and `/api/deploy` to different services.

One enrollment covers those routes and an SSH upstream configured on the same gateway. For separate public HTTPS origins, use a separate gateway configuration and enroll a credential for each origin. You can use the same physical YubiKey for each enrollment.
