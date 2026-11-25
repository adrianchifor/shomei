# Shomei

Rust authentication proxy and CLI for supported YubiKey 5 Series keys with firmware 5.7.4 or later. A YubiKey PIN and touch unlock HTTP requests or short-lived mTLS access to a fixed TCP upstream. [Yubico attestation guidance](https://developers.yubico.com/U2F/Attestation_and_Metadata/)

## Run locally

Build with Rust 1.95 or newer. Linux builds need `pkg-config`, `libudev-dev`, and `libclang-dev`. Linux release binaries need `libudev.so.1`. [mkcert](https://github.com/FiloSottile/mkcert)

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
export SHOMEI_PROXY=https://localhost:8443
umask 077
mkdir -p local/config local/state
cp shomei.example.toml local/config/shomei.toml
mkcert -install
mkcert -cert-file local/config/tls.pem -key-file local/config/tls-key.pem localhost
export SHOMEI_CA_FILE="$(mkcert -CAROOT)/rootCA.pem"
shomei init --account operator --identity-file local/operator.json
shomei get-id --identity-file local/operator.json | jq -s . > local/config/identities.json
SHOMEI_UID=$(id -u) SHOMEI_GID=$(id -g) docker compose up --build
```

Set `http_upstream` and `[tcp].upstream` in the config. Either relay can be omitted. For a native gateway, set local TLS and state paths and run `shomei serve path/to/shomei.toml`.

The allowlist is a JSON array of public identity records from `get-id`. Each record binds one account to one HTTPS origin and an attested YubiKey credential. Replace the allowlist file atomically to add or remove identities. The gateway reloads it within about a second and keeps the last valid file if an update fails. Additions preserve grants. Removing or replacing a credential invalidates existing sessions and closes active TCP relays. Replace old enrollment-token settings with `identities_file` when upgrading.

## Browser and API

Open the protected URL and select **Use YubiKey**. The account defaults to `operator`. Enroll keys locally with `shomei init`, optionally with `--set-pin` for a key without a FIDO2 PIN.

For a deployment endpoint, send a one-use assertion with the request itself. Keep the upstream private so deployments pass through Shomei.

```sh
curl --fail-with-body --cacert "$SHOMEI_CA_FILE" -c local/session.txt \
  -H "Authorization: Shomei $(shomei sign)" -X POST "$SHOMEI_PROXY/deploy"
curl --fail-with-body --cacert "$SHOMEI_CA_FILE" -b local/session.txt \
  "$SHOMEI_PROXY/status"
```

Pass `--proxy`, `--account`, or `--ca-file` as needed. With public TLS certificates, use the system client defaults and omit the local CA options. The assertion and Shomei cookie are stripped before forwarding.

## SSH with Compose

Set `upstream = "ssh-fixture:2222"` and `ssh_host = "deploy"` in `[tcp]`. The gateway only dials its configured upstream. OpenSSH still checks the destination’s host key and authenticates the SSH user.

```sh
sh fixtures/ssh/setup.sh ~/.ssh/id_ed25519.pub
SHOMEI_UID=$(id -u) SHOMEI_GID=$(id -g) \
  docker compose -f compose.yaml -f compose.ssh.yaml up --build
shomei ssh --proxy "$SHOMEI_PROXY" \
  --ssh-arg=-o --ssh-arg="UserKnownHostsFile=$PWD/local/ssh/known_hosts" \
  --ssh-arg=-o --ssh-arg=StrictHostKeyChecking=yes ubuntu@deploy -- id -un
```

The smoke command should print `ubuntu`. The backend stays on a private Compose network. A `tls://localhost:9443` proxy URL also works. Pass `--auth-url` if the HTTPS listener uses a port other than 8443.

## Expiry and releases

Set `session_ttl_seconds` for HTTP cookies and `[tcp].cert_ttl_seconds` for mTLS grants. Defaults are 600 and 300 seconds. Active SSH connections close when their certificate expires. Restarting the gateway clears all grants. `[limits]` sets connection and challenge capacity. Run the loopback benchmark with `cargo test --locked --release relay_load -- --ignored --nocapture`.

Pushed tags build and publish SHA-256 checksums and binaries for Linux amd64, Linux arm64, and macOS arm64. The build uses the upstream RSA 0.10 compatibility fix. [Release workflow](.github/workflows/release.yml) · [Upstream dependency fix](https://github.com/kanidm/crypto-glue/pull/49)
