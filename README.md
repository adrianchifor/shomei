# Shomei

Rust authentication proxy and CLI for hardware-attested YubiKeys. The default policy requires a supported YubiKey 5 Series key with firmware 5.7.4 or later, PIN, and touch. [Yubico attestation guidance](https://developers.yubico.com/U2F/Attestation_and_Metadata/)

## Local setup

Set up localhost TLS and the identity file before starting either Compose example. [mkcert](https://github.com/FiloSottile/mkcert)

```sh
export SHOMEI_PROXY=https://localhost:8443
export SHOMEI_UID="$(id -u)" SHOMEI_GID="$(id -g)"
export CAROOT="$PWD/local/ca"
export SHOMEI_CA_FILE="$CAROOT/rootCA.pem"
umask 077
mkdir -p local/config local/deploy-state local/ssh-state
mkcert -install
mkcert -ecdsa -cert-file local/config/tls.pem -key-file local/config/tls-key.pem localhost
[ -e local/config/identities.json ] || printf '[]\n' > local/config/identities.json
```

An empty allowlist lets the stack start and denies every authentication request. To approve requests, build the CLI with Rust 1.95 or newer and register a YubiKey. Linux builds need `pkg-config`, `libudev-dev`, and `libclang-dev`. Linux release binaries need `libudev.so.1`.

```sh
cargo build --locked --release
export PATH="$PWD/target/release:$PATH"
shomei init --account operator --identity-file local/operator.json
shomei get-id --identity-file local/operator.json | jq -es 'select(length > 0)' > local/config/identities.next \
  && mv local/config/identities.next local/config/identities.json
```

Use `shomei init --set-pin` when the key has no FIDO2 PIN. Both examples use the same HTTPS origin and identity file. Run one stack at a time.

### YubiKey 4 on localhost

Both Compose examples enable `allow_yubikey_4` for localhost. YubiKey 4 enrollment verifies Yubico’s U2F attestation. The browser and CLI require a touch for approval. [YubiKey U2F PIN support](https://docs.yubico.com/yesdk/users-manual/application-u2f/u2f-pin.html)

For a fresh demo allowlist, use this enrollment command after building the CLI.

```sh
shomei init --u2f --account operator --identity-file local/yubikey4-operator.json
shomei get-id --identity-file local/yubikey4-operator.json | jq -es 'select(length > 0)' > local/config/identities.next \
  && mv local/config/identities.next local/config/identities.json
```

## Click to deploy

```sh
docker compose -f compose.deploy.yaml up --build --wait
```

If the gateway exits during startup, run `docker compose -f compose.deploy.yaml logs shomei` for the cause.

Open [the deploy page](https://localhost:8443/_shomei/action), click **Deploy service**, and complete the YubiKey prompt. The page sends a one-use assertion with `POST /api/deploy`. Shomei verifies the assertion before the private demo API increments its revision. Each deployment requires a fresh assertion. The session cookie can read `/status`.

```sh
curl --fail-with-body --cacert "$SHOMEI_CA_FILE" -c local/session.txt \
  -H "Authorization: Shomei $(shomei sign)" -X POST "$SHOMEI_PROXY/api/deploy"
curl --fail-with-body --cacert "$SHOMEI_CA_FILE" -b local/session.txt "$SHOMEI_PROXY/status"
docker compose -f compose.deploy.yaml down
```

## SSH into Ubuntu

```sh
sh fixtures/ssh/setup.sh ~/.ssh/id_ed25519.pub
docker compose -f compose.ssh.yaml up --build --wait
shomei ssh --proxy tls://localhost:9443 \
  --ssh-arg=-o --ssh-arg="UserKnownHostsFile=$PWD/local/ssh/known_hosts" \
  --ssh-arg=-o --ssh-arg=StrictHostKeyChecking=yes ubuntu@deploy -- id -un
```

The command should print `ubuntu`. Shomei checks the allowlisted alias `deploy` and the YubiKey assertion before issuing a client certificate. OpenSSH verifies the pinned host key and uses your regular SSH key. The Ubuntu container binds SSH to loopback in Shomei’s network namespace, with port 9443 exposed only through the mTLS relay. Pass `--auth-url` if the HTTPS listener uses a port other than 8443. [Compose network modes](https://docs.docker.com/reference/compose-file/container-spec/#network_mode)

## Configuration

Each example ships its own configuration under `fixtures/`. Set `session_ttl_seconds` for HTTP cookies and `[tcp].cert_ttl_seconds` for mTLS grants. Defaults are 600 and 300 seconds. Active SSH connections close when their certificate expires. `[browser_action]` enables the action page and requires a fresh assertion for writes through that gateway.

The allowlist is a JSON array of public records from `get-id`. Replace it atomically to update identities. Additions preserve grants. Removing or replacing a credential revokes existing grants. The gateway keeps the last valid file if a reload fails.

For your own upstream, create `local/state`, copy `shomei.example.toml` to `local/config/shomei.toml`, and start `compose.yaml`. For a native gateway, use local file paths and run `shomei serve path/to/shomei.toml`. `[limits]` sets connection and challenge capacity. Run the loopback benchmark with `cargo test --locked --release relay_load -- --ignored --nocapture`.

Pushed tags build and publish SHA-256 checksums and binaries for Linux amd64, Linux arm64, and macOS arm64. The build uses the upstream RSA 0.10 compatibility fix. [Release workflow](.github/workflows/release.yml) · [Upstream dependency fix](https://github.com/kanidm/crypto-glue/pull/49)
