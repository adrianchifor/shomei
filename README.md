# Shomei

Rust authentication proxy for YubiKey 5 Series accounts with one credential per account. Enrollment requires an allowlisted model and a FIDO attestation chain issued under Yubico Attestation Root 1, used since firmware 5.7.4. Sign-in requires a one-time ES256 WebAuthn assertion with user verification and presence. Replace older enrollments before upgrading. [Yubico attestation certificates](https://developers.yubico.com/U2F/Attestation_and_Metadata/) · [Yubico firmware advisory](https://www.yubico.com/support/security-advisories/ysa-2024-03/) · [YubiKey model IDs](https://support.yubico.com/s/article/YubiKey-hardware-FIDO2-AAGUIDs)

## Run

Run as an unprivileged user. Create a trusted `localhost` certificate and configure your upstreams in `local/config/shomei.toml`. [mkcert](https://github.com/FiloSottile/mkcert)

```sh
umask 077
mkdir -p local/config local/state
cp shomei.example.toml local/config/shomei.toml
mkcert -install
mkcert -cert-file local/config/tls.pem -key-file local/config/tls-key.pem localhost
openssl rand -hex 32 > local/config/enrollment-token
SHOMEI_UID=$(id -u) SHOMEI_GID=$(id -g) docker compose up --build
```

Open `https://localhost:8443/_shomei/enroll` in a current Chromium browser. Enter the enrollment token, select your YubiKey, enter its FIDO2 PIN, and touch it. Then open `https://localhost:8443/` to sign in and reach the HTTP upstream. The token is only usable before enrollment. Configure either relay or both in the TOML file.

For a native run, set the example’s TLS and state paths to local files, point the upstreams at their native addresses, and run `cargo run --locked --release -- path/to/shomei.toml` with Rust 1.95+.

For named accounts, set `enrollment_tokens_file` to a TOML file mapping lowercase account names to independent tokens generated with `openssl rand -hex 32`. Enter the account name at enrollment and sign-in, or pass `--account` to the CLI. The legacy token file and `credential.json` belong to `operator`. Restrict filesystem access to the configuration and state directories.

## CLI

Use Python 3.10+ and connect the enrolled USB YubiKey. Pass `--ca-file` when Python needs a local CA. With a publicly trusted server certificate, omit it.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-cli.txt
CA="$(mkcert -CAROOT)/rootCA.pem"
.venv/bin/python cli.py --ca-file "$CA" https://localhost:8443 http local/cookies.txt
curl --cacert "$CA" --cookie local/cookies.txt https://localhost:8443/
```

For TCP, use OpenSSL 3 to generate a client key and CSR. Shomei ties the CSR to the WebAuthn challenge and returns a client certificate. The client keeps the private key.

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=shomei -keyout local/client.key -out local/client.csr
.venv/bin/python cli.py --ca-file "$CA" https://localhost:8443 tcp local/client.csr local/client.pem
openssl s_client -quiet -connect localhost:9443 -servername localhost \
  -verify_hostname localhost -verify_return_error -CAfile "$CA" \
  -cert local/client.pem -key local/client.key
```

## API

All routes below accept JSON under `/_shomei/api`.

| POST | Body | Response |
| --- | --- | --- |
| `/enroll/start` | Optional `account` | `challenge_id` and `publicKey` creation options |
| `/enroll/finish` | `challenge_id` and the WebAuthn registration `credential` | `204` |
| `/auth/start` | Optional `account`, plus `client_csr_pem` for TCP | `challenge_id` and `publicKey` request options |
| `/auth/finish` | `challenge_id` and the WebAuthn assertion `credential` | HTTP session cookie or `certificate_pem`, plus `expires_at` in Unix seconds |

Both enrollment requests require `Authorization: Bearer <enrollment-token>`. Omitting `account` selects `operator`. Each challenge lasts two minutes and can be used once. The HTTP cookie uses ChaCha20-Poly1305 and is `Secure` and `HttpOnly`. TCP client keys and CSR signatures use P-256 and SHA-256. Both listeners and upstream HTTPS use TLS 1.3. TCP closes active relays at certificate expiry.

## Capacity

The default limits are 4,096 connections per listener, 512 concurrent handshakes per listener, and 8,192 in-flight HTTP requests. `[limits]` controls capacity and challenge quotas. Challenge quotas group clients by source IPv4 address or IPv6 /64. Size the descriptor limit for both proxy legs and idle upstream connections. For a four-worker loopback load test, run `cargo test --locked --release relay_load -- --ignored --nocapture`.

Shomei runs as a single instance. Restarting clears grants and preserves enrolled credentials. Keep upstreams private and trust the HTTP app served on the sign-in origin. The TCP upstream is plain TCP. HTTPS supports HTTP/1.1 and HTTP/2. Upgrades are disabled.

The lockfile uses the upstream `crypto-glue` RSA 0.10 compatibility fix until it is available in a published release. [Upstream change](https://github.com/kanidm/crypto-glue/pull/49)
