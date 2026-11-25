# Shomei

Rust authentication proxy for one enrolled YubiKey 5 Series credential. Enrollment verifies packed FIDO2 attestation against pinned Yubico FIDO issuers and model IDs. Sign-in verifies a one-time WebAuthn assertion with user verification and presence. [Yubico attestation certificates](https://developers.yubico.com/U2F/Attestation_and_Metadata/) · [YubiKey model IDs](https://support.yubico.com/s/article/YubiKey-hardware-FIDO2-AAGUIDs)

## Run

Create a trusted `localhost` certificate and configure your upstreams in `local/config/shomei.toml`. [mkcert](https://github.com/FiloSottile/mkcert)

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

For a native run, set the example’s TLS and state paths to local files, point the upstreams at their native addresses, and run `cargo run -- path/to/shomei.toml`. The build needs Rust 1.95+ and OpenSSL development libraries.

## CLI

Use Python 3.10+ and connect the enrolled USB YubiKey. Pass `--ca-file` when Python needs a local CA. With a publicly trusted server certificate, omit it.

```sh
python3 -m venv .venv
.venv/bin/pip install 'fido2==2.0.0'
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
| `/enroll/start` | `{}` | `challenge_id` and `publicKey` creation options |
| `/enroll/finish` | `challenge_id` and the WebAuthn registration `credential` | `204` |
| `/auth/start` | `{}` for HTTP, or `client_csr_pem` for TCP | `challenge_id` and `publicKey` request options |
| `/auth/finish` | `challenge_id` and the WebAuthn assertion `credential` | HTTP session cookie or `certificate_pem`, plus `expires_at` in Unix seconds |

Both enrollment requests require `Authorization: Bearer <enrollment-token>`. The challenge lasts two minutes and is consumed on verification. The HTTP cookie is encrypted, `Secure`, and `HttpOnly`. TCP uses TLS 1.3 with mandatory client certificates and closes active relays at certificate expiry.

The PoC runs as a single instance with a persistent credential, an in-memory session key and TCP client CA, and a static YubiKey allowlist. Restarting clears all grants. Keep upstreams private and trust the HTTP app served on the same origin as the sign-in page. The TCP upstream is plain TCP. The HTTP relay uses HTTP/1.1 and excludes upgrades.
