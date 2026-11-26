# Shomei integration guide for agents

Use Shomei as the public entry point for an HTTP application, a fixed SSH upstream, or both. Keep upstream listeners reachable only from the gateway. All enrolled YubiKeys authenticate as `shomei`. Ask the operator to complete PIN and touch prompts on the machine with the key.

## Set up the gateway

1. Use `ghcr.io/adrianchifor/shomei:latest` for the gateway on Linux amd64 or arm64. Set `SHOMEI_IMAGE` to pin a release tag or digest. Run `curl -fsSL https://raw.githubusercontent.com/adrianchifor/shomei/main/install.sh | sh` on the machine with the YubiKey. The installer places the verified CLI at `~/.local/bin/shomei`. Use that path if `shomei` is outside `PATH`. On Linux the CLI requires `libudev.so.1`. [GitHub Packages](https://github.com/adrianchifor/shomei/pkgs/container/shomei) · [Binary releases](https://github.com/adrianchifor/shomei/releases)
2. Pick the HTTPS origin clients will use, including any nondefault port. It must use a DNS name. Install a certificate and private key for that hostname. Use the same value for the config’s `origin` and the client’s `SHOMEI_PROXY`. For local TLS and sample stacks, follow the [quickstart](README.md#quickstart).
3. Copy `shomei.example.toml` to `local/config/shomei.toml` and configure at least one upstream using the sections below. Use addresses the gateway can reach from its own network. For HTTP-only, remove `[tcp]`. For SSH-only, remove `http_upstream`. [Example configuration](shomei.example.toml)
4. On the gateway host, place the TLS files and the public allowlist from enrollment under `local/config`, and create `local/state`. Set `SHOMEI_UID` and `SHOMEI_GID` to a user that can read the config and write state. Run `docker compose up -d` after the files are in place. The supplied Compose file publishes listeners on loopback. For a native deployment, set the file paths and run `shomei serve path/to/shomei.toml`.

### Enroll a key

Run this on the operator’s machine. The default policy uses a supported YubiKey 5 Series key with firmware 5.7.4 or later, PIN, and touch.

```sh
export SHOMEI_PROXY=https://gateway.example.com:8443
shomei init
```

Use `--set-pin` for a YubiKey 5 with no FIDO2 PIN. For a localhost YubiKey 4 demo, use `--u2f` and set `allow_yubikey_4 = true` in the gateway config. For the bundled demo certificates, pass `--ca-file fixtures/localhost/ca.pem` to `sign` and `ssh`. For other localhost setups the CLI can use the public CA at `~/.shomei/localhost-ca.pem`.

The default public identity is `~/.shomei/identity.json`. `init` defaults to `https://localhost:8443` when the proxy is unspecified. `get-id` reads the local identity and `sign` can use its recorded origin from any working directory. Use `--identity-file` to select a separate identity.

Use `shomei clear` to delete a local identity after operator confirmation. Revoke gateway access by removing its entry from the allowlist.

The gateway accepts one `shomei-id-v1:` token per line from `shomei get-id`. Use an inline `#` comment for the operator’s username. To create a new Compose allowlist, run:

```sh
umask 077
mkdir -p local/config
if [ ! -e local/config/identities.json ]; then
  shomei get-id > local/config/identities.next \
    && mv local/config/identities.next local/config/identities.json
fi
```

Replace the file atomically to add or remove tokens. The gateway reloads it automatically. Removing or replacing a key revokes existing grants. For a JSON array allowlist, `shomei get-id --json` prints a compatible record.

After upgrading the gateway, convert a legacy JSON allowlist in Bash or Zsh with `jq` installed:

```sh
(
  set -o pipefail
  jq -c 'if type == "array" then .[] else error("expected a JSON array") end' local/config/identities.json |
    while IFS= read -r identity; do
      printf '%s\n' "$identity" | shomei get-id --identity-file /dev/stdin || exit 1
    done > local/config/identities.next
) && mv local/config/identities.next local/config/identities.json
```

## Share a gateway across services

Use one public HTTPS origin for related sites and APIs. Set `http_upstream` to a private router that sends paths such as `/dashboard` and `/api/deploy` to their respective services. Configure `[tcp]` on the same gateway to reuse the enrollment for SSH.

Use a separate Shomei configuration and enrollment for each distinct HTTPS origin, including when the port differs. The same physical YubiKey can enroll at each origin. [Shared gateway overview](README.md#share-a-gateway-across-services)

## Integrate a website

Set `http_upstream` to the application’s HTTP or HTTPS origin, without a path. Set these keys at the top level of the TOML file, before any tables. Route the application and `/_shomei` through the same Shomei HTTPS origin.

```toml
http_upstream = "http://web:8080"
session_ttl_seconds = 600
```

Unauthenticated HTML `GET` requests redirect to the login page and return to the original path after approval. A website can also link to login directly. Use an absolute gateway URL when linking from a different origin.

```html
<a href="/_shomei/login?next=%2Fdashboard">Continue with YubiKey</a>
```

Open the authentication page as a top-level navigation. Shomei sets `frame-ancestors 'none'` and rejects mismatched origins on authentication routes.

### Require approval for a website action

```toml
[browser_action]
path = "/api/deploy"
label = "Deploy service"
```

Link to `/_shomei/action` to open the built-in approval page. After a tap, it sends a signed `POST` to the configured path. This setting requires a fresh assertion for all HTTP writes through that gateway. Session cookies still authorize `GET`, `HEAD`, and `OPTIONS`.

For a custom same-origin WebAuthn UI, `POST {}` as JSON to `/_shomei/api/auth/start`. Pass the returned `publicKey` options to `navigator.credentials.get` after decoding the challenge and credential IDs. Serialize the result as WebAuthn JSON. Submit `{challenge_id, credential}` to `/_shomei/api/auth/finish` to create a session, or send that JSON as base64url without padding in `Authorization: Shomei <assertion>` on the intended upstream request. Each challenge can be used once. [Browser implementation](assets/auth.js)

Agents can obtain a one-use assertion with `shomei sign`. The following example calls a read endpoint and saves the returned cookie for later requests to the same gateway.

```sh
assertion="$(shomei sign)" && curl --fail-with-body \
  -H "Authorization: Shomei $assertion" -c local/session.txt "$SHOMEI_PROXY/status"
```

Pass `--cacert "$SHOMEI_CA_FILE"` to curl for a private CA. Session cookies belong to the issuing gateway process and expire on restart.

## Proxy SSH

Set a fixed private upstream and a client-facing SSH alias in `[tcp]`. Set `public_port` to the port clients can reach.

```toml
[tcp]
bind = "0.0.0.0:9443"
upstream = "sshd:22"
ssh_host = "deploy"
public_port = 9443
cert_ttl_seconds = 300
```

Expose port 9443 as raw TCP so Shomei can terminate mTLS. Keep the HTTPS authorization and mTLS listeners on the same hostname. Configure normal SSH user authentication on the upstream. Put its verified host key in the client’s known-hosts file under the `ssh_host` alias.

```sh
shomei ssh --proxy "$SHOMEI_PROXY" \
  --ssh-arg=-o --ssh-arg="UserKnownHostsFile=$HOME/.ssh/shomei_known_hosts" \
  --ssh-arg=-o --ssh-arg=StrictHostKeyChecking=yes ubuntu@deploy -- id -un
```

`shomei ssh` gets a short-lived client certificate after approval and starts OpenSSH through the relay. Omit the remote command for an interactive shell. To use `--proxy tls://gateway.example.com:9443` instead, pass `--auth-url "$SHOMEI_PROXY"` if the HTTPS port differs from 8443. The mTLS relay closes active connections at certificate expiry.

## Verify the integration

- For HTTP, check that an unauthenticated API request returns `401` and a browser `GET` redirects to login. Approve one request and verify it reaches the intended upstream.
- For SSH, check that the upstream port is private and a plain SSH client fails against the mTLS port. Run `shomei ssh` with the enrolled key and confirm that the upstream returns the expected user.
