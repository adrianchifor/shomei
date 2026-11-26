# <img src="assets/seal.png" alt="" width="32" height="32"> Shomei

Shomei (署名, Japanese for “signature”) is a Rust authentication proxy for HTTP and TCP backed by hardware-attested YubiKeys.

- **HTTP** supports browser WebAuthn and one-use CLI assertions, with encrypted session cookies for follow-up requests.
- **TCP** uses short-lived mTLS certificates. `shomei ssh` uses a certificate to tunnel OpenSSH to a fixed upstream.
- **Tailscale SSH** can require YubiKey approval before a direct connection from the caller’s device.

All enrolled keys authenticate as `shomei`. The default policy requires a supported YubiKey 5 Series key with firmware 5.7.4 or later, PIN, and touch.

<p align="center">
  <img src="docs/yubikey-prompt.png" width="360" alt="Browser prompting for a security key touch on the Shomei sign-in page">
</p>

## Quickstart

Start a local deploy API behind Shomei and approve a deploy with your YubiKey. Run the commands in an empty directory with Docker Compose installed. The bundled TLS key is public and for loopback demos only. Use `init --u2f` for a YubiKey 4. Once Compose is up, you can also approve a deploy from a browser that trusts `fixtures/localhost/ca.pem`. [Open Deploy service](https://localhost:8443/_shomei/action)

```sh
curl -fsSL https://raw.githubusercontent.com/adrianchifor/shomei/main/install.sh | sh
curl -fsSL https://github.com/adrianchifor/shomei/releases/latest/download/shomei-deploy-example.tar.gz | tar -xz

shomei="$HOME/.local/bin/shomei"
ca=fixtures/localhost/ca.pem
deploy=https://localhost:8443/api/deploy
mkdir -m 0755 -p local/config
"$shomei" init
"$shomei" get-id > local/config/identities.json
chmod 0644 local/config/identities.json
docker compose -f compose.deploy.yaml up --wait

curl -si --cacert "$ca" -X POST "$deploy" # 401 Unauthorized
approval="$("$shomei" sign --ca-file "$ca")" && curl -fsS --cacert "$ca" \
  -H "Authorization: Shomei $approval" -X POST "$deploy"
# Enter your PIN if prompted and touch your YubiKey. Expect HTTP 200 with the new deploy revision.
```

## SSH demo

Run this demo in a repository checkout. Stop the deploy demo with `docker compose -f compose.deploy.yaml down`, then copy its `local/config/identities.json` into the checkout at the same path. Use the public key that matches your OpenSSH identity.

```sh
sh fixtures/ssh/setup.sh "$HOME/.ssh/id_ed25519.pub"
docker compose -f compose.ssh.yaml up --wait
"$HOME/.local/bin/shomei" ssh --proxy tls://localhost:9443 --ca-file fixtures/localhost/ca.pem \
  --ssh-arg=-o --ssh-arg="UserKnownHostsFile=$PWD/local/ssh/known_hosts" \
  --ssh-arg=-o --ssh-arg=StrictHostKeyChecking=yes ubuntu@deploy -- id -un
```

`ubuntu` is the OpenSSH login user. `deploy` matches `tcp.ssh_host` in the gateway config, and `tcp.upstream` sets the actual SSH destination. In this demo that destination is `127.0.0.1:2222` inside the gateway network namespace. [SSH demo configuration](fixtures/ssh/shomei.toml)

Approve with your YubiKey. The command prints `ubuntu`. Omit `-- id -un` for an interactive shell.

Stop the demo with `docker compose -f compose.ssh.yaml down`.

## Configure your own upstream

Save the example configuration as `local/config/shomei.toml`, set your origin and upstreams, and create a writable `local/state`. Save the Compose file alongside `local/` and run `docker compose up -d` to start `ghcr.io/adrianchifor/shomei:latest`. Keep upstream listeners private. [Compose file](compose.yaml) · [Example configuration](shomei.example.toml)

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

Replace the identity file atomically to reload the allowlist. Removing or replacing a key revokes existing HTTP sessions and TCP relay access. Restarting the proxy invalidates its session cookies.

### Share a gateway across services

One Shomei gateway serves one public HTTPS origin and forwards HTTP to one upstream. Point `http_upstream` at a private router to serve multiple sites and APIs under that origin. For example, the router can send `/dashboard` and `/api/deploy` to different services.

One enrollment covers those routes and an SSH upstream configured on the same gateway. For separate public HTTPS origins, use a separate gateway configuration and enroll a credential for each origin. You can use the same physical YubiKey for each enrollment.

## Tailscale SSH

Shomei verifies a YubiKey and grants the calling device a short access window to a fixed target. OpenSSH connects directly from that device, so Tailscale evaluates the caller’s posture and SSH re-authentication. This mode requires Tailscale Premium or Enterprise. [Setup and policy example](AGENTS.md#approve-direct-tailscale-ssh)

```sh
shomei ssh --tailscale --proxy https://shomei.example.ts.net:8443 ubuntu@deploy.example.ts.net
```
