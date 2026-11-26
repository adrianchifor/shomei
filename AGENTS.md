# Shomei integration guide for agents

Use Shomei for HTTP authentication, forward HTTP/TCP access, an SSH relay, or direct Tailscale SSH approval. Keep reverse upstreams private. All enrolled YubiKeys authenticate as `shomei`. Ask the operator to complete PIN and touch prompts on the machine with the key.

## Set up the gateway

1. Use `ghcr.io/adrianchifor/shomei:latest` for the gateway on Linux amd64 or arm64. Set `SHOMEI_IMAGE` to pin a release tag or digest. Run `curl -fsSL https://raw.githubusercontent.com/adrianchifor/shomei/main/install.sh | sh` on the machine with the YubiKey. The installer places the verified CLI at `~/.local/bin/shomei`. Use that path if `shomei` is outside `PATH`. On Linux the CLI requires `libudev.so.1`. [GitHub Packages](https://github.com/adrianchifor/shomei/pkgs/container/shomei) · [Binary releases](https://github.com/adrianchifor/shomei/releases)
2. Pick the HTTPS origin clients will use, including any nondefault port. It must use a DNS name. Install a certificate and private key for that hostname. Use the same value for the config’s `origin` and the client’s `SHOMEI_PROXY`. For local TLS and sample stacks, follow the [quickstart](README.md#quickstart).
3. Copy `shomei.example.toml` to `local/config/shomei.toml` and configure a reverse upstream, forward scope, or direct Tailscale SSH approval. For forward-only, keep the HTTPS authorization listener and remove the reverse upstream settings. [Example configuration](shomei.example.toml)
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

To keep some paths public, use ingress routing to send only the protected paths and `/_shomei` to Shomei. Keep the protected backend private. All paths served by Shomei's reverse proxy require authentication.

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

Add `protected_paths` at the top level to leave the rest of the site public. Listed paths and descendants require a fresh assertion on every request. Matching is case-insensitive, and ambiguous paths also require approval. Include any application route aliases that reach the protected handler.

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

## Forward HTTP, HTTPS, and TCP

Configure `cidrs` and `ports` in each `[forward.scopes.NAME]`. Optional `dns_suffixes` require a matching DNS name and resolved IP. All enrolled keys can approve all scopes. With one scope, omit `--scope`. With several, select `--scope NAME` when approving.

Set `allow_all = true` in place of CIDRs, DNS suffixes, and ports to allow all reachable destinations. TCP can use any port. Enable `forward.http_bind` for HTTP and HTTPS clients. Plain HTTP checks `http_ports` when configured and defaults to port 80 for restricted scopes. HTTPS CONNECT checks `https_ports` (default 443). Keep those ports limited to HTTPS services because the tunnel can carry any TCP protocol. Keep deployment backends that require per-request approval outside unrestricted egress. [Example configuration](shomei.example.toml)

```sh
approval="$(shomei sign --proxy "$SHOMEI_PROXY" --forward)" &&
  curl --proxy https://shomei.example.com:9445 \
    --proxy-header "Proxy-Authorization: Shomei $approval" \
    https://status.internal.example.com/
```

Pass `--session` to issue a reusable forward session, and send it as `Proxy-Authorization: Shomei-Session <token>`. Reverse browser WebAuthn uses cookies. For a private proxy CA, pass `--proxy-cacert "$SHOMEI_CA_FILE"` to curl.

Expose `forward.public_port` (9444 by default) as raw TCP on the authorization hostname. Shomei verifies mTLS certificates on this listener.

```sh
shomei mtls --proxy "$SHOMEI_PROXY" --out ./fleet-cert
shomei connect --credentials ./fleet-cert --listen 127.0.0.1:15432 db.internal.example.com:5432
```

For SSH, run `shomei ssh --proxy "$SHOMEI_PROXY" --credentials ./fleet-cert ubuntu@host.internal.example.com`. Existing SSH host-key checks and user authentication apply. Use `connect` without `--credentials` or `ssh --forward` to approve a new in-memory certificate. `connect` listens on loopback, where any local process can use the port. Treat the exported directory as private. Active tunnels close on expiry or allowlist revocation.

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

## Approve direct Tailscale SSH

Use a Premium or Enterprise tailnet. Run `shomei serve /etc/shomei/shomei.toml` on the gateway node with access to its `tailscaled` Unix socket. Bind `https_bind` to the node’s Tailscale IP, allow ingress to that port only via Tailscale, and use a TLS certificate for the gateway’s MagicDNS name. Run the service with permission to read the LocalAPI socket and the OAuth secret file. [Tailscale just-in-time access](https://tailscale.com/docs/features/tailscale-accessbot-jit)

Create a Tailscale OAuth client with the `devices:posture_attributes` write scope. Put the client secret in a file readable only by the service user. Set the following alongside the normal origin, TLS, state, and allowlist settings. For an approval-only gateway, omit `http_upstream` and `[tcp]`. Enroll keys for this gateway’s HTTPS origin.

```toml
[tailscale_ssh]
target = "deploy.example.ts.net"
posture_attribute = "custom:shomei_ssh_deploy"
oauth_client_id = "your-oauth-client-id"
oauth_client_secret_file = "/etc/shomei/tailscale-oauth-secret"
socket = "/var/run/tailscale/tailscaled.sock"
ttl_seconds = 300
```

Enable Tailscale SSH on `deploy`. In the tailnet policy, allow your users to reach the approval endpoint and require the approval attribute on every grant that gives them TCP port 22 on `deploy`. Include your existing device checks in the same posture definition as the approval assertion. Entries in `srcPosture` are alternatives. Keep the SSH `check` rule for the caller’s existing login and re-authentication policy. [Tailscale posture rules](https://tailscale.com/docs/features/device-posture/postures-in-access-rules) · [Tailscale SSH policy](https://tailscale.com/docs/reference/syntax/policy-file#tailscale-ssh)

Choose your caller group and destination tags in the tailnet policy. Replace the example `group:ops`, `tag:shomei`, and `tag:deploy` with your own selectors for the callers, gateway, and configured target. Scope the target selector to that device. Match the custom attribute to `posture_attribute` and replace the auto-update check with your existing posture assertions.

```json
{
  "postures": {
    "posture:approvedDeploy": ["node:tsAutoUpdate == true", "custom:shomei_ssh_deploy == true"]
  },
  "grants": [
    { "src": ["group:ops"], "dst": ["tag:shomei"], "ip": ["tcp:8443"] },
    { "src": ["group:ops"], "dst": ["tag:deploy"], "ip": ["tcp:22"], "srcPosture": ["posture:approvedDeploy"] }
  ],
  "ssh": [
    { "action": "check", "src": ["group:ops"], "dst": ["tag:deploy"], "users": ["ubuntu"], "checkPeriod": "always" }
  ]
}
```

From the caller’s Tailscale device, use the configured target’s full MagicDNS name. Verify its SSH host key through your usual trusted channel.

```sh
shomei ssh --tailscale --proxy https://shomei.example.ts.net:8443 ubuntu@deploy.example.ts.net
```

After a successful YubiKey approval, Shomei sets the device’s attribute to expire in `ttl_seconds` (default 300, range 1–3600). Each fresh approval starts a new window. Tailscale removes the attribute automatically at expiry. Removing a YubiKey from the Shomei allowlist blocks new approvals. To revoke an approval early, remove the device’s approval attribute in Tailscale. [Tailscale attribute expiry](https://tailscale.com/docs/features/tailscale-accessbot-jit#set-custom-posture-attributes-by-using-the-api)

## Verify the integration

- For HTTP, check that an unauthenticated API request returns `401` and a browser `GET` redirects to login. Approve one request and verify it reaches the intended upstream.
- For SSH, check that the upstream port is private and a plain SSH client fails against the mTLS port. Run `shomei ssh` with the enrolled key and confirm that the upstream returns the expected user.
