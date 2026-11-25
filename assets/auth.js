const form = document.querySelector("form");
const account = form.querySelector("#account");
const button = form.querySelector("button");
const notice = document.querySelector("#status");
let prepared;
let revision = 0;
let inputTimer;

async function post(path, body) {
  const response = await fetch(`/_shomei/api/auth/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
  });
  if (response.ok) return response.json();
  const result = await response.json().catch(() => ({}));
  throw new Error(result.error || `Request failed (${response.status}).`);
}

function decode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (byte) => byte.charCodeAt(0));
}

function encode(value) {
  if (value === null) return null;
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function assertion(credential) {
  const { authenticatorData, clientDataJSON, signature, userHandle } = credential.response;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      authenticatorData: encode(authenticatorData),
      clientDataJSON: encode(clientDataJSON),
      signature: encode(signature),
      userHandle: encode(userHandle),
    },
  };
}

async function prepare(message = "") {
  const current = ++revision;
  prepared = undefined;
  button.disabled = true;
  if (!window.isSecureContext || typeof PublicKeyCredential === "undefined" || !navigator.credentials?.get) {
    notice.textContent = "Open this page over HTTPS in a browser with WebAuthn support.";
    return;
  }
  notice.textContent = message || "Preparing sign-in…";
  try {
    const name = account.value.trim();
    const { challenge_id, publicKey } = await post("start", name ? { account: name } : {});
    if (current !== revision) return;
    prepared = {
      challenge_id,
      loadedAt: Date.now(),
      publicKey: {
        ...publicKey,
        challenge: decode(publicKey.challenge),
        allowCredentials: publicKey.allowCredentials.map(({ id, ...descriptor }) => ({
          ...descriptor,
          id: decode(id),
          transports: descriptor.transports || ["usb", "nfc"],
        })),
        hints: ["security-key"],
      },
    };
    button.disabled = false;
    notice.textContent = message;
  } catch (error) {
    if (current === revision) notice.textContent = error.message;
  }
}

function destination() {
  const next = new URLSearchParams(location.search).get("next") || "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  const target = new URL(location.origin + next);
  return target.pathname.startsWith("/_shomei") ? "/" : target.href;
}

account.addEventListener("input", () => {
  revision++;
  prepared = undefined;
  button.disabled = true;
  notice.textContent = "Preparing sign-in…";
  clearTimeout(inputTimer);
  inputTimer = setTimeout(prepare, 250);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!prepared) return;
  const { challenge_id, loadedAt, publicKey } = prepared;
  if (Date.now() - loadedAt > 105_000) {
    await prepare("Sign-in refreshed. Select Use YubiKey again.");
    return;
  }
  prepared = undefined;
  button.disabled = true;
  account.disabled = true;
  notice.textContent = "Follow the prompt, then touch your YubiKey.";
  try {
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) throw new Error("YubiKey sign-in canceled.");
    await post("finish", { challenge_id, credential: assertion(credential) });
    location.assign(destination());
  } catch (error) {
    account.disabled = false;
    const message = error.name === "NotAllowedError"
      ? "YubiKey prompt canceled or timed out. Select Use YubiKey to try again."
      : error.message;
    await prepare(message);
  }
});

prepare();
