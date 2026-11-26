const button = document.querySelector("[data-action]");
const notice = document.querySelector("#status");
const tap = "Tap your YubiKey to continue.";
let challenge;
let busy = false;

async function json(response) {
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status}).`);
  return value;
}

async function post(path, body) {
  return json(await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
  }));
}

function decode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (byte) => byte.charCodeAt(0));
}

function encode(value) {
  if (value == null) return null;
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

async function prepare() {
  const { challenge_id, publicKey } = await post("/_shomei/api/auth/start", {});
  challenge = {
    id: challenge_id,
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
}

function destination() {
  const next = new URLSearchParams(location.search).get("next") || "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  const target = new URL(location.origin + next);
  return target.pathname.startsWith("/_shomei") ? "/" : target.href;
}

async function run() {
  if (busy) return;
  busy = true;
  const controller = new AbortController();
  if (button) button.disabled = true;
  try {
    if (!challenge || Date.now() - challenge.loadedAt > 100_000) {
      if (button) notice.textContent = "Preparing YubiKey approval…";
      await prepare();
    }
    notice.textContent = tap;
    const prompt = navigator.credentials.get({
      publicKey: {
        ...challenge.publicKey,
        timeout: Math.min(challenge.publicKey.timeout ?? 90_000, 90_000, 115_000 - (Date.now() - challenge.loadedAt)),
      },
      mediation: "required",
      signal: controller.signal,
    });
    const confirmation = button && fetch("/_shomei/api/action", {
      redirect: "error", signal: controller.signal,
    }).then(json);
    const [credential, currentAction] = await Promise.all([prompt, confirmation]);
    if (!credential) throw new DOMException("Approval canceled", "NotAllowedError");

    const signed = { challenge_id: challenge.id, credential: assertion(credential) };
    challenge = undefined;
    notice.textContent = "Verifying YubiKey approval…";
    if (button) {
      const authorization = encode(new TextEncoder().encode(JSON.stringify(signed)));
      const result = await json(await fetch(currentAction.path, {
        method: "POST",
        headers: { Authorization: `Shomei ${authorization}`, Accept: "application/json" },
        redirect: "error",
      }));
      notice.textContent = result.message || "Request approved.";
    } else {
      await post("/_shomei/api/auth/finish", signed);
      location.assign(destination());
    }
  } catch (error) {
    if (["NotAllowedError", "AbortError"].includes(error.name)) {
      notice.textContent = button
        ? "Approval canceled or timed out. Select the action to try again."
        : "Click the page or press Enter to open the YubiKey prompt.";
    } else {
      notice.textContent = error.message;
    }
  } finally {
    controller.abort();
    busy = false;
    if (button) button.disabled = false;
  }
}

async function start() {
  if (!window.isSecureContext || typeof PublicKeyCredential === "undefined" || !navigator.credentials?.get) {
    notice.textContent = "Open this page over HTTPS in a browser with WebAuthn support.";
    return;
  }
  if (button) {
    button.addEventListener("click", run);
    try {
      const action = await json(await fetch("/_shomei/api/action", { redirect: "error" }));
      button.textContent = action.label;
      await prepare();
      notice.textContent = "";
    } catch (error) {
      notice.textContent = error.message;
    }
    button.disabled = false;
  } else {
    document.addEventListener("click", (event) => {
      if (!event.target.closest("a")) run();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.target.closest("a")) run();
    });
    if (document.visibilityState === "visible") {
      run();
    } else {
      document.addEventListener("visibilitychange", function visible() {
        if (document.visibilityState !== "visible") return;
        document.removeEventListener("visibilitychange", visible);
        run();
      });
    }
  }
}

start();
