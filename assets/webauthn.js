export function supportsWebAuthn() {
  return window.isSecureContext
    && typeof PublicKeyCredential !== "undefined"
    && !!navigator.credentials?.get;
}

export async function readJson(response) {
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || "Request failed (" + response.status + ").");
  return value;
}

export async function post(path, body) {
  return readJson(await fetch(path, {
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

export async function prepareApproval(request = {}) {
  const { challenge_id, publicKey } = await post("/_shomei/api/auth/start", request);
  return {
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
}

export async function signApproval(approval) {
  const credential = await navigator.credentials.get({
    publicKey: {
      ...approval.publicKey,
      timeout: Math.min(approval.publicKey.timeout ?? 90_000, 90_000, 115_000 - (Date.now() - approval.loadedAt)),
    },
    mediation: "required",
  });
  if (!credential) throw new DOMException("Approval canceled", "NotAllowedError");

  const { authenticatorData, clientDataJSON, signature, userHandle } = credential.response;
  return {
    challenge_id: approval.challenge_id,
    credential: {
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
    },
  };
}

export function authorizationHeader(signed) {
  return "Shomei " + encode(new TextEncoder().encode(JSON.stringify(signed)));
}
