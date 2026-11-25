const enroll = location.pathname === "/_shomei/enroll";
const form = document.querySelector("form");
const token = form.querySelector("input");
const button = form.querySelector("button");
const status = document.querySelector("#status");

if (enroll) {
  document.querySelector("h1").textContent = "Enroll your YubiKey";
  form.querySelector("label").hidden = false;
  token.required = true;
}

async function post(path, body, bearer) {
  const headers = { "Content-Type": "application/json" };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  const response = await fetch(`/_shomei/api/${path}`, {
    method: "POST", headers, body: JSON.stringify(body), redirect: "error",
  });
  if (response.status === 204) return;
  if (response.ok) return response.json();
  const result = await response.json().catch(() => ({}));
  throw new Error(result.error || `Request failed (${response.status}).`);
}

function destination() {
  const next = new URLSearchParams(location.search).get("next") || "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  const target = new URL(location.origin + next);
  if (!target.pathname.startsWith("/_shomei")) {
    return target.href;
  }
  return "/";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = "Follow the prompt, then touch your YubiKey.";
  try {
    if (!window.PublicKeyCredential?.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      throw new Error("Open this page over HTTPS in a browser with WebAuthn support.");
    }
    const flow = enroll ? "enroll" : "auth";
    const bearer = enroll ? token.value.trim() : undefined;
    const { challenge_id, publicKey } = await post(`${flow}/start`, {}, bearer);
    publicKey.hints = ["security-key"];
    const credential = enroll
      ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey) })
      : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey) });
    await post(`${flow}/finish`, { challenge_id, credential: credential.toJSON() }, bearer);
    if (enroll) {
      token.value = "";
      status.textContent = "YubiKey enrolled.";
    } else {
      location.assign(destination());
    }
  } catch (error) {
    status.textContent = error.name === "NotAllowedError" ? "YubiKey prompt canceled or timed out." : error.message;
    button.disabled = false;
  }
});
