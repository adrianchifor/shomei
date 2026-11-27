import { post, prepareApproval, signApproval, supportsWebAuthn } from "/_shomei/webauthn.js";

const prefix = "/_shomei";
const header = "X-Shomei-Browser-Approval";
let dialogOpen = false;

// A page from another site could frame the app, hide the prompt and steer a
// click onto the button that asks for approval.
function framedByAnotherSite() {
  try {
    for (let frame = window; frame !== window.top; frame = frame.parent) {
      if (frame.parent.location.origin !== location.origin) return true;
    }
    return false;
  } catch {
    return true;
  }
}

// The whole target is shown, however long: a cut-off prompt would hide part
// of what the touch approves.
function describe(details, withHost) {
  const host = withHost ? String(details.host).replace(/:443$/, "") : "";
  return details.request.method + " " + host + details.request.path;
}

async function authorize(details, signal) {
  if (!supportsWebAuthn()) throw new Error("Open Shomei over HTTPS in a browser with WebAuthn support.");
  const challenge = await prepareApproval({ browser_approval: details }, signal);
  signal?.throwIfAborted();
  const signed = await signApproval(challenge, signal);
  signal?.throwIfAborted();
  return post(prefix + "/api/auth/finish", signed, signal);
}

function popupApproval(gateway, details, dialog, signal) {
  const verify = dialog.querySelector("[data-shomei-verify]");
  const status = dialog.querySelector("#shomei-status");
  const id = crypto.randomUUID();
  const url = new URL(prefix + "/approval-popup", gateway);
  url.search = new URLSearchParams({ id, details: JSON.stringify(details) });
  verify.hidden = false;
  status.textContent = "Open the Shomei prompt to verify your YubiKey.";

  return new Promise((resolve, reject) => {
    let popup;
    const stopped = () => finish(() => reject(new DOMException("Approval canceled", "AbortError")));
    const message = (event) => {
      if (!popup || event.source !== popup || event.origin !== url.origin
        || event.data?.type !== "shomei-approval" || event.data.id !== id
        || event.data.result?.site_origin !== location.origin) return;
      finish(() => resolve(event.data.result));
    };
    const timer = setInterval(() => {
      if (popup?.closed) {
        popup = undefined;
        verify.disabled = false;
        status.textContent = "The prompt closed. Try again or cancel.";
      }
    }, 350);
    function finish(done) {
      clearInterval(timer);
      window.removeEventListener("message", message);
      signal.removeEventListener("abort", stopped);
      popup?.close();
      done();
    }
    verify.addEventListener("click", () => {
      popup = window.open(url, "_blank", "popup,width=420,height=420");
      verify.disabled = !!popup;
      status.textContent = popup ? "Complete approval in the Shomei window." : "Allow popups to open the Shomei prompt.";
    });
    window.addEventListener("message", message);
    signal.addEventListener("abort", stopped, { once: true });
    if (signal.aborted) stopped();
  });
}

async function promptApproval(gateway, details, signal) {
  if (dialogOpen) throw new Error("A YubiKey approval is already open.");
  dialogOpen = true;
  const overlay = document.createElement("div");
  const controller = new AbortController();
  const cancel = () => controller.abort(new DOMException("Approval canceled", "AbortError"));
  signal.addEventListener("abort", cancel, { once: true });
  try {
    signal.throwIfAborted();
    const response = await fetch(prefix + "/approval.html", { signal: controller.signal });
    if (!response.ok) throw new Error("Could not load the Shomei approval dialog.");
    const root = overlay.attachShadow({ mode: "open" });
    root.innerHTML = await response.text();
    const dialog = root.querySelector("dialog");
    dialog.querySelector("[data-shomei-request]").textContent = describe(details, false);
    dialog.querySelector("[data-shomei-cancel]").addEventListener("click", cancel);
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      cancel();
    });
    document.body.append(overlay);
    dialog.showModal();
    return gateway === location.origin
      ? await authorize(details, controller.signal)
      : await popupApproval(gateway, details, dialog, controller.signal);
  } finally {
    signal.removeEventListener("abort", cancel);
    overlay.remove();
    dialogOpen = false;
  }
}

function remembered(prefix, path) {
  try {
    const target = decodeURIComponent(path).toLowerCase();
    let longest = -1;
    let approval = null;
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (!key?.startsWith(prefix)) continue;
      const rule = key.slice(prefix.length).toLowerCase();
      const next = target[rule.length];
      if (rule.length > longest && target.startsWith(rule)
        && (next === undefined || next === "/" || next === ".")) {
        longest = rule.length;
        approval = sessionStorage.getItem(key);
      }
    }
    return approval;
  } catch {
    return null;
  }
}

export async function approvedFetch(input, init) {
  const request = new Request(input, init);
  const target = new URL(request.url);
  if (target.origin !== location.origin) throw new Error("Shomei approval requires a same-origin request.");
  if (framedByAnotherSite()) throw new Error("Shomei approval cannot run inside a frame from another site.");
  const details = { method: request.method, path: target.pathname + target.search };
  const key = "shomei.approval." + details.method + " ";
  let approval = remembered(key, target.pathname);
  const check = await post(prefix + "/api/auth/browser/check", { request: details, approval }, request.signal);
  if (!check.ready) {
    const result = await promptApproval(check.gateway, { host: check.host, request: details }, request.signal);
    if (result.site_origin !== location.origin) throw new Error("Shomei returned approval for a different site.");
    approval = result.approval;
    if (result.reusable && check.scope) {
      try { sessionStorage.setItem(key + check.scope, approval); } catch {}
    }
  }
  const headers = new Headers(request.headers);
  headers.set(header, approval);
  return fetch(new Request(request, { headers, mode: "same-origin", referrerPolicy: "strict-origin" }));
}

if (document.documentElement.hasAttribute("data-shomei-popup")) {
  const verify = document.querySelector("[data-shomei-verify]");
  const status = document.querySelector("#shomei-status");
  const query = new URLSearchParams(location.search);
  try {
    const details = JSON.parse(query.get("details"));
    const opener = window.opener;
    if (!opener || !query.get("id")) throw new Error("Open this prompt from the application.");
    document.querySelector("[data-shomei-request]").textContent = describe(details, true);
    verify.disabled = false;
    verify.addEventListener("click", async () => {
      verify.disabled = true;
      status.textContent = "Tap your YubiKey to continue.";
      try {
        const result = await authorize(details);
        opener.postMessage({ type: "shomei-approval", id: query.get("id"), result }, result.site_origin);
        status.textContent = "Approved. You can close this window.";
      } catch (error) {
        status.textContent = error.message;
        verify.disabled = false;
      }
    });
  } catch (error) {
    status.textContent = error.message;
  }
}
