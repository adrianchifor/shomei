import { post, prepareApproval, signApproval, supportsWebAuthn } from "/_shomei/webauthn.js";

const notice = document.querySelector("#status");
const query = new URLSearchParams(location.search);
const app = query.get("app");
const next = query.get("next") || "/";
let busy = false;

function destination() {
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  const target = new URL(location.origin + next);
  return target.pathname.startsWith("/_shomei") ? "/" : target.href;
}

async function run() {
  if (busy) return;
  busy = true;
  try {
    notice.textContent = "Tap your YubiKey to continue.";
    const approval = await prepareApproval(app ? { browser_login: { app, next } } : {});
    const signed = await signApproval(approval);
    notice.textContent = "Verifying YubiKey approval…";
    const result = await post("/_shomei/api/auth/finish", signed);
    location.assign(result.redirect || destination());
  } catch (error) {
    notice.textContent = ["NotAllowedError", "AbortError"].includes(error.name)
      ? "Click the page or press Enter to open the YubiKey prompt."
      : error.message;
  } finally {
    busy = false;
  }
}

function start() {
  if (!supportsWebAuthn()) {
    notice.textContent = "Open this page over HTTPS in a browser with WebAuthn support.";
    return;
  }
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

start();
