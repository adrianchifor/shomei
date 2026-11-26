import { authorizationHeader, prepareApproval, readJson, signApproval, supportsWebAuthn } from "/_shomei/webauthn.js";

const button = document.querySelector("button");
const status = document.querySelector("#status");
let approval;

async function prepare() {
  try {
    approval = await prepareApproval();
  } catch (error) {
    status.textContent = error.message;
  }
  button.disabled = false;
}

button.addEventListener("click", async () => {
  button.disabled = true;
  try {
    if (!approval || Date.now() - approval.loadedAt > 100_000) {
      approval = await prepareApproval();
    }
    status.textContent = "Tap your YubiKey to approve the deploy.";
    const signed = await signApproval(approval);
    const result = await readJson(await fetch("/api/deploy", {
      method: "POST",
      headers: { Authorization: authorizationHeader(signed), Accept: "application/json" },
      redirect: "error",
    }));
    status.textContent = result.message;
  } catch (error) {
    status.textContent = error.name === "NotAllowedError" ? "Approval canceled. Try again." : error.message;
  } finally {
    approval = undefined;
    await prepare();
  }
});

if (supportsWebAuthn()) {
  prepare();
} else {
  status.textContent = "Open this page over HTTPS in a browser with WebAuthn support.";
}
