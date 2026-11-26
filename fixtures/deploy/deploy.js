import { approvedFetch } from "/_shomei/approval.js";
import { readJson } from "/_shomei/webauthn.js";

const button = document.querySelector("button");
const status = document.querySelector("#status");
button.disabled = false;

button.addEventListener("click", async () => {
  button.disabled = true;
  try {
    const result = await readJson(await approvedFetch("/api/deploy", {
      method: "POST",
      headers: { Accept: "application/json" },
    }));
    status.textContent = result.message;
  } catch (error) {
    status.textContent = error.name === "AbortError" ? "Approval canceled." : error.message;
  } finally {
    button.disabled = false;
  }
});
