import {bridgeEnvelopeInput, registerPrf} from "./passkey-prf.mjs";

const status = document.querySelector("#status");
const button = document.querySelector("#register");

button.addEventListener("click", async () => {
  button.disabled = true;
  status.textContent = "Waiting for authenticator…";
  try {
    if (typeof window.kagiPasskeyBridge !== "function")
      throw new Error("trusted kagi host bridge is unavailable");
    const result = await registerPrf({credentials: navigator.credentials,
      rpId: location.hostname, userId: crypto.getRandomValues(new Uint8Array(32)),
      userName: "kagi-owner"});
    await window.kagiPasskeyBridge(bridgeEnvelopeInput(result));
    status.textContent = "Passkey unlock enabled.";
  } catch (error) {
    status.textContent = `Passkey setup failed: ${error.message}`;
  } finally {
    button.disabled = false;
  }
});
