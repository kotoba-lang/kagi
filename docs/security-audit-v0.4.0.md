# v0.4.0 security review delta

Status: ready for independent review; external audit not yet performed.

Review `web/passkey-prf.mjs`, `web/passkey-app.mjs` and `kagi.passkey`. Confirm that WebAuthn
PRF support is required, user verification is required, RP/credential/salt bindings survive the
browser-to-JVM bridge, and PRF output is neither rendered nor persisted. Test with real platform
and roaming authenticators across supported browsers.

Known limitation: the HTML surface requires a trusted host to provide `window.kagiPasskeyBridge`;
shipping and authenticating that native/local bridge is application integration work.
