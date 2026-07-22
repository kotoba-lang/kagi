# v0.5.0 security review delta

Status: ready for independent review; external audit not yet performed.

Review `kagi.passkey-bridge` and `unlock-enable-passkey`. Confirm loopback-only binding,
high-entropy one-shot token handling, exact Origin checks, CSP/cache headers, timeout behavior,
replay rejection and shutdown ordering. Exercise DNS rebinding, malformed JSON, oversized bodies,
slow requests and browser navigation edge cases.

The request body is capped at 64 KiB and the entire bridge expires after 120 seconds. A distinct
per-read socket timeout is not available on the JDK `HttpServer`; reviewers should assess whether
the global expiry and forced server stop are sufficient for the loopback threat model.
