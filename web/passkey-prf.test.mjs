import assert from "node:assert/strict";
import test from "node:test";
import { assertRpContext, registerPasskeyPrf, withPasskeyPrf } from "./passkey-prf.mjs";

const cryptoApi = { getRandomValues(out) { out.fill(7); return out; } };
const location = { protocol: "https:", hostname: "vault.example.com" };

function clientData(type = "webauthn.get", challenge = new Uint8Array(32).fill(7),
                    origin = "https://vault.example.com") {
  return new TextEncoder().encode(JSON.stringify({
    type, challenge: Buffer.from(challenge).toString("base64url"), origin, crossOrigin: false,
  }));
}

function assertionCredential({ id = new Uint8Array([1]), flags = 0x05,
                               data = clientData(), prf = new Uint8Array(32).fill(5) } = {}) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData[32] = flags;
  return {
    type: "public-key", rawId: id,
    response: { clientDataJSON: data, authenticatorData },
    getClientExtensionResults: () => ({ prf: { results: { first: prf.buffer } } }),
  };
}

test("RP ID is origin-bound and cleartext remote origins fail", () => {
  assert.doesNotThrow(() => assertRpContext(location, "example.com"));
  assert.throws(() => assertRpContext(location, "evil.example"), /RP ID/);
  assert.throws(() => assertRpContext({ protocol: "http:", hostname: "example.com" }, "example.com"),
                /secure context/);
});

test("registration requires resident user-verified PRF credential", async () => {
  let options;
  const navigator = { credentials: { async create(value) {
    options = value;
    return { type: "public-key", rawId: new Uint8Array([1, 2, 3]).buffer,
             response: { clientDataJSON: clientData("webauthn.create") },
             getClientExtensionResults: () => ({ prf: { enabled: true } }) };
  } } };
  const result = await registerPasskeyPrf({ navigator, location, crypto: cryptoApi,
    rpId: "example.com", userId: new Uint8Array([9]), username: "user",
    salt: new Uint8Array(32) });
  assert.deepEqual([...result.credentialId], [1, 2, 3]);
  assert.equal(options.publicKey.authenticatorSelection.residentKey, "required");
  assert.equal(options.publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(options.publicKey.attestation, "none");
});

test("PRF output exists only during local callback and is zeroized", async () => {
  let captured;
  const navigator = { credentials: { async get() {
    return assertionCredential();
  } } };
  const value = await withPasskeyPrf({ navigator, location, crypto: cryptoApi,
    rpId: "example.com", credentialId: new Uint8Array([1]), salt: new Uint8Array(32) },
    output => { captured = output; return output[0]; });
  assert.equal(value, 5);
  assert.ok(captured.every(byte => byte === 0));
});

test("missing PRF result fails closed", async () => {
  const navigator = { credentials: { async get() {
    const credential = assertionCredential();
    credential.getClientExtensionResults = () => ({});
    return credential;
  } } };
  await assert.rejects(() => withPasskeyPrf({ navigator, location, crypto: cryptoApi,
    rpId: "example.com", credentialId: new Uint8Array([1]), salt: new Uint8Array(32) },
    () => null), /did not return/);
});

test("assertion binds credential, challenge, origin, UP and UV", async () => {
  const invoke = credential => withPasskeyPrf({
    navigator: { credentials: { get: async () => credential } }, location, crypto: cryptoApi,
    rpId: "example.com", credentialId: new Uint8Array([1]), salt: new Uint8Array(32),
  }, () => null);
  await assert.rejects(() => invoke(assertionCredential({ id: new Uint8Array([2]) })), /unexpected credential/);
  await assert.rejects(() => invoke(assertionCredential({ data: clientData("webauthn.get", new Uint8Array(32)) })), /challenge mismatch/);
  await assert.rejects(() => invoke(assertionCredential({ data: clientData("webauthn.get", undefined, "https://evil.example") })), /origin mismatch/);
  await assert.rejects(() => invoke(assertionCredential({ flags: 0x04 })), /presence/);
  await assert.rejects(() => invoke(assertionCredential({ flags: 0x01 })), /verification/);
});

test("PRF output is zeroized when callback throws", async () => {
  let captured;
  await assert.rejects(() => withPasskeyPrf({
    navigator: { credentials: { get: async () => assertionCredential() } },
    location, crypto: cryptoApi, rpId: "example.com",
    credentialId: new Uint8Array([1]), salt: new Uint8Array(32),
  }, output => { captured = output; throw new Error("consumer failed"); }), /consumer failed/);
  assert.ok(captured.every(byte => byte === 0));
});
