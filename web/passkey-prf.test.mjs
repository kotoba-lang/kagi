import test from "node:test";
import assert from "node:assert/strict";
import {authenticatePrf, bridgeEnvelopeInput, registerPrf} from "./passkey-prf.mjs";

const rawId = new Uint8Array([1, 2, 3]);
const prf = new Uint8Array(32).fill(7);
const credential = (extensions) => ({rawId, getClientExtensionResults: () => extensions});

test("registration requires PRF and immediately obtains bound output", async () => {
  const calls = [];
  const credentials = {
    create: async (options) => (calls.push(options), credential({prf: {enabled: true}})),
    get: async (options) => (calls.push(options),
      credential({prf: {results: {first: prf.buffer}}})),
  };
  const result = await registerPrf({credentials, rpId: "vault.example",
                                    userId: new Uint8Array([9]), userName: "fixture"});
  assert.deepEqual(result.prfOutput, prf);
  assert.equal(calls[0].publicKey.rp.id, "vault.example");
  assert.equal(calls[1].publicKey.rpId, "vault.example");
  assert.equal(calls[1].publicKey.userVerification, "required");
});

test("unsupported or missing PRF fails closed", async () => {
  await assert.rejects(registerPrf({credentials: {create: async () => credential({prf: {enabled: false}})},
                                    rpId: "vault.example", userId: new Uint8Array([1]),
                                    userName: "fixture"}), /does not support/);
  await assert.rejects(authenticatePrf({credentials: {get: async () => credential({})},
                                        rpId: "vault.example", credentialId: rawId,
                                        salt: new Uint8Array(32)}), /output unavailable/);
});

test("bridge output is explicit secret material and JSON-safe", () => {
  const value = bridgeEnvelopeInput({rpId: "vault.example", credentialId: rawId,
                                     salt: new Uint8Array(32).fill(4), prfOutput: prf});
  assert.deepEqual(Object.keys(value).sort(), ["credentialId", "prfOutput", "prfSalt", "rpId", "secret"]);
  assert.equal(value.secret, true);
  assert.doesNotMatch(JSON.stringify(value), /\[7,7,7/);
});
