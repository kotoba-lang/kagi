const bytes = (value, name) => {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError(`${name} must be bytes`);
};

export const base64url = (value) =>
  Buffer.from(bytes(value, "value")).toString("base64url");

const random = (crypto, size) => {
  const out = new Uint8Array(size);
  crypto.getRandomValues(out);
  return out;
};

const extensionResult = (credential) => {
  const result = credential.getClientExtensionResults?.()?.prf;
  const first = result?.results?.first;
  if (!first) throw new Error("WebAuthn PRF output unavailable");
  return bytes(first, "PRF output");
};

export async function authenticatePrf({credentials, rpId, credentialId, salt}) {
  if (!credentials?.get) throw new Error("WebAuthn unavailable");
  const credential = await credentials.get({publicKey: {
    challenge: random(globalThis.crypto, 32),
    rpId,
    allowCredentials: [{type: "public-key", id: bytes(credentialId, "credentialId")}],
    userVerification: "required",
    extensions: {prf: {eval: {first: bytes(salt, "salt")}}},
  }});
  if (!credential) throw new Error("WebAuthn authentication cancelled");
  return {rpId, credentialId: bytes(credential.rawId, "rawId"), salt: bytes(salt, "salt"),
          prfOutput: extensionResult(credential)};
}

export async function registerPrf({credentials, rpId, userId, userName}) {
  if (!credentials?.create) throw new Error("WebAuthn unavailable");
  const salt = random(globalThis.crypto, 32);
  const credential = await credentials.create({publicKey: {
    challenge: random(globalThis.crypto, 32),
    rp: {id: rpId, name: "kagi"},
    user: {id: bytes(userId, "userId"), name: userName, displayName: userName},
    pubKeyCredParams: [{type: "public-key", alg: -7}, {type: "public-key", alg: -8}],
    authenticatorSelection: {residentKey: "required", userVerification: "required"},
    attestation: "none",
    extensions: {prf: {eval: {first: salt}}},
  }});
  if (!credential) throw new Error("WebAuthn registration cancelled");
  const enabled = credential.getClientExtensionResults?.()?.prf?.enabled;
  if (enabled !== true) throw new Error("authenticator does not support WebAuthn PRF");
  return authenticatePrf({credentials, rpId, credentialId: credential.rawId, salt});
}

export const bridgeEnvelopeInput = ({rpId, credentialId, salt, prfOutput}) => ({
  rpId,
  credentialId: base64url(credentialId),
  prfSalt: base64url(salt),
  prfOutput: base64url(prfOutput),
  secret: true,
});
