const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function bytes(value, name, length) {
  const out = value instanceof Uint8Array ? value : new Uint8Array(value || []);
  if (length && out.byteLength !== length) throw new Error(`${name} must be ${length} bytes`);
  return out;
}

function random32(cryptoApi) {
  const out = new Uint8Array(32);
  cryptoApi.getRandomValues(out);
  return out;
}

function equalBytes(left, right) {
  const a = bytes(left, "left");
  const b = bytes(right, "right");
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function base64url(value) {
  let binary = "";
  for (const octet of bytes(value, "value")) binary += String.fromCharCode(octet);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function expectedOrigin(locationLike) {
  if (locationLike?.origin) return locationLike.origin;
  const port = locationLike?.port ? `:${locationLike.port}` : "";
  return `${locationLike.protocol}//${locationLike.hostname}${port}`;
}

function verifyClientData(response, challenge, locationLike, expectedType) {
  if (!response?.clientDataJSON) throw new Error("WebAuthn response has no client data");
  let data;
  try {
    data = JSON.parse(new TextDecoder().decode(bytes(response.clientDataJSON, "clientDataJSON")));
  } catch {
    throw new Error("WebAuthn client data is invalid");
  }
  if (data.type !== expectedType) throw new Error("WebAuthn client data has the wrong ceremony type");
  if (data.challenge !== base64url(challenge)) throw new Error("WebAuthn challenge mismatch");
  if (data.origin !== expectedOrigin(locationLike) || data.crossOrigin === true) {
    throw new Error("WebAuthn origin mismatch");
  }
}

function verifyAssertionFlags(response) {
  const authenticatorData = bytes(response?.authenticatorData, "authenticatorData");
  if (authenticatorData.byteLength < 37) throw new Error("WebAuthn authenticator data is invalid");
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0) throw new Error("WebAuthn user presence is required");
  if ((flags & 0x04) === 0) throw new Error("WebAuthn user verification is required");
}

export function assertRpContext(locationLike, rpId) {
  const host = locationLike?.hostname;
  const secure = locationLike?.protocol === "https:" || LOCAL_HOSTS.has(host);
  if (!secure) throw new Error("Passkey PRF requires a secure context");
  if (!rpId || !(host === rpId || host?.endsWith(`.${rpId}`))) {
    throw new Error("RP ID is not bound to the current origin");
  }
}

export async function registerPasskeyPrf({
  navigator: nav = globalThis.navigator,
  location: loc = globalThis.location,
  crypto: cryptoApi = globalThis.crypto,
  rpId, userId, username, displayName = username, salt,
}) {
  assertRpContext(loc, rpId);
  if (!nav?.credentials?.create) throw new Error("WebAuthn is unavailable");
  const prfSalt = bytes(salt, "PRF salt", 32);
  const challenge = random32(cryptoApi);
  const credential = await nav.credentials.create({
    publicKey: {
      rp: { id: rpId, name: "kagi" },
      user: { id: bytes(userId, "userId"), name: username, displayName },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 },
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  if (credential?.type !== "public-key" || !credential?.rawId) {
    throw new Error("Passkey registration returned no public-key credential ID");
  }
  verifyClientData(credential.response, challenge, loc, "webauthn.create");
  const extension = credential.getClientExtensionResults?.().prf;
  if (extension?.enabled !== true) throw new Error("Authenticator did not enable WebAuthn PRF");
  return { credentialId: new Uint8Array(credential.rawId), rpId };
}

export async function withPasskeyPrf({
  navigator: nav = globalThis.navigator,
  location: loc = globalThis.location,
  crypto: cryptoApi = globalThis.crypto,
  rpId, credentialId, salt,
}, use) {
  assertRpContext(loc, rpId);
  if (typeof use !== "function") throw new Error("local PRF consumer is required");
  if (!nav?.credentials?.get) throw new Error("WebAuthn is unavailable");
  const expectedCredentialId = bytes(credentialId, "credentialId");
  const challenge = random32(cryptoApi);
  const credential = await nav.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [{ type: "public-key", id: expectedCredentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: bytes(salt, "PRF salt", 32) } } },
    },
  });
  if (credential?.type !== "public-key" || !credential?.rawId ||
      !equalBytes(credential.rawId, expectedCredentialId)) {
    throw new Error("WebAuthn returned an unexpected credential");
  }
  verifyClientData(credential.response, challenge, loc, "webauthn.get");
  verifyAssertionFlags(credential.response);
  const result = credential?.getClientExtensionResults?.().prf?.results?.first;
  if (!result) throw new Error("Authenticator did not return WebAuthn PRF output");
  const output = bytes(result, "PRF output", 32);
  try {
    return await use(output);
  } finally {
    output.fill(0);
  }
}
