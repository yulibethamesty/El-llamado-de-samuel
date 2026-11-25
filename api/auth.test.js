"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { createLocalJWKSet, exportJWK, SignJWT } = require("jose");
const { createFirebaseTokenVerifier } = require("./auth");

const PROJECT_ID = "el-llamado-de-samuel";
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;

async function createToken(privateKey, claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    sub: "admin-user-id",
    auth_time: now - 60,
    email: "yulibethame@gmail.com",
    email_verified: true,
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(ISSUER)
    .setAudience(PROJECT_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

test("verifies Firebase ID token signature, audience, issuer, and time claims", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicJwk = await exportJWK(publicKey);
  const verifier = createFirebaseTokenVerifier(
    PROJECT_ID,
    createLocalJWKSet({ keys: [{ ...publicJwk, kid: "test-key", alg: "RS256", use: "sig" }] })
  );

  const token = await createToken(privateKey);
  const payload = await verifier(token);
  assert.equal(payload.email, "yulibethame@gmail.com");
  assert.equal(payload.email_verified, true);

  const wrongAudience = await new SignJWT({ sub: "admin-user-id", auth_time: Math.floor(Date.now() / 1000) })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(ISSUER)
    .setAudience("different-project")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
  await assert.rejects(() => verifier(wrongAudience), /aud|claim/i);
});
