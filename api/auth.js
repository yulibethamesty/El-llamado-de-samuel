"use strict";

const { createRemoteJWKSet, jwtVerify } = require("jose");

const FIREBASE_JWKS_URL = new URL(
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
);

function createFirebaseTokenVerifier(projectId, jwks = createRemoteJWKSet(FIREBASE_JWKS_URL)) {
  if (typeof projectId !== "string" || !projectId) {
    throw new TypeError("FIREBASE_PROJECT_ID must be configured.");
  }

  const issuer = `https://securetoken.google.com/${projectId}`;
  return async (token) => {
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ["RS256"],
      audience: projectId,
      issuer,
    });
    const now = Math.floor(Date.now() / 1000);
    if (
      typeof payload.sub !== "string" ||
      !payload.sub ||
      payload.sub.length > 128 ||
      !Number.isSafeInteger(payload.auth_time) ||
      payload.auth_time > now ||
      !Number.isSafeInteger(payload.iat) ||
      payload.iat > now ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= now
    ) {
      throw new Error("Firebase ID token claims are invalid.");
    }
    return payload;
  };
}

module.exports = { createFirebaseTokenVerifier };
