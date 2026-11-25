"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createServer } = require("node:http");
const test = require("node:test");
const { createHandler } = require("./app");

const ADMIN = "yulibethame@gmail.com";
const ORIGIN = "https://el-llamado-de-samuel.web.app";

async function withServer(handler, callback) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    await callback(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

function makeHandler(verifyIdToken) {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return createHandler({
    verifyIdToken,
    privateJwk: privateKey.export({ format: "jwk" }),
    allowedOrigins: new Set([ORIGIN]),
    adminEmail: ADMIN,
  });
}

test("generates a key only for the verified administrator", async () => {
  const handler = makeHandler(async () => ({ email: ADMIN, email_verified: true }));
  await withServer(handler, async (url) => {
    const response = await fetch(`${url}/api/generate-activation`, {
      method: "POST",
      headers: {
        authorization: "Bearer valid-token",
        "content-type": "application/json",
        origin: ORIGIN,
      },
      body: JSON.stringify({ code: "SAM-4829", church: "Iglesia Ejemplo", expires: "2027-12-31" }),
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(typeof body.key, "string");
    assert.equal(response.headers.get("access-control-allow-origin"), ORIGIN);
  });
});

test("rejects missing credentials, unverified administrators, and untrusted origins", async () => {
  const handler = makeHandler(async () => ({ email: ADMIN, email_verified: false }));
  await withServer(handler, async (url) => {
    const missingToken = await fetch(`${url}/api/generate-activation`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: "{}",
    });
    assert.equal(missingToken.status, 401);

    const unverified = await fetch(`${url}/api/generate-activation`, {
      method: "POST",
      headers: {
        authorization: "Bearer valid-token",
        "content-type": "application/json",
        origin: ORIGIN,
      },
      body: JSON.stringify({ code: "SAM-4829", church: "Iglesia", expires: "2027-12-31" }),
    });
    assert.equal(unverified.status, 403);

    const untrustedOrigin = await fetch(`${url}/api/generate-activation`, {
      method: "POST",
      headers: {
        authorization: "Bearer valid-token",
        "content-type": "application/json",
        origin: "https://attacker.example",
      },
      body: JSON.stringify({ code: "SAM-4829", church: "Iglesia", expires: "2027-12-31" }),
    });
    assert.equal(untrustedOrigin.status, 403);
  });
});

test("allows browser preflight from the configured website origin", async () => {
  const handler = makeHandler(async () => ({ email: ADMIN, email_verified: true }));
  await withServer(handler, async (url) => {
    const response = await fetch(`${url}/api/generate-activation`, {
      method: "OPTIONS",
      headers: {
        origin: ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), ORIGIN);
    assert.match(response.headers.get("access-control-allow-headers"), /Authorization/i);
  });
});
