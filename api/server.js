"use strict";

const { createServer } = require("node:http");
const { createPrivateKey } = require("node:crypto");
const { createFirebaseTokenVerifier } = require("./auth");
const { createHandler } = require("./app");

const projectId = process.env.FIREBASE_PROJECT_ID || "el-llamado-de-samuel";
const adminEmail = (process.env.ADMIN_EMAIL || "yulibethame@gmail.com").trim().toLowerCase();
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

function loadPrivateJwk() {
  const value = process.env.LICENSE_PRIVATE_JWK;
  if (!value) {
    throw new Error("Set LICENSE_PRIVATE_JWK in the Render environment.");
  }
  try {
    const privateJwk = JSON.parse(value);
    if (privateJwk.kty !== "EC" || privateJwk.crv !== "P-256" || !privateJwk.d) {
      throw new Error("Invalid P-256 private JWK.");
    }
    createPrivateKey({ key: privateJwk, format: "jwk" });
    return privateJwk;
  } catch (error) {
    throw new Error("LICENSE_PRIVATE_JWK must be a valid P-256 private JWK.", { cause: error });
  }
}

if (!allowedOrigins.size) {
  throw new Error("Set ALLOWED_ORIGINS to the HTTPS origin of the hosted app.");
}
for (const origin of allowedOrigins) {
  const url = new URL(origin);
  if (url.origin !== origin || (url.protocol !== "https:" && url.hostname !== "localhost")) {
    throw new Error(`ALLOWED_ORIGINS contains an invalid origin: ${origin}`);
  }
}

const handler = createHandler({
  verifyIdToken: createFirebaseTokenVerifier(projectId),
  privateJwk: loadPrivateJwk(),
  allowedOrigins,
  adminEmail,
});
const server = createServer((request, response) => {
  Promise.resolve(handler(request, response)).catch((error) => {
    console.error("License API request failed.", error);
    if (!response.headersSent) {
      response.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      response.end(JSON.stringify({ error: "Error interno del servidor." }));
    } else {
      response.destroy();
    }
  });
});
const port = Number(process.env.PORT) || 10000;

server.listen(port, "0.0.0.0", () => {
  console.log(`License API listening on port ${port}.`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
