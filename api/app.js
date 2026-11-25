"use strict";

const { createActivationKey, validateActivation } = require("./license");

const MAX_BODY_BYTES = 8192;

function sendJson(response, status, body, corsHeaders) {
  response.writeHead(status, {
    ...corsHeaders,
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(body));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let settled = false;

    request.on("data", (chunk) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        settled = true;
        const error = new Error("La solicitud es demasiado grande.");
        error.statusCode = 413;
        reject(error);
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (settled) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        const error = new Error("El cuerpo de la solicitud debe ser JSON válido.");
        error.statusCode = 400;
        reject(error);
      }
    });
    request.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
  });
}

function createHandler({ verifyIdToken, privateJwk, allowedOrigins, adminEmail }) {
  if (
    typeof verifyIdToken !== "function" ||
    !privateJwk ||
    !(allowedOrigins instanceof Set) ||
    !adminEmail
  ) {
    throw new TypeError("License API configuration is incomplete.");
  }

  const configuredAdmin = adminEmail.trim().toLowerCase();
  return async (request, response) => {
    const origin = request.headers.origin;
    const corsHeaders = { Vary: "Origin" };
    if (origin && allowedOrigins.has(origin)) {
      corsHeaders["Access-Control-Allow-Origin"] = origin;
    } else if (origin) {
      sendJson(response, 403, { error: "Origen no autorizado." }, corsHeaders);
      return;
    }

    const path = new URL(request.url || "/", "http://localhost").pathname;
    if (request.method === "GET" && path === "/healthz") {
      sendJson(response, 200, { status: "ok" }, corsHeaders);
      return;
    }
    if (request.method === "OPTIONS" && path === "/api/generate-activation") {
      if (!origin) {
        sendJson(response, 403, { error: "Origen no autorizado." }, corsHeaders);
        return;
      }
      response.writeHead(204, {
        ...corsHeaders,
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      });
      response.end();
      return;
    }
    if (request.method !== "POST" || path !== "/api/generate-activation") {
      sendJson(response, 404, { error: "Ruta no encontrada." }, corsHeaders);
      return;
    }

    const authorization = request.headers.authorization || "";
    const match = /^Bearer ([^\s]+)$/i.exec(authorization);
    if (!match) {
      sendJson(response, 401, { error: "Inicia sesión con la cuenta administradora." }, corsHeaders);
      return;
    }

    let token;
    try {
      token = await verifyIdToken(match[1]);
    } catch {
      sendJson(response, 401, { error: "La sesión de Firebase no es válida; vuelve a iniciar sesión." }, corsHeaders);
      return;
    }
    if (
      typeof token.email !== "string" ||
      token.email.toLowerCase() !== configuredAdmin ||
      token.email_verified !== true
    ) {
      sendJson(response, 403, { error: "Solo la cuenta administradora verificada puede generar claves." }, corsHeaders);
      return;
    }

    if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] || "")) {
      sendJson(response, 415, { error: "El contenido debe enviarse como JSON." }, corsHeaders);
      return;
    }

    let activation;
    try {
      activation = validateActivation(await readJsonBody(request));
    } catch (error) {
      const status = error.statusCode === 413 ? 413 : 400;
      sendJson(response, status, { error: error.message }, corsHeaders);
      return;
    }

    try {
      const key = createActivationKey(activation, privateJwk);
      sendJson(response, 200, { key }, corsHeaders);
    } catch (error) {
      console.error("Activation key signing failed.", error);
      sendJson(response, 500, { error: "No se pudo firmar la clave de activación." }, corsHeaders);
    }
  };
}

module.exports = { createHandler };
