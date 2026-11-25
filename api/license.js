"use strict";

const crypto = require("node:crypto");

function validateActivation(data) {
  const { code, church, expires } = data || {};
  if (typeof code !== "string" || !/^SAM-\d{4}$/.test(code)) {
    throw new TypeError("El código debe tener el formato SAM-4829.");
  }
  if (typeof church !== "string" || !church.trim() || church.length > 60) {
    throw new TypeError("Indica el nombre de la iglesia (máximo 60 caracteres).");
  }
  if (/[|.]/.test(church)) {
    throw new TypeError("El nombre contiene caracteres no permitidos.");
  }
  if (typeof expires !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
    throw new TypeError("La fecha de vencimiento no es válida.");
  }
  const expiry = new Date(`${expires}T00:00:00Z`);
  if (Number.isNaN(expiry.getTime()) || expiry.toISOString().slice(0, 10) !== expires) {
    throw new TypeError("La fecha de vencimiento no es válida.");
  }
  return { code, church: church.trim(), expires };
}

function createActivationKey({ code, church, expires }, privateJwk) {
  if (!privateJwk || privateJwk.kty !== "EC" || privateJwk.crv !== "P-256" || !privateJwk.d) {
    throw new TypeError("La llave de firma debe ser una llave privada EC P-256.");
  }
  const payload = `${code}|${church}|${expires}`;
  const key = crypto.createPrivateKey({ key: privateJwk, format: "jwk" });
  const signature = crypto.sign("sha256", Buffer.from(payload, "utf8"), {
    key,
    dsaEncoding: "ieee-p1363",
  });
  return `${Buffer.from(payload).toString("base64url")}.${signature.toString("base64url")}`;
}

module.exports = { createActivationKey, validateActivation };
