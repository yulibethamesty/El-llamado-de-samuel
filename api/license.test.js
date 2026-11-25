"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { createActivationKey, validateActivation } = require("./license");

test("creates a P-256 key accepted by the app's Web Crypto verifier", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicJwk = publicKey.export({ format: "jwk" });
  const activation = validateActivation({
    code: "SAM-4829",
    church: " Iglesia Ejemplo ",
    expires: "2027-12-31",
  });

  const [encodedPayload, encodedSignature] = createActivationKey(activation, privateJwk).split(".");
  const payload = Buffer.from(encodedPayload, "base64url").toString("utf8");
  const signature = Buffer.from(encodedSignature, "base64url");
  const verifyKey = crypto.createPublicKey({ key: publicJwk, format: "jwk" });

  assert.equal(payload, "SAM-4829|Iglesia Ejemplo|2027-12-31");
  assert.equal(signature.length, 64);
  assert.equal(
    crypto.verify(
      "sha256",
      Buffer.from(payload),
      { key: verifyKey, dsaEncoding: "ieee-p1363" },
      signature
    ),
    true
  );
});

test("rejects malformed or ambiguous activation input", () => {
  assert.throws(
    () => validateActivation({ code: "SAM-12", church: "Iglesia", expires: "2027-12-31" }),
    /formato/
  );
  assert.throws(
    () => validateActivation({ code: "SAM-4829", church: "A|B", expires: "2027-12-31" }),
    /caracteres/
  );
  assert.throws(
    () => validateActivation({ code: "SAM-4829", church: "Iglesia", expires: "2027-02-30" }),
    /fecha/
  );
});
