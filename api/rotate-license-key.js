"use strict";

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const { generateKeyPairSync } = require("node:crypto");

async function main() {
  const prompt = readline.createInterface({ input: stdin, output: stdout });
  const answer = await prompt.question(
    "This replaces the activation signing key. Existing activation keys will stop working. Type ROTATE to continue: "
  );
  prompt.close();
  if (answer !== "ROTATE") {
    console.log("No changes made.");
    return;
  }

  const indexPath = path.join(__dirname, "..", "index.html");
  const html = fs.readFileSync(indexPath, "utf8");
  const match = html.match(/const VERSION='[^']+',PUB=(\{[^}]+\}),enc=/);
  if (!match) {
    throw new Error("Could not locate the public-key declaration in index.html.");
  }

  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicOnly = {
    kty: "EC",
    crv: "P-256",
    x: publicJwk.x,
    y: publicJwk.y,
  };
  const updated = html.replace(match[1], JSON.stringify(publicOnly));
  fs.writeFileSync(indexPath, updated, "utf8");

  console.log("Updated the public key in index.html.");
  console.log("Set this value as the Render environment variable LICENSE_PRIVATE_JWK; do not publish it:");
  console.log(JSON.stringify(privateJwk));
  console.log("If the secret is lost, rotate again before issuing activation keys.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
