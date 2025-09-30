import crypto from "node:crypto";

// Decrypt WhatsApp Flow envelope using AES-256-GCM
export function decryptRequest(envelope, rsaPem) {
  const aesKey = crypto.privateDecrypt(
    { key: rsaPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(envelope.encrypted_aes_key, "base64")
  );

  const iv  = Buffer.from(envelope.initial_vector, "base64");
  const enc = Buffer.from(envelope.encrypted_flow_data, "base64");
  const tag = enc.subarray(enc.length - 16);
  const ct  = enc.subarray(0, enc.length - 16);

  const dec = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  dec.setAuthTag(tag);
  const plaintext = Buffer.concat([dec.update(ct), dec.final()]);
  return { body: JSON.parse(plaintext.toString("utf8")), aesKey, iv };
}

// Encrypt response using AES-256-GCM and flipped IV, return base64(ciphertext||tag)
export function encryptResponse(obj, aesKey, requestIv) {
  const flippedIv = Buffer.from(requestIv.map(b => b ^ 0xff)); // XOR 0xFF
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, flippedIv);
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const c1 = cipher.update(json);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([c1, c2, tag]).toString("base64"); // single Base64 string
}

// Self-test: decrypt our own response with flipped IV
export function selfTest(b64, aesKey, iv) {
  const flippedIv = Buffer.from(iv.map(b => b ^ 0xff));
  const buf = Buffer.from(b64, "base64");
  const tag = buf.subarray(buf.length - 16);
  const ct  = buf.subarray(0, buf.length - 16);
  const dec = crypto.createDecipheriv("aes-256-gcm", aesKey, flippedIv);
  dec.setAuthTag(tag);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  return plain.toString("utf8"); // should print OK JSON
}
