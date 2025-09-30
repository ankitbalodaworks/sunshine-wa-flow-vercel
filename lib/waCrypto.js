import crypto from "node:crypto";

// Decrypt WhatsApp Flow envelope using AES-256-GCM
export function decryptRequest({ encrypted_flow_data, encrypted_aes_key, initial_vector }, rsaPem) {
  const aesKey = crypto.privateDecrypt(
    { key: rsaPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(encrypted_aes_key, "base64")
  );
  const iv  = Buffer.from(initial_vector, "base64");
  const flow = Buffer.from(encrypted_flow_data, "base64");

  const tag  = flow.subarray(flow.length - 16);
  const body = flow.subarray(0, flow.length - 16);

  const dec = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  dec.setAuthTag(tag);
  const plaintext = Buffer.concat([dec.update(body), dec.final()]);
  return { payload: JSON.parse(plaintext.toString("utf8")), aesKey, iv };
}

// Encrypt response using AES-256-GCM and flipped IV, return base64(ciphertext||tag)
export function encryptResponse(obj, aesKey, iv) {
  const flippedIv = Buffer.from(iv.map(b => b ^ 0xff));
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, flippedIv);
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const c1 = cipher.update(json);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([c1, c2, tag]).toString("base64");
}
