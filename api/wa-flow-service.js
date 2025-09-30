import crypto from "node:crypto";

function decryptRequest(envelope, rsaPem) {
  const aesKey = crypto.privateDecrypt(
    { key: rsaPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(envelope.encrypted_aes_key, "base64")
  );
  const iv  = Buffer.from(envelope.initial_vector, "base64");
  const buf = Buffer.from(envelope.encrypted_flow_data, "base64");
  const tag = buf.subarray(buf.length - 16);
  const ct  = buf.subarray(0, buf.length - 16);

  const dec = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  dec.setAuthTag(tag);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  return { body: JSON.parse(plain.toString("utf8")), aesKey, iv };
}

function encryptResponse(obj, aesKey, requestIv) {
  const flippedIv = Buffer.from(requestIv.map(b => b ^ 0xff));
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, flippedIv);
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const c1 = cipher.update(json);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([c1, c2, tag]).toString("base64");
}

export default async (req) => {
  const rsaPem = process.env.WA_PRIVATE_KEY;
  const envelope = await req.json();

  const { body: payload, aesKey, iv } = decryptRequest(envelope, rsaPem);
  const ok = { version: "3.0", screen: "SERVICE_SUCCESS", data: { ok: true } };
  const b64 = encryptResponse(ok, aesKey, iv);

  // Self-test: prove we can decrypt our own response
  {
    const flippedIv = Buffer.from(iv.map(b => b ^ 0xff));
    const buf = Buffer.from(b64, "base64");
    const tag = buf.subarray(buf.length - 16);
    const ct  = buf.subarray(0, buf.length - 16);
    const dec = crypto.createDecipheriv("aes-256-gcm", aesKey, flippedIv);
    dec.setAuthTag(tag);
    const plain = Buffer.concat([dec.update(ct), dec.final()]);
    console.log("[SELFTEST]", plain.toString("utf8"));
    console.log("[RESP-CT]", "text/plain", "lenB64:", b64.length);
  }

  return new Response(b64, { headers: { "Content-Type": "text/plain" } });
};
