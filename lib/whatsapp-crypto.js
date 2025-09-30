import crypto from 'node:crypto';

// Decrypts inbound envelope from WhatsApp Flow client
export function decryptEnvelope({ encrypted_flow_data, encrypted_aes_key, initial_vector, iv }) {
  const ivB64 = initial_vector || iv; // some SDKs label it `iv`
  if (!encrypted_flow_data || !encrypted_aes_key || !ivB64) {
    throw new Error('Missing encrypted envelope fields');
  }

  const privPem = process.env.WA_PRIVATE_KEY;
  if (!privPem) throw new Error('WA_PRIVATE_KEY is not set');

  // 1) unwrap AES key with RSA-OAEP(SHA-256)
  const privateKey = crypto.createPrivateKey({ key: privPem, format: 'pem' });
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  // 2) decrypt payload with AES-256-GCM
  const ivBuf = Buffer.from(ivB64, 'base64');
  const blob = Buffer.from(encrypted_flow_data, 'base64');
  const tag = blob.subarray(blob.length - 16);
  const cipher = blob.subarray(0, blob.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuf);
  decipher.setAuthTag(tag);
  const clear = Buffer.concat([decipher.update(cipher), decipher.final()]);
  const json = JSON.parse(clear.toString('utf8'));

  return { aesKey, ivBuf, payload: json };
}

// Encrypts response JSON. By default we use the “invert IV” pattern
// seen in reference implementations; if it fails for your account,
// switch WA_IV_STRATEGY="same" to reuse the request IV (varies by docs/examples).
export function encryptResponse(aesKey, requestIvBuf, responseObj) {
  const strategy = (process.env.WA_IV_STRATEGY || 'invert').toLowerCase();
  const respIv =
    strategy === 'same'
      ? requestIvBuf
      : Buffer.from(requestIvBuf).reverse(); // "invert IV" pattern documented by several integrations

  const plaintext = Buffer.from(JSON.stringify(responseObj), 'utf8');

  const enc = crypto.createCipheriv('aes-256-gcm', aesKey, respIv);
  const ciphertext = Buffer.concat([enc.update(plaintext), enc.final()]);
  const tag = enc.getAuthTag();
  // WhatsApp expects base64 of (ciphertext || tag)
  return Buffer.concat([ciphertext, tag]).toString('base64');
}
