import crypto from 'node:crypto';

// Try base64(JSON) → JSON; else try JSON → object; else null
export function parsePossiblyBase64JSON(body) {
  if (typeof body !== 'string') return null;
  const s = body.trim();
  if (!s) return null;
  try { return JSON.parse(Buffer.from(s, 'base64').toString('utf8')); } catch {}
  try { return JSON.parse(s); } catch {}
  return null;
}

// Depth-first traverse
function* walk(o) {
  if (o && typeof o === 'object') {
    yield o;
    for (const k of Object.keys(o)) yield* walk(o[k]);
  }
}

// Find an envelope that *looks* like { ek, iv, tag, ct } (all base64; lengths match)
function findCryptoEnvelope(obj) {
  const b64 = s => typeof s === 'string' && /^[A-Za-z0-9+/=]+$/.test(s) && s.length > 8;
  for (const sub of walk(obj)) {
    const ents = Object.entries(sub).filter(([,v]) => b64(v));
    for (let i=0;i<ents.length;i++)
    for (let j=0;j<ents.length;j++) if (j!==i)
    for (let k=0;k<ents.length;k++) if (k!==i && k!==j)
    for (let m=0;m<ents.length;m++) if (m!==i && m!==j && m!==k) {
      const ekB64 = ents[i][1], ivB64 = ents[j][1], tagB64 = ents[k][1], ctB64 = ents[m][1];
      try {
        const ek = Buffer.from(ekB64,'base64');
        const iv = Buffer.from(ivB64,'base64');
        const tag= Buffer.from(tagB64,'base64');
        const ct = Buffer.from(ctB64,'base64');
        if (ek.length >= 128 && iv.length === 12 && tag.length === 16 && ct.length >= 16) {
          return { ekB64, ivB64, tagB64, ctB64, node: sub };
        }
      } catch {}
    }
  }
  return null;
}

function rsaUnwrap(encryptedKeyB64, rsaPrivateKeyPem) {
  const buf = Buffer.from(encryptedKeyB64, 'base64');
  return crypto.privateDecrypt(
    { key: rsaPrivateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    buf
  ); // 32 bytes
}

function aesGcmDecrypt(keyBuf, ivB64, ctB64, tagB64) {
  const iv  = Buffer.from(ivB64, 'base64');
  const ct  = Buffer.from(ctB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const dec = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

function aesGcmEncrypt(keyBuf, jsonString) {
  const iv = crypto.randomBytes(12);
  const enc = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct  = Buffer.concat([enc.update(Buffer.from(jsonString,'utf8')), enc.final()]);
  const tag = enc.getAuthTag();
  return { iv: iv.toString('base64'), ciphertext: ct.toString('base64'), tag: tag.toString('base64') };
}

// Decrypt incoming request → { clear, aesKey }
export function decryptFlowRequestBody(eventBody, rsaPrivateKeyPem) {
  const raw = parsePossiblyBase64JSON(eventBody);
  if (!raw) throw new Error('Request body not JSON (or base64 JSON)');
  const env = findCryptoEnvelope(raw);
  if (!env) { // preview / non-encrypted probe
    return { clear: raw, aesKey: null };
  }
  const aesKey = rsaUnwrap(env.ekB64, rsaPrivateKeyPem);
  const plain = aesGcmDecrypt(aesKey, env.ivB64, env.ctB64, env.tagB64);
  const clear = JSON.parse(plain.toString('utf8'));
  return { clear, aesKey };
}

// Encrypt response object using same AES key → base64(JSON envelope) string
export function encryptFlowResponseBody(obj, aesKey) {
  if (!aesKey) throw new Error('No AES key to encrypt response');
  const env = aesGcmEncrypt(aesKey, JSON.stringify(obj));
  return Buffer.from(JSON.stringify(env),'utf8').toString('base64');
}
