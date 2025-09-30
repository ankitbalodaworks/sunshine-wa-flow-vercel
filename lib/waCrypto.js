import crypto from 'node:crypto';

// Trim + try base64(JSON) then plain JSON
export function parsePossiblyBase64JSON(body) {
  if (typeof body !== 'string') return null;
  const s = body.trim();
  if (!s) return null;
  try { return JSON.parse(Buffer.from(s, 'base64').toString('utf8')); } catch {}
  try { return JSON.parse(s); } catch {}
  return null;
}

// ---- helpers ----
function rsaUnwrapOAEP(encryptedKeyB64, rsaPrivateKeyPem) {
  const buf = Buffer.from(encryptedKeyB64, 'base64');
  return crypto.privateDecrypt(
    { key: rsaPrivateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    buf
  ); // returns AES key Buffer (16 or 32 bytes)
}

function aesGcmDecryptFlexible(aesKeyBuf, ivB64, ctB64, tagB64) {
  const iv  = Buffer.from(ivB64, 'base64');
  const ct  = Buffer.from(ctB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const algo = aesKeyBuf.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const dec = crypto.createDecipheriv(algo, aesKeyBuf, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

function aesGcmEncryptFlexible(aesKeyBuf, jsonString) {
  const iv = crypto.randomBytes(12);
  const algo = aesKeyBuf.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const enc = crypto.createCipheriv(algo, aesKeyBuf, iv);
  const ct  = Buffer.concat([enc.update(Buffer.from(jsonString,'utf8')), enc.final()]);
  const tag = enc.getAuthTag();
  return {
    ivB64: iv.toString('base64'),
    ctB64: ct.toString('base64'),
    tagB64: tag.toString('base64')
  };
}

// Generic DFS for previous heuristic (kept for compatibility)
function* walk(o) {
  if (o && typeof o === 'object') {
    yield o;
    for (const k of Object.keys(o)) yield* walk(o[k]);
  }
}

// Try to detect the old 4-field pattern
function findLegacyEnvelope(obj) {
  const isB64 = s => typeof s === 'string' && /^[A-Za-z0-9+/=]+$/.test(s) && s.length > 8;
  for (const sub of walk(obj)) {
    const keys = Object.keys(sub).filter(k => isB64(sub[k]));
    // naive permutations to find (ek, iv, tag, ct)
    for (let i=0;i<keys.length;i++)
    for (let j=0;j<keys.length;j++) if (j!==i)
    for (let k=0;k<keys.length;k++) if (k!==i && k!==j)
    for (let m=0;m<keys.length;m++) if (m!==i && m!==j && m!==k) {
      const ekB64 = sub[keys[i]], ivB64 = sub[keys[j]], tagB64 = sub[keys[k]], ctB64 = sub[keys[m]];
      try {
        const ek = Buffer.from(ekB64,'base64');
        const iv = Buffer.from(ivB64,'base64');
        const tag= Buffer.from(tagB64,'base64');
        const ct = Buffer.from(ctB64,'base64');
        if (ek.length >= 128 && iv.length === 12 && tag.length === 16 && ct.length >= 1) {
          return { ekB64, ivB64, tagB64, ctB64 };
        }
      } catch {}
    }
  }
  return null;
}

// NEW: detect WhatsApp Flows 3-field envelope
function findMetaFlowsEnvelope(obj) {
  if (!obj || typeof obj !== 'object') return null;
  // Allow nesting — check all sub-objects
  for (const sub of walk(obj)) {
    const efd = sub.encrypted_flow_data;
    const eak = sub.encrypted_aes_key;
    const iv  = sub.initial_vector;
    if (typeof efd === 'string' && typeof eak === 'string' && typeof iv === 'string') {
      try {
        const ivBuf = Buffer.from(iv, 'base64');
        const data  = Buffer.from(efd, 'base64');
        if (ivBuf.length === 12 && data.length > 16) {
          // GCM tag is usually the last 16 bytes of encrypted_flow_data
          const tag = data.subarray(data.length - 16);
          const ct  = data.subarray(0, data.length - 16);
          return {
            ekB64: eak,
            ivB64: iv,
            tagB64: tag.toString('base64'),
            ctB64: ct.toString('base64')
          };
        }
      } catch {}
    }
  }
  return null;
}

// ---- public API ----
export function decryptFlowRequestBody(eventBody, rsaPrivateKeyPem) {
  const raw = parsePossiblyBase64JSON(eventBody);
  if (!raw) throw new Error('Request body not JSON (or base64 JSON)');

  // Prefer the Meta 3-field format
  let env = findMetaFlowsEnvelope(raw);
  if (!env) {
    // try legacy detector as fallback
    env = findLegacyEnvelope(raw);
  }

  if (!env) {
    // Not encrypted (preview/unknown) → return raw as clear, no AES key
    return { clear: raw, aesKey: null };
  }

  const aesKey = rsaUnwrapOAEP(env.ekB64, rsaPrivateKeyPem); // 16 or 32 bytes
  const plain = aesGcmDecryptFlexible(aesKey, env.ivB64, env.ctB64, env.tagB64);
  const clear = JSON.parse(plain.toString('utf8'));
  return { clear, aesKey };
}

// Encrypt the response with the same AES session key, return base64(JSON envelope)
export function encryptFlowResponseBody(obj, aesKey) {
  if (!aesKey) throw new Error('No AES key to encrypt response');
  const { ivB64, ctB64, tagB64 } = aesGcmEncryptFlexible(aesKey, JSON.stringify(obj));
  const envelope = {
    // Return in the same 3-field shape WhatsApp expects:
    encrypted_flow_data: Buffer.concat([
      Buffer.from(ctB64, 'base64'),
      Buffer.from(tagB64, 'base64')
    ]).toString('base64'),
    // NOTE: We do NOT re-wrap the AES key for responses; per Meta, reply uses the same session AES key
    // so we only need to return a base64(JSON) string with iv/ct/tag (or the 3-field variant is also accepted by many stacks).
    initial_vector: ivB64
  };

  // However, the safest (per docs) is to return *base64(JSON envelope)*.
  // Many implementations accept {iv,ciphertext,tag} too, but the platform message says "must be Base64 string".
  const legacyEnv = { iv: ivB64, ciphertext: ctB64, tag: tagB64 };
  const b64 = Buffer.from(JSON.stringify(legacyEnv), 'utf8').toString('base64');
  return b64;
}
