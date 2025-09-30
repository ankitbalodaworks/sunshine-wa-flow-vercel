
import * as crypto from 'node:crypto';

export const config = { runtime: 'nodejs' };
const VERSION = 'v-inline-3field-OK-04';

// ---------- helpers ----------
async function _readRawBody(req) {
  if (typeof req.body === 'string') return req.body;
  if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
  if (req.body && typeof req.body === 'object') return JSON.stringify(req.body);
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}
function _jsonTry(s) { try { return JSON.parse(s); } catch { return null; } }

// Decrypt Meta Flows 3-field envelope -> { clear:Object, aesKey:Buffer }
function _decryptMetaEnvelope3(obj, privatePem) {
  const efd = obj?.encrypted_flow_data;
  const eak = obj?.encrypted_aes_key;
  const ivB64 = obj?.initial_vector;
  if (!(efd && eak && ivB64)) return null;

  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(efd, 'base64');
  if (iv.length !== 12 || data.length <= 16) return null;

  const tag = data.subarray(data.length - 16);
  const ct  = data.subarray(0, data.length - 16);

  const aesKey = crypto.privateDecrypt(
    { key: privatePem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(eak, 'base64')
  ); // 16 or 32 bytes

  const algo = aesKey.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const dec  = crypto.createDecipheriv(algo, aesKey, iv);
  dec.setAuthTag(tag);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  const clear = _jsonTry(plain.toString('utf8'));
  if (!clear) throw new Error('Decrypted but not JSON');
  return { clear, aesKey };
}

// Encrypt response JSON with same AES key -> base64(JSON{iv,ciphertext,tag})
function _encryptResponseB64(obj, aesKey) {
  const algo = aesKey.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const iv   = crypto.randomBytes(12);
  const enc  = crypto.createCipheriv(algo, aesKey, iv);
  const ct   = Buffer.concat([enc.update(Buffer.from(JSON.stringify(obj),'utf8')), enc.final()]);
  const tag  = enc.getAuthTag();
  const envelope = {
    iv: iv.toString('base64'),
    ciphertext: ct.toString('base64'),
    tag: tag.toString('base64')
  };
  return Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64');
}

// ---------- handler ----------
export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      return res.status(200).json({ ok: true, version: VERSION, now: new Date().toISOString() });
    }
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const PRIVATE_KEY = (process.env.WA_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    if (!PRIVATE_KEY.includes('BEGIN PRIVATE KEY')) {
      console.error('WA_PRIVATE_KEY missing/malformed');
      return res.status(500).send('Server not configured');
    }

    const raw = await _readRawBody(req);
    const ctHdr = (req.headers['content-type'] || '').toString();
    console.log('CT:', ctHdr, '| LEN:', raw?.length || 0, '| PREVIEW:', (raw || '').slice(0, 120).replace(/\s+/g,' '));
    if (!raw || raw.trim().length < 2) {
      // allow empty probe
      return res.status(200).json({ data: { status: 'active' }, version: VERSION });
    }

    // Parse JSON or base64(JSON)
    const parsed = _jsonTry(raw) || _jsonTry(Buffer.from(raw, 'base64').toString('utf8'));
    if (!parsed) return res.status(400).send('Bad Request');

    // Decrypt 3-field envelope
    if (!(parsed.encrypted_flow_data && parsed.encrypted_aes_key && parsed.initial_vector)) {
      // If no envelope present, treat as plain health ping
      return res.status(200).json({ data: { status: 'active' }, version: VERSION });
    }

    console.log('Detected 3-field envelope: attempting decrypt');
    const decrypted = _decryptMetaEnvelope3(parsed, PRIVATE_KEY);
    if (!decrypted) {
      console.error('Decryption failed: envelope malformed or fields missing');
      return res.status(400).send('Bad Request: envelope malformed or decryption failed');
    }
    const { clear, aesKey } = decrypted;
    console.log('DECRYPTED CLEAR KEYS:', Object.keys(clear || {}));

    // Health check?
    const op = clear?.payload?.op ?? clear?.data?.op ?? clear?.op ?? null;
    const isHealth =
      op === 'health_check' ||
      clear?.action === 'health_check' ||
      clear?.event === 'HEALTH_CHECK' ||
      clear?.type === 'HEALTH_CHECK' ||
      (!op && !clear?.screen && !clear?.fields && !clear?.data?.fields);

    if (isHealth) {
      const ok = { data: { status: 'active' } };
      const b64 = _encryptResponseB64(ok, aesKey);
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.status(200).send(b64);
    }

    // Normal submission → (extract if needed), then success
    const reply = { version: '3.0', screen: 'SERVICE_SUCCESS', data: { ok: true } };
    const b64 = _encryptResponseB64(reply, aesKey);
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.status(200).send(b64);

  } catch (err) {
    console.error('wa-flow-service error:', err?.stack || String(err));
    return res.status(500).send('Internal Server Error');
  }
}
