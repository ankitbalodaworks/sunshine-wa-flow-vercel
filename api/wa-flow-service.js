
// api/wa-flow-service.js
import crypto from 'node:crypto';

export const config = { runtime: 'nodejs' }; // valid: "nodejs" | "edge"
const VERSION = 'v-inline-3field-OK-02';

// ---------- helpers ----------
async function _readRawBody(req) {
  if (typeof req.body === 'string') return req.body;
  if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
  if (req.body && typeof req.body === 'object') return JSON.stringify(req.body);
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
function _jsonTry(s) { try { return JSON.parse(s); } catch { return null; } }

// Decrypt Meta Flows 3-field envelope -> { clear:Object, aesKey:Buffer }

// api/wa-flow-service.js
import crypto from 'node:crypto';

export const config = { runtime: 'nodejs' };
const VERSION = 'v-inline-3field-OK-03';

// ---------- helpers (names prefixed with _) ----------
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
      console.warn('Empty body -> plain health OK');
      return res.status(200).json({ data: { status: 'active' }, version: VERSION });
    }

    // Parse incoming as JSON (or base64(JSON))
    const parsed = _jsonTry(raw) || _jsonTry(Buffer.from(raw, 'base64').toString('utf8'));
    if (!parsed) {
      console.error('Incoming not JSON nor base64(JSON)');
      return res.status(400).send('Bad Request');
    }

    // Decrypt 3-field envelope
    let clear, aesKey;
    if (parsed.encrypted_flow_data && parsed.encrypted_aes_key && parsed.initial_vector) {
      console.log('Detected 3-field envelope: attempting decrypt');
      ({ clear, aesKey } = _decryptMetaEnvelope3(parsed, PRIVATE_KEY));
    } else {
      console.warn('No 3-field envelope present -> plain health OK');
      return res.status(200).json({ data: { status: 'active' }, version: VERSION });
    }

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

    // Submission path (extract fields if present)
    let fields = {};
    if (Array.isArray(clear?.data?.fields)) {
      for (const f of clear.data.fields) {
        const name = f?.name;
        const value = (f?.value !== undefined) ? f.value : (f?.selected_option?.id ?? f);
        if (name) fields[name] = value;
      }
    } else if (clear?.data?.service_form) {
      fields = clear.data.service_form;
    } else if (clear?.fields) {
      fields = clear.fields;
    } else if (clear?.data && typeof clear.data === 'object') {
      fields = clear.data;
    }
    console.log('FIELDS_KEYS:', Object.keys(fields));

    const reply = { version: '3.0', screen: 'SERVICE_SUCCESS', data: { ok: true } };
    const b64 = _encryptResponseB64(reply, aesKey);
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.status(200).send(b64);

  } catch (err) {
    console.error('wa-flow-service error:', err?.stack || String(err));
    return res.status(500).send('Internal Server Error');
  }
}
    const preview = rawBody ? rawBody.slice(0, 120).replace(/\s+/g, ' ') : '';
    console.log('CT:', ct, '| LEN:', rawBody?.length || 0, '| PREVIEW:', preview);

    // --- CRITICAL: if body is empty or 1-2 chars junk, treat as health probe without encryption ---
    const trimmed = (rawBody || '').trim();
    if (!trimmed || trimmed.length < 2) {
      const ok = { data: { status: 'active' } };
      console.warn('Empty/short body -> sending plain health OK');
      return res.status(200).json(ok);
    }

    // Try decrypt (normal flow health/data_exchange path)
    let clear, aesKey;
    try {
      ({ clear, aesKey } = decryptFlowRequestBody(rawBody, PRIVATE_KEY));
    } catch (e) {
      // If decrypt fails, log and try a plain JSON fallback for health checks
      console.error('decryptFlowRequestBody failed:', e?.message || e, '\nBody:', rawBody, '\nKey:', PRIVATE_KEY);
      try {
        const maybe = JSON.parse(trimmed);
        clear = maybe;
        aesKey = null;
        console.warn('Proceeding with PLAIN JSON clear (no AES)');
      } catch {
        // Still not JSON → bail with Bad Request (but 200 plain health for Flow HC might be acceptable)
        return res.status(400).send('Bad Request: body not decryptable');
      }
    }

    console.log('DECRYPTED/PLAIN CLEAR keys:', Object.keys(clear || {}));

    const op = clear?.payload?.op ?? clear?.data?.op ?? clear?.op ?? null;
    const isHealth =
      op === 'health_check' ||
      clear?.action === 'health_check' ||
      clear?.event === 'HEALTH_CHECK' ||
      clear?.type === 'HEALTH_CHECK' ||
      (!op && !clear?.screen && !clear?.fields && !clear?.data?.fields);

    if (isHealth) {
      const ok = { data: { status: 'active' } };
      console.log('HEALTH CHECK RESPONSE: aesKey present?', !!aesKey);
      if (aesKey) {
        const b64 = encryptFlowResponseBody(ok, aesKey);
        res.setHeader('Content-Type', 'application/octet-stream');
        return res.status(200).send(b64);
      }
      // If we don't have AES (plain probe), reply JSON
      return res.status(200).json(ok);
    }

    // ------- extract fields (unchanged) -------
    function arrayToObject(arr = []) {
      const out = {};
      for (const e of arr) {
        const name = e?.name || e?.key || e?.id;
        if (!name) continue;
        if (e.value !== undefined) out[name] = e.value;
        else if (e.selected_option?.id) out[name] = e.selected_option.id;
        else if (Array.isArray(e.values) && e.values.length === 1) out[name] = e.values[0];
      }
      return out;
    }
    function extractFormFields(obj) {
      const roots = [obj?.data?.fields, obj?.data?.service_form, obj?.fields, obj?.data];
      for (const r of roots) {
        if (!r) continue;
        if (Array.isArray(r)) { const o = arrayToObject(r); if (Object.keys(o).length) return o; }
        if (Array.isArray(r?.fields)) { const o = arrayToObject(r.fields); if (Object.keys(o).length) return o; }
        if (r.full_name || r.mobile) return r;
      }
      if (Array.isArray(obj?.data?.form_responses)) {
        for (const fr of obj.data.form_responses) {
          if (Array.isArray(fr?.fields)) {
            const o = arrayToObject(fr.fields);
            if (Object.keys(o).length) return o;
          }
        }
      }
      return {};
    }

    const fields = extractFormFields(clear);
    console.log('FIELDS_KEYS:', Object.keys(fields));

    // Optional forward to Google Sheets Web App
    if (process.env.GAS_WEBAPP_URL && Object.keys(fields).length) {
      try {
        await fetch(process.env.GAS_WEBAPP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields, received_at: new Date().toISOString(), source: 'wa-flow' })
        });
      } catch (e) {
        console.warn('Forward to GAS failed:', e.message);
      }
    }

    if (Object.keys(fields).length) {
      persistServiceSubmission({ type: 'service_form', ...fields, received_at: new Date().toISOString() });
    }

    const reply = { version: '3.0', screen: 'SERVICE_SUCCESS', data: { ok: true } };
    if (aesKey) {
      const b64 = encryptFlowResponseBody(reply, aesKey);
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.status(200).send(b64);
    }
    return res.status(200).json(reply);

  } catch (err) {
    console.error('wa-flow-service error:', err?.stack || String(err));
    return res.status(500).send('Internal Server Error');
  }
}
