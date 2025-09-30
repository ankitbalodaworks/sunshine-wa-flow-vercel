import { decryptFlowRequestBody, encryptFlowResponseBody } from '../lib/waCrypto.js';
import { persistServiceSubmission } from '../lib/persist.js';

export const config = { runtime: 'nodejs' };

// Robust raw-body reader
async function readRawBody(req) {
  if (typeof req.body === 'string') return req.body;
  if (Buffer.isBuffer(req.body))     return req.body.toString('utf8');
  if (req.body && typeof req.body === 'object') return JSON.stringify(req.body);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      return res.status(200).json({ ok: true, now: new Date().toISOString(), v: 'def-2' });
    }
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const PRIVATE_KEY = (process.env.WA_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    if (!PRIVATE_KEY.includes('BEGIN PRIVATE KEY')) {
      console.error('WA_PRIVATE_KEY missing/malformed');
      return res.status(500).send('Server not configured');
    }

    const rawBody = await readRawBody(req);
    const ct = (req.headers['content-type'] || req.headers['Content-Type'] || '').toString();
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
