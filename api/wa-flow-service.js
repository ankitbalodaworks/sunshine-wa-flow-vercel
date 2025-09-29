import { decryptFlowRequestBody, encryptFlowResponseBody } from '../lib/waCrypto.js';
import { persistServiceSubmission } from '../lib/persist.js';

export const config = { runtime: 'nodejs20.x' };

export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      return res.status(200).json({ ok: true, now: new Date().toISOString() });
    }
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const PRIVATE_KEY = (process.env.WA_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    if (!PRIVATE_KEY.includes('BEGIN PRIVATE KEY')) {
      console.error('WA_PRIVATE_KEY missing/malformed');
      return res.status(500).send('Server not configured');
    }

    // Vercel can parse JSON; we need raw string for decrypt helper
    const rawBody = typeof req.body === 'string'
      ? req.body
      : (req.body ? JSON.stringify(req.body) : req.rawBody);

    const { clear, aesKey } = decryptFlowRequestBody(rawBody, PRIVATE_KEY);
    console.log('DECRYPTED CLEAR:', JSON.stringify(clear));

    const op = clear?.payload?.op ?? clear?.data?.op ?? clear?.op ?? null;
    const isHealth =
      op === 'health_check' ||
      clear?.action === 'health_check' ||
      clear?.event === 'HEALTH_CHECK' ||
      clear?.type === 'HEALTH_CHECK' ||
      (!op && !clear?.screen && !clear?.fields && !clear?.data?.fields);

    if (isHealth) {
      const ok = { data: { status: 'active' } };
      if (aesKey) {
        const b64 = encryptFlowResponseBody(ok, aesKey);
        res.setHeader('Content-Type', 'application/octet-stream');
        return res.status(200).send(b64);
      }
      return res.status(200).json(ok);
    }

    // ---- Extract fields in common shapes
    function arrayToObject(arr=[]) {
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

    // ---- (Optional) forward to your Google Apps Script Web App to append to Sheet
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

    // Persist/log locally
    if (Object.keys(fields).length) {
      persistServiceSubmission({ type: 'service_form', ...fields, received_at: new Date().toISOString() });
    }

    // Tell WhatsApp to advance to success screen
    const responseJson = { version: '3.0', screen: 'SERVICE_SUCCESS', data: { ok: true } };
    if (aesKey) {
      const b64 = encryptFlowResponseBody(responseJson, aesKey);
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.status(200).send(b64);
    }
    return res.status(200).json(responseJson);

  } catch (err) {
    console.error('wa-flow-service error:', err);
    return res.status(500).send('Internal Server Error');
  }
}
