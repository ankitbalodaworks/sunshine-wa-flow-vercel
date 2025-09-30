export const runtime = 'nodejs'; // ensures Node runtime (crypto available)

import { decryptEnvelope, encryptResponse } from '@/lib/whatsapp-crypto';

// Simple schema guard
function must(v, name) {
  if (!v) throw new Error(`Missing ${name}`);
  return v;
}

export async function POST(request) {
  try {
    // 1) Parse envelope (WhatsApp sends JSON with base64 fields)
    const body = await request.json();

    // 2) Decrypt -> get plain payload
    const { aesKey, ivBuf, payload } = decryptEnvelope(body);

    // payload often contains: { version, screen, action, data, flow_token, ... }
    // console.log('Decrypted payload:', payload);

    // 3) Forward to Make.com webhook (plain JSON, no encryption)
    const makeUrl = must(process.env.MAKE_WEBHOOK_URL, 'MAKE_WEBHOOK_URL');

    // Build a normalized record for your Leads sheet
    const record = {
      // safe-guard optional paths
      full_name: payload?.data?.full_name ?? '',
      mobile: payload?.data?.mobile ?? '',
      address: payload?.data?.address ?? '',
      village: payload?.data?.village ?? '',
      avg_bill: payload?.data?.avg_bill ?? '',
      phase: payload?.data?.phase ?? '',
      roof_type: payload?.data?.roof_type ?? '',
      preferred_date: payload?.data?.preferred_date ?? '',
      preferred_time: payload?.data?.preferred_time ?? '',
      meta: {
        version: payload?.version ?? '3.0',
        screen: payload?.screen ?? 'BOOK_SURVEY',
        received_at: new Date().toISOString()
      }
    };

    await fetch(makeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record)
    });

    // 4) Build success screen object (per WhatsApp Flows spec)
    // Minimal required: { version, screen, data? }
    const responseObj = {
      version: '3.0',
      screen: 'SERVICE_SUCCESS',
      data: { ok: true }
    };

    // 5) Encrypt with same AES key; IV strategy configurable
    const b64 = encryptResponse(aesKey, ivBuf, responseObj);

    // 6) Return Base64 string, not JSON
    return new Response(b64, {
      status: 200,
      headers: { 'Content-Type': 'text/plain' }
    });
  } catch (err) {
    // Return an encrypted error screen if we can’t process
    console.error('Flow endpoint error:', err);

    // If decryption failed, we can’t encrypt a response; return 400
    if (/decrypt/i.test(String(err)) || /Missing encrypted envelope/.test(String(err))) {
      return new Response('Bad Request', { status: 400 });
    }

    return new Response('Server Error', { status: 500 });
  }
}

export async function GET() {
  // Health endpoint for quick checks
  return new Response('ok', { status: 200 });
}
