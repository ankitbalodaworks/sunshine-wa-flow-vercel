# sunshine-wa-flow-vercel

WhatsApp Flow service endpoint for Vercel.  
See `api/wa-flow-service.js` for main logic.  
Crypto helpers in `lib/waCrypto.js`, logging in `lib/persist.js`.

You can add your private key and Google Apps Script endpoint to environment variables:
- `WA_PRIVATE_KEY`
- `GAS_WEBAPP_URL`