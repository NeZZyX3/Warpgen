const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ── CURVE25519 KEY GENERATION ─────────────────────────────
// Node.js 18+ has native X25519 support
function generateKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');

  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  const pubRaw  = publicKey.export({ type: 'spki',  format: 'der' });

  // PKCS8 X25519 private key: last 32 bytes are the raw key
  const privBytes = privRaw.slice(-32);
  // SPKI X25519 public key: last 32 bytes are the raw key
  const pubBytes  = pubRaw.slice(-32);

  return {
    privateKey: privBytes.toString('base64'),
    publicKey:  pubBytes.toString('base64'),
  };
}

// ── CLOUDFLARE WARP API ───────────────────────────────────
const CF_API = 'https://api.cloudflareclient.com/v0a2158/reg';

async function registerWarpDevice(publicKey) {
  const body = JSON.stringify({
    key:        publicKey,
    install_id: randomUUID(),
    fcm_token:  randomUUID(),
    tos:        new Date().toISOString(),
    type:       'Android',
    model:      'PC',
    locale:     'en_US',
  });

  const resp = await fetch(CF_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent':   'okhttp/3.12.1',
    },
    body,
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`CF API ${resp.status}: ${txt.slice(0, 200)}`);
  }

  const data = await resp.json();
  return data.result ?? data;
}

// ── BUILD CONFIG FILES ────────────────────────────────────
const DNS_MAP = {
  malware:    { primary: '1.1.1.2',       secondary: '1.0.0.2' },
  xbox:       { primary: '8.8.8.8',       secondary: '4.4.4.4' },
  adguard:    { primary: '94.140.14.14',  secondary: '94.140.15.15' },
  cloudflare: { primary: '1.1.1.1',       secondary: '1.0.0.1' },
};

// Hardcoded Cloudflare WARP server endpoints (these are stable)
const CF_ENDPOINTS = [
  { ip: '162.159.192.1',   port: 2408 },
  { ip: '162.159.193.1',   port: 2408 },
  { ip: '162.159.195.1',   port: 2408 },
  { ip: '188.114.96.1',    port: 2408 },
  { ip: '188.114.97.1',    port: 2408 },
];

// Cloudflare WARP server public key (stable, official)
const CF_SERVER_PUBKEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2+PY8Ew=';

function buildConfFile(keys, warpData, opts) {
  const dns = DNS_MAP[opts.dns] || DNS_MAP.malware;
  const iface = warpData.config.interface.addresses;

  const addr = opts.ipv6 && iface.v6
    ? `${iface.v4}/32, ${iface.v6}/128`
    : `${iface.v4}/32`;

  const dnsStr = dns.secondary
    ? `${dns.primary}, ${dns.secondary}`
    : dns.primary;

  const ep = CF_ENDPOINTS[Math.floor(Math.random() * CF_ENDPOINTS.length)];
  const endpoint = opts.endpoint === 'auto'
    ? `${ep.ip}:${ep.port}`
    : opts.endpoint;

  const allowedIPs = opts.fullTunnel
    ? (opts.ipv6 ? '0.0.0.0/0, ::/0' : '0.0.0.0/0')
    : (opts.ipv6 ? '0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1' : '0.0.0.0/1, 128.0.0.0/1');

  const H = () => (crypto.randomInt(0x10000000, 0xFFFFFFFF));

  let conf = `[Interface]
PrivateKey = ${keys.privateKey}
Address = ${addr}
DNS = ${dnsStr}
MTU = ${opts.mtu || 1280}
`;

  if (opts.client === 'amnezia') {
    conf += `Jc = ${opts.jc || 4}
Jmin = ${opts.jmin || 23}
Jmax = ${opts.jmax || 911}
S1 = ${opts.s1 || 0}
S2 = ${opts.s2 || 0}
H1 = ${H()}
H2 = ${H()}
H3 = ${H()}
H4 = ${H()}
`;
  }

  conf += `
[Peer]
PublicKey = ${CF_SERVER_PUBKEY}
AllowedIPs = ${allowedIPs}
Endpoint = ${endpoint}
PersistentKeepalive = 25
`;

  return conf;
}

function buildAmneziaJson(keys, warpData, opts, confText) {
  const dns = DNS_MAP[opts.dns] || DNS_MAP.malware;
  return JSON.stringify({
    containers: [{
      container: 'amneziawg',
      awg_settings: {
        H1: crypto.randomInt(0x10000000, 0xFFFFFFFF),
        H2: crypto.randomInt(0x10000000, 0xFFFFFFFF),
        H3: crypto.randomInt(0x10000000, 0xFFFFFFFF),
        H4: crypto.randomInt(0x10000000, 0xFFFFFFFF),
        Jc:   opts.jc   || 4,
        Jmax: opts.jmax || 911,
        Jmin: opts.jmin || 23,
        S1:   opts.s1   || 0,
        S2:   opts.s2   || 0,
        last_config: confText,
      },
    }],
    defaultContainer: 'amneziawg',
    description: `WARP ${(opts.dns || 'malware').toUpperCase()} — warpgen`,
    dns1: dns.primary,
    dns2: dns.secondary || dns.primary,
  }, null, 2);
}

// ── API ENDPOINT ──────────────────────────────────────────
app.post('/api/generate', async (req, res) => {
  try {
    const opts = req.body || {};

    // 1. Generate keypair on server (real X25519)
    const keys = generateKeypair();

    // 2. Register with Cloudflare WARP
    let warpData;
    try {
      warpData = await registerWarpDevice(keys.publicKey);
    } catch (err) {
      console.error('CF API error:', err.message);
      // Return error — don't silently use fake data
      return res.status(502).json({
        error: 'Cloudflare WARP API недоступен',
        detail: err.message,
      });
    }

    // 3. Build config files
    const confText = buildConfFile(keys, warpData, opts);
    const jsonText = buildAmneziaJson(keys, warpData, opts, confText);

    const iface = warpData.config.interface.addresses;

    res.json({
      ok: true,
      conf: confText,
      json: jsonText,
      info: {
        deviceId:  warpData.id,
        ipv4:      iface.v4,
        ipv6:      iface.v6 || null,
        publicKey: keys.publicKey,
        dns:       opts.dns || 'malware',
        client:    opts.client || 'amnezia',
      },
    });

  } catch (err) {
    console.error('Generate error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get('/api/health', (_, res) => res.json({ ok: true, ts: Date.now() }));

// SPA fallback
app.get('*', (_, res) =>
  res.sendFile(path.join(__dirname, '../public/index.html'))
);

app.listen(PORT, () =>
  console.log(`WARPGEN server running on port ${PORT}`)
);

// ── UTILS ─────────────────────────────────────────────────
function randomUUID() {
  return crypto.randomUUID();
}
