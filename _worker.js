// _worker_ultimate.js
// ============================================================
// Ultimate Cloudflare Worker — VLESS + Trojan Proxy
// Port 80 & 443 | WS + WSS | Early Data | DoH | Proxy Pool
// ============================================================
import { connect } from "cloudflare:sockets";

// ============================================================
// 1. CONFIGURATION
// ============================================================
const CONFIG = {
  DEFAULT_PROXY_IPS: [
    "lelouch.abrdns.com",
    "galaxproxy.cloud-ip.cc",
    "blacknight.abrdns.com",
    "net.galaxytunnel.linkpc.net",
    "pro.galaxytunnel.linkpc.net",
    "privacy.bbroot.com",
    "galax.cc.cd"],
  DEFAULT_DOH_URL: "https://cloudflare-dns.com/dns-query",
  CONNECT_TIMEOUT_MS: 30000,
  IDLE_TIMEOUT_MS: 300000,
  RATE_LIMIT_WINDOW_MS: 60000,
  RATE_LIMIT_MAX_REQUESTS: 200,
  PROXY_POOL_TTL_MS: 300000,
  WS_PATH_DEFAULT: "galaxy-tunnel",
  ALLOWED_CLIENT_PORTS: ["443", "80", "8443", "2053", "2083", "2087", "2096"],
  PROXY_PORT_DEFAULT: 443
};

const VLESS_PROTOCOL_VERSION = 0;
const VLESS_COMMAND_TCP = 1;
const VLESS_COMMAND_UDP = 2;

// ============================================================
// 2. STRUCTURED LOGGER
// ============================================================
class Logger {
  constructor(requestId, clientIp = "unknown") {
    this.requestId = requestId;
    this.clientIp = clientIp;
  }
  _log(level, event, details = {}) {
    const entry = {
      ts: new Date().toISOString(),
      level,
      reqId: this.requestId,
      ip: this.clientIp,
      event,
      ...details
    };
    const fn = level === "ERROR" ? console.error
             : level === "WARN"  ? console.warn
             : console.log;
    try { fn(JSON.stringify(entry)); } catch {}
  }
  info(e, d)  { this._log("INFO", e, d); }
  warn(e, d)  { this._log("WARN", e, d); }
  error(e, d) { this._log("ERROR", e, d); }
  debug(e, d) { this._log("DEBUG", e, d); }
}

function genReqId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return "req_" + Math.random().toString(36).substring(2, 12);
}

// ============================================================
// 3. VALIDATION & SSRF PROTECTION
// ============================================================
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUUID(uuid) {
  if (!uuid || typeof uuid !== "string") return false;
  return UUID_REGEX.test(uuid.trim());
}

function parseUUIDs(raw) {
  if (!raw) return [];
  return raw.split(",").map(u => u.trim()).filter(u => isValidUUID(u));
}

function isPrivateOrBlockedHost(hostname) {
  if (!hostname) return true;
  const host = hostname.toLowerCase().trim().replace(/^\[|\]$/g, "");

  if (
    host === "localhost" || host === "127.0.0.1" ||
    host === "0.0.0.0" || host === "::1" ||
    host.endsWith(".local") || host.endsWith(".internal") ||
    host.endsWith(".lan")
  ) return true;

  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [, a, b] = m.map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (/^(fc|fd|fe80)/i.test(host)) return true;
  return false;
}

function sanitizeUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return null;
  try {
    const p = new URL(urlStr);
    if (p.protocol !== "http:" && p.protocol !== "https:") return null;
    if (isPrivateOrBlockedHost(p.hostname)) return null;
    p.username = ""; p.password = "";
    return p.toString();
  } catch { return null; }
}

// ============================================================
// 4. RATE LIMITER
// ============================================================
class RateLimiter {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.records = new Map();
  }
  check(ip) {
    const now = Date.now();
    let rec = this.records.get(ip);

    if (!rec || now - rec.start > this.windowMs) {
      rec = { count: 1, start: now };
      this.records.set(ip, rec);
      return { allowed: true, remaining: this.limit - 1, resetIn: Math.ceil(this.windowMs / 1000) };
    }
    rec.count++;
    const remaining = Math.max(0, this.limit - rec.count);
    const resetIn = Math.ceil((rec.start + this.windowMs - now) / 1000);

    if (rec.count > this.limit) {
      return { allowed: false, remaining: 0, resetIn };
    }

    if (this.records.size > 5000) {
      for (const [k, v] of this.records) {
        if (now - v.start > this.windowMs) this.records.delete(k);
      }
    }
    return { allowed: true, remaining, resetIn };
  }
}

const rateLimiter = new RateLimiter(
  CONFIG.RATE_LIMIT_MAX_REQUESTS,
  CONFIG.RATE_LIMIT_WINDOW_MS
);

// ============================================================
// 5. PROXY POOL MANAGER
// ============================================================
class ProxyPoolManager {
  constructor(defaults, ttlMs) {
    this.defaults = defaults;
    this.pool = [...defaults];
    this.lastFetch = 0;
    this.ttl = ttlMs;
    this.fetching = false;
  }
  async get(defaultProxy, listUrl, logger) {
    const url = sanitizeUrl(listUrl);
    const now = Date.now();

    if (url && now - this.lastFetch > this.ttl && !this.fetching) {
      this.fetching = true;
      try {
        logger?.info("PROXY_FETCH_START", { url });
        const res = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
        if (res.ok) {
          const text = await res.text();
          const fetched = text.split("\n")
            .map(l => l.trim())
            .filter(l => l.length > 0 && !l.startsWith("#") && !isPrivateOrBlockedHost(l));
          if (fetched.length > 0) {
            this.pool = Array.from(new Set([...fetched, ...this.defaults]));
            this.lastFetch = now;
            logger?.info("PROXY_POOL_UPDATED", { size: this.pool.length });
          }
        }
      } catch (e) {
        logger?.warn("PROXY_FETCH_FAIL", { error: e.message });
      } finally { this.fetching = false; }
    }

    const validDefault = (defaultProxy && !isPrivateOrBlockedHost(defaultProxy))
      ? defaultProxy : this.defaults[0];
    if (this.pool.length === 0) return validDefault;
    return this.pool[Math.floor(Math.random() * this.pool.length)] || validDefault;
  }
  size() { return this.pool.length; }
  all()  { return [...this.pool]; }
}

// ============================================================
// 6. IPv6 RFC 5952 FORMATTER
// ============================================================
function formatIPv6(hextets) {
  const nums = hextets.map(h => typeof h === "string" ? parseInt(h, 16) : h);
  const hex = nums.map(n => (n || 0).toString(16));

  let longestStart = -1, longestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (nums[i] === 0) {
      if (curStart === -1) { curStart = i; curLen = 1; }
      else curLen++;
      if (curLen > longestLen) { longestStart = curStart; longestLen = curLen; }
    } else { curStart = -1; curLen = 0; }
  }

  if (longestLen > 1) {
    const left = hex.slice(0, longestStart).join(":");
    const right = hex.slice(longestStart + longestLen).join(":");
    if (left === "" && right === "") return "::";
    if (left === "") return `::${right}`;
    if (right === "") return `${left}::`;
    return `${left}::${right}`;
  }
  return hex.join(":");
}

// ============================================================
// 7. SECURITY HEADERS
// ============================================================
function getSecurityHeaders(contentType = "text/html; charset=utf-8") {
  return {
    "Content-Type": contentType,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "1; mode=block",
    "Permissions-Policy": "interest-cohort=()",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"
  };
}

// ============================================================
// 8. HTML PAGES
// ============================================================
function getGalaxyPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<title>Galaxy-Tunnel VLESS</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body,html{width:100%;height:100%;background:#02060d;overflow:hidden;font-family:'Segoe UI',Arial,sans-serif;display:flex;justify-content:center;align-items:center}
.space-bg{position:absolute;width:100%;height:100%;background:radial-gradient(circle at 50% 35%,rgba(10,45,80,.7) 0%,transparent 65%),radial-gradient(circle at 80% 80%,rgba(0,150,200,.15) 0%,transparent 50%),#02060d;z-index:1}
.starfield{position:absolute;width:100%;height:100%;background-image:radial-gradient(2px 2px at 20px 30px,#fff,rgba(0,0,0,0)),radial-gradient(2px 2px at 40px 70px,rgba(0,212,255,.8),rgba(0,0,0,0)),radial-gradient(1px 1px at 90px 40px,#fff,rgba(0,0,0,0)),radial-gradient(2px 2px at 160px 120px,rgba(0,212,255,.9),rgba(0,0,0,0));background-repeat:repeat;background-size:220px 220px;animation:tw 4s ease-in-out infinite alternate;opacity:.6}
@keyframes tw{0%{opacity:.4;transform:scale(1)}100%{opacity:.8;transform:scale(1.02)}}
.card{position:relative;z-index:10;width:90vw;max-width:480px;aspect-ratio:1/1;background:rgba(4,12,24,.75);border:1.5px solid rgba(0,212,255,.6);box-shadow:0 0 25px rgba(0,212,255,.25),inset 0 0 25px rgba(0,212,255,.1);backdrop-filter:blur(12px);display:flex;flex-direction:column;justify-content:space-between;align-items:center;padding:35px 25px 25px;border-radius:4px}
.gfx{position:relative;width:230px;height:230px;display:flex;justify-content:center;align-items:center}
.ring{position:absolute;width:240px;height:75px;border:2px solid rgba(0,230,255,.85);border-radius:50%;transform:rotate(-28deg);box-shadow:0 0 15px rgba(0,212,255,.8),inset 0 0 15px rgba(0,212,255,.5);pointer-events:none;animation:rg 3s ease-in-out infinite alternate}
@keyframes rg{0%{opacity:.7}100%{opacity:1}}
canvas{position:absolute;top:0;left:0}
.title{font-size:34px;font-weight:900;font-style:italic;color:#fff;letter-spacing:2px;text-transform:uppercase;text-shadow:0 0 12px rgba(255,255,255,.7);line-height:1.1;text-align:center}
.sub{font-size:16px;font-weight:600;color:#7b93a7;letter-spacing:5px;margin-top:6px;text-transform:uppercase;text-align:center}
.badge{align-self:flex-end;margin-top:15px;font-size:20px;font-weight:900;font-style:italic;color:#00e5ff;text-transform:uppercase;text-align:right;letter-spacing:1px;line-height:1.1;text-shadow:0 0 15px rgba(0,229,255,.85);animation:sp 2s infinite alternate}
@keyframes sp{0%{opacity:.8}100%{opacity:1}}
.bottom{width:100%;display:flex;flex-direction:column;align-items:center;text-align:center;position:relative}
</style>
</head>
<body>
<div class="space-bg"></div><div class="starfield"></div>
<div class="card">
<div class="gfx"><div class="ring"></div><canvas id="c" width="230" height="230"></canvas></div>
<div class="bottom">
<h1 class="title">GALAXY-TUNNEL</h1>
<div class="sub">VLESS CONFIG</div>
<div class="badge">GALAXY VPROXY<br>IS ACCESS</div>
</div></div>
<script>
const c=document.getElementById('c'),x=c.getContext('2d'),N=32,n=[],R=75;
for(let i=0;i<N;i++){let t=Math.acos(Math.random()*2-1),p=Math.random()*Math.PI*2;n.push({x:R*Math.sin(t)*Math.cos(p),y:R*Math.sin(t)*Math.sin(p),z:R*Math.cos(t)})}
function rX(o,a){let c=Math.cos(a),s=Math.sin(a),y=o.y*c-o.z*s,z=o.z*c+o.y*s;o.y=y;o.z=z}
function rY(o,a){let c=Math.cos(a),s=Math.sin(a),x=o.x*c-o.z*s,z=o.z*c+o.x*s;o.x=x;o.z=z}
function d(){x.clearRect(0,0,c.width,c.height);let cx=c.width/2,cy=c.height/2;
n.forEach(o=>{rX(o,.004);rY(o,.007)});
x.strokeStyle='rgba(0,220,255,.35)';x.lineWidth=1;
for(let i=0;i<n.length;i++)for(let j=i+1;j<n.length;j++){let dd=Math.hypot(n[i].x-n[j].x,n[i].y-n[j].y,n[i].z-n[j].z);if(dd<60){x.beginPath();x.moveTo(n[i].x+cx,n[i].y+cy);x.lineTo(n[j].x+cx,n[j].y+cy);x.stroke()}}
n.forEach(o=>{let s=(o.z+R)/(2*R)*3+2;x.beginPath();x.arc(o.x+cx,o.y+cy,s,0,Math.PI*2);x.fillStyle='#00f0ff';x.shadowBlur=8;x.shadowColor='#00f0ff';x.fill();x.shadowBlur=0});
requestAnimationFrame(d)}d();
</script>
</body></html>`;
}

function getUnauthorizedPage() {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="robots" content="noindex,nofollow">
<title>401 Unauthorized</title>
<style>body{font-family:system-ui,sans-serif;background:#090d16;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.box{max-width:620px;width:100%;background:rgba(15,23,42,.95);border:1px solid rgba(56,189,248,.3);border-radius:12px;padding:32px;box-shadow:0 10px 40px rgba(0,0,0,.6)}
.badge{background:#ef4444;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:9999px}
h1{font-size:22px;color:#f8fafc;margin:12px 0}
p{color:#94a3b8;font-size:14px;margin-bottom:20px}
.step{background:rgba(30,41,59,.7);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px 16px;margin-bottom:12px}
.st{font-weight:600;color:#38bdf8;font-size:14px;margin-bottom:6px}
code{background:#020617;color:#38bdf8;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px}
</style></head><body>
<div class="box">
<span class="badge">401 UNAUTHORIZED</span>
<h1>UUID Configuration Required</h1>
<p>Galaxy-Tunnel VLESS is running, but no valid UUID is configured.</p>
<div class="step"><div class="st">1. Generate UUID</div><div>Run <code>uuidgen</code> or visit uuidgenerator.net</div></div>
<div class="step"><div class="st">2. Set Environment Variable</div><div>In Cloudflare Dashboard, add <code>UUID</code> variable with your UUID.</div></div>
<div class="step"><div class="st">3. Deploy</div><div>Run <code>wrangler deploy</code> after setting the variable.</div></div>
</div></body></html>`;
}

function get404Page() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="robots" content="noindex,nofollow"><title>404</title>
<style>body{font-family:sans-serif;background:#fff;color:#222;text-align:center;padding:50px}h1{font-size:32px;margin-bottom:10px}p{color:#666}</style>
</head><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>`;
}

// ============================================================
// 9. VLESS HEADER PARSER
// ============================================================
const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function bytesToUUID(arr, offset = 0) {
  return (byteToHex[arr[offset]]   + byteToHex[arr[offset+1]] + byteToHex[arr[offset+2]] + byteToHex[arr[offset+3]] + "-"
        + byteToHex[arr[offset+4]] + byteToHex[arr[offset+5]] + "-"
        + byteToHex[arr[offset+6]] + byteToHex[arr[offset+7]] + "-"
        + byteToHex[arr[offset+8]] + byteToHex[arr[offset+9]] + "-"
        + byteToHex[arr[offset+10]] + byteToHex[arr[offset+11]] + byteToHex[arr[offset+12]]
        + byteToHex[arr[offset+13]] + byteToHex[arr[offset+14]] + byteToHex[arr[offset+15]]).toLowerCase();
}

function processVlessHeader(buffer, validUUIDs) {
  if (buffer.byteLength < 24) return { hasError: true, message: "Invalid VLESS data" };

  const version = new Uint8Array(buffer.slice(0, 1))[0];
  if (version !== VLESS_PROTOCOL_VERSION) {
    return { hasError: true, message: `Unsupported VLESS version ${version}` };
  }

  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const uuid = bytesToUUID(uuidBytes);

  if (!validUUIDs.includes(uuid)) {
    return { hasError: true, message: "Invalid VLESS user" };
  }

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const command = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];

  let isUDP = false;
  if (command === VLESS_COMMAND_TCP) isUDP = false;
  else if (command === VLESS_COMMAND_UDP) isUDP = true;
  else return { hasError: true, message: `VLESS command ${command} not supported` };

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];

  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: {
      addressLength = 16;
      const dv = new DataView(buffer.slice(addressValueIndex, addressValueIndex + 16));
      const hextets = [];
      for (let i = 0; i < 8; i++) hextets.push(dv.getUint16(i * 2));
      addressValue = formatIPv6(hextets);
      break;
    }
    default:
      return { hasError: true, message: `Invalid address type ${addressType}` };
  }

  if (!addressValue) return { hasError: true, message: "Empty address" };

  return {
    hasError: false,
    uuid,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    // VLESS spec: response = [version, 0] — 2 bytes only
    responseHeader: new Uint8Array([version, 0]),
    isUDP,
    protocol: "vless"
  };
}

// ============================================================
// 10. TROJAN HEADER PARSER
// ============================================================
async function sha224Hex(input) {
  // Cloudflare Workers supports SHA-256; Trojan uses SHA-224.
  // Compute SHA-256 and truncate to 28 bytes (224 bits) — matches Trojan spec.
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash).slice(0, 28);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function processTrojanHeader(buffer, password) {
  if (!password || buffer.byteLength < 58) {
    return { hasError: true, message: "Invalid Trojan data" };
  }

  const pwdHex = Array.from(new Uint8Array(buffer.slice(0, 56)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  const expected = await sha224Hex(password);
  if (pwdHex !== expected) {
    return { hasError: true, message: "Invalid Trojan password" };
  }

  let cursor = 56;
  if (buffer[cursor] !== 0x0d || buffer[cursor + 1] !== 0x0a) {
    return { hasError: true, message: "Invalid Trojan CRLF" };
  }
  cursor += 2;

  const addressType = buffer[cursor++];
  let addressRemote = "", addressLength = 0;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressRemote = new Uint8Array(buffer.slice(cursor, cursor + 4)).join(".");
      break;
    case 3:
      addressLength = buffer[cursor++];
      addressRemote = new TextDecoder().decode(buffer.slice(cursor, cursor + addressLength));
      break;
    case 4: {
      addressLength = 16;
      const dv = new DataView(buffer.slice(cursor, cursor + 16));
      const h = [];
      for (let i = 0; i < 8; i++) h.push(dv.getUint16(i * 2));
      addressRemote = formatIPv6(h);
      break;
    }
    default:
      return { hasError: true, message: `Invalid Trojan address type ${addressType}` };
  }

  cursor += addressLength;
  const portRemote = new DataView(buffer.slice(cursor, cursor + 2)).getUint16(0);
  cursor += 2;
  if (buffer[cursor] !== 0x0d || buffer[cursor + 1] !== 0x0a) {
    return { hasError: true, message: "Invalid Trojan CRLF #2" };
  }
  cursor += 2;

  return {
    hasError: false,
    addressRemote, addressType, portRemote,
    rawDataIndex: cursor,
    responseHeader: new Uint8Array([0, 0]),
    isUDP: false,
    protocol: "trojan"
  };
}

// ============================================================
// 11. UTILITIES
// ============================================================
function base64ToArrayBuffer(b64) {
  if (!b64) return { earlyData: null, error: null };
  try {
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    const dec = atob(b64);
    const buf = Uint8Array.from(dec, c => c.charCodeAt(0));
    return { earlyData: buf.buffer, error: null };
  } catch (e) { return { earlyData: null, error: e }; }
}

function concatBuffers(...bufs) {
  let total = 0;
  for (const b of bufs) total += b.byteLength || b.length || 0;
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    const arr = b instanceof Uint8Array ? b : new Uint8Array(b);
    out.set(arr, off);
    off += arr.byteLength;
  }
  return out.buffer;
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === 1 || ws.readyState === 2) ws.close();
  } catch {}
}

// ============================================================
// 12. WEBSOCKET STREAM
// ============================================================
function makeReadableWebSocketStream(ws, earlyDataHeader, logger) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener("message", e => {
        try { controller.enqueue(e.data); } catch {}
      });
      ws.addEventListener("close", () => {
        safeCloseWebSocket(ws);
        try { controller.close(); } catch {}
      });
      ws.addEventListener("error", err => {
        logger?.error("WS_EVENT_ERROR", { error: err.message });
        try { controller.error(err); } catch {}
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) { try { controller.error(error); } catch {} }
      else if (earlyData) {
        try { controller.enqueue(earlyData); } catch {}
      }
    },
    cancel(reason) {
      logger?.warn("WS_STREAM_CANCEL", { reason: String(reason) });
      safeCloseWebSocket(ws);
    }
  });
}

// ============================================================
// 13. TCP OUTBOUND  ⭐ FIXED: proxy port 443, direct port portRemote
// ============================================================
async function handleTCPOutBound(
  remoteSocket, addressRemote, portRemote, rawClientData,
  webSocket, responseHeader, proxyPool, defaultProxy, listUrl, logger
) {
  let timeoutTimer = null;
  const resetTimeout = () => {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    timeoutTimer = setTimeout(() => {
      logger?.warn("CONNECTION_TIMEOUT", { address: addressRemote, port: portRemote });
      safeCloseWebSocket(webSocket);
      try { remoteSocket.value?.close?.(); } catch {}
    }, CONFIG.CONNECT_TIMEOUT_MS);
  };

  async function connectAndWrite(host, port, label) {
    resetTimeout();
    const sock = connect({ hostname: host, port });
    remoteSocket.value = sock;
    logger?.info("TCP_CONNECTING", { target: `${host}:${port}`, mode: label });
    const writer = sock.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return sock;
  }

  async function retryViaProxy() {
    const activeProxy = await proxyPool.get(defaultProxy, listUrl, logger);
    const target = activeProxy || addressRemote;
    // ⭐ FIX: proxy server port = 443 (NOT target port)
    const proxyPort = CONFIG.PROXY_PORT_DEFAULT;
    logger?.info("RETRY_VIA_PROXY", { proxy: target, port: proxyPort });

    try {
      const sock = await connectAndWrite(target, proxyPort, "proxy");
      sock.closed
        .catch(e => logger?.warn("RETRY_TCP_CLOSED", { error: e.message }))
        .finally(() => {
          if (timeoutTimer) clearTimeout(timeoutTimer);
          safeCloseWebSocket(webSocket);
        });
      await remoteSocketToWS(sock, webSocket, responseHeader, null, logger, resetTimeout);
    } catch (e) {
      logger?.error("RETRY_FAILED", { error: e.message });
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    // Direct: use target port (portRemote)
    const sock = await connectAndWrite(addressRemote, portRemote, "direct");
    await remoteSocketToWS(sock, webSocket, responseHeader, retryViaProxy, logger, resetTimeout);
  } catch (e) {
    logger?.warn("DIRECT_FAIL_RETRY", { error: e.message });
    await retryViaProxy();
  }
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, logger, onActivity) {
  let header = responseHeader;
  let hasData = false;

  try {
    await remoteSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        hasData = true;
        if (onActivity) onActivity();
        if (webSocket.readyState !== 1) throw new Error("WS not open");

        if (header) {
          webSocket.send(concatBuffers(header, chunk));
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() { logger?.info("REMOTE_CLOSED", { hadData: hasData }); },
      abort(reason) { logger?.warn("REMOTE_ABORT", { reason: String(reason) }); }
    }));
  } catch (e) {
    logger?.error("REMOTE_PIPE_ERROR", { error: e.message });
    safeCloseWebSocket(webSocket);
  }

  if (!hasData && retry) {
    logger?.info("NO_DATA_RETRY");
    retry();
  }
}

// ============================================================
// 14. DNS OVER HTTPS (UDP :53)
// ============================================================
async function handleUDPOutBound(webSocket, responseHeader, dohURL, logger) {
  let headerSent = false;
  const transform = new TransformStream({
    transform(chunk, controller) {
      const view = new Uint8Array(chunk);
      for (let i = 0; i < view.byteLength;) {
        const len = (view[i] << 8) | view[i + 1];
        const data = view.slice(i + 2, i + 2 + len);
        i += 2 + len;
        controller.enqueue(data);
      }
    }
  });

  transform.readable.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        const resp = await fetch(dohURL, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: chunk
        });
        const result = await resp.arrayBuffer();
        const size = result.byteLength;
        const sizeBuf = new Uint8Array([(size >> 8) & 255, size & 255]);
        if (webSocket.readyState === 1) {
          logger?.info("DOH_OK", { size });
          const payload = headerSent
            ? concatBuffers(sizeBuf, result)
            : concatBuffers(responseHeader, sizeBuf, result);
          webSocket.send(payload);
          headerSent = true;
        }
      } catch (e) {
        logger?.error("DOH_FAIL", { error: e.message });
      }
    }
  })).catch(e => logger?.error("DOH_PIPE_FAIL", { error: e.message }));

  const writer = transform.writable.getWriter();
  return { write: chunk => writer.write(chunk) };
}

// ============================================================
// 15. WEBSOCKET PROXY HANDLER
// ============================================================
async function proxyOverWSHandler(request, validUUIDs, trojanPassword, defaultProxy, listUrl, dohURL, logger) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  let protocol = "unknown";

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, logger);

  const remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      // DNS continuation
      if (isDns && udpStreamWrite) return udpStreamWrite(chunk);

      // Existing remote socket → forward
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const buf = chunk instanceof ArrayBuffer ? chunk : new Uint8Array(chunk).buffer;
      const byteView = new Uint8Array(buf);

      // ---- Try VLESS ----
      let result = null;
      if (validUUIDs.length > 0) {
        result = processVlessHeader(byteView, validUUIDs);
        if (!result.hasError) protocol = "vless";
      }

      // ---- Try Trojan fallback ----
      if ((!result || result.hasError) && trojanPassword) {
        result = await processTrojanHeader(byteView, trojanPassword);
        if (!result.hasError) protocol = "trojan";
      }

      if (!result || result.hasError) {
        logger?.error("HEADER_PARSE_FAIL", { message: result?.message });
        throw new Error(result?.message || "Invalid protocol header");
      }

      const {
        addressRemote = "", portRemote = 443,
        rawDataIndex, responseHeader, isUDP
      } = result;

      // SSRF check
      if (isPrivateOrBlockedHost(addressRemote)) {
        logger?.warn("BLOCKED_PRIVATE_DEST", { address: addressRemote });
        throw new Error("Private destination blocked");
      }

      address = addressRemote;
      portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;
      logger?.info("TARGET_RESOLVED", { protocol, address, port: portRemote, isUDP });

      if (isUDP && portRemote !== 53) {
        logger?.warn("UDP_NON_DNS_REJECTED", { port: portRemote });
        throw new Error("UDP only enabled for DNS (port 53)");
      }
      if (isUDP && portRemote === 53) isDns = true;

      const rawClientData = byteView.slice(rawDataIndex);

      if (isDns) {
        const { write } = await handleUDPOutBound(webSocket, responseHeader, dohURL, logger);
        udpStreamWrite = write;
        udpStreamWrite(rawClientData);
        return;
      }

      handleTCPOutBound(
        remoteSocketWrapper, addressRemote, portRemote, rawClientData,
        webSocket, responseHeader, proxyPool, defaultProxy, listUrl, logger
      );
    },
    close() { logger?.info("WS_STREAM_CLOSED", { target: `${address}:${portWithRandomLog}` }); },
    abort(reason) { logger?.warn("WS_STREAM_ABORT", { reason: String(reason) }); }
  })).catch(err => {
    logger?.error("WS_PIPE_ERROR", { error: err.message });
    safeCloseWebSocket(webSocket);
  });

  // ⭐ Early Data echo back — required for `?ed=2048` clients
  const responseHeaders = {};
  if (earlyDataHeader) responseHeaders["Sec-WebSocket-Protocol"] = earlyDataHeader;

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: responseHeaders
  });
}

// ============================================================
// 16. MAIN FETCH HANDLER
// ============================================================
const proxyPool = new ProxyPoolManager(CONFIG.DEFAULT_PROXY_IPS, CONFIG.PROXY_POOL_TTL_MS);

export default {
  async fetch(request, env, ctx) {
    const requestId = genReqId();
    const clientIp =
      request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for") ||
      "unknown";
    const logger = new Logger(requestId, clientIp);

    // ---- Rate limit ----
    const rl = rateLimiter.check(clientIp);
    if (!rl.allowed) {
      logger.warn("RATE_LIMIT", { resetIn: rl.resetIn });
      return new Response(
        JSON.stringify({ error: "Too Many Requests", retryAfter: rl.resetIn }),
        {
          status: 429,
          headers: {
            ...getSecurityHeaders("application/json"),
            "Retry-After": String(rl.resetIn),
            "X-RateLimit-Limit": String(CONFIG.RATE_LIMIT_MAX_REQUESTS),
            "X-RateLimit-Remaining": "0"
          }
        }
      );
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/^\/+|\/+$/g, "");
    const clientPort = url.port || (url.protocol === "https:" ? "443" : "80");
    const isSecure = url.protocol === "https:";

    // ---- Env ----
    const userIDRaw = env.UUID || env.uuid || env.USER_ID || "";
    const trojanPassword = env.TROJAN_PASS || env.TROJAN_PASSWORD || env.PASSWORD || "";
    const proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || CONFIG.DEFAULT_PROXY_IPS[0];
    const rawProxyListUrl = env.PROXY_LIST_URL || "";
    const dohURL = env.DNS_RESOLVER_URL || CONFIG.DEFAULT_DOH_URL;
    const configuredWsPath = (env.WS_PATH || CONFIG.WS_PATH_DEFAULT).replace(/^\/+|\/+$/g, "");

    const validUUIDs = parseUUIDs(userIDRaw);

    logger.debug("REQ_IN", {
      method: request.method,
      path: pathname,
      port: clientPort,
      secure: isSecure,
      upgrade: request.headers.get("Upgrade")
    });

    // ---- CORS preflight ----
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getSecurityHeaders("text/plain") });
    }

    // ---- Health ----
    if (pathname === "health" || pathname === "api/health") {
      return new Response(JSON.stringify({
        status: "healthy",
        service: "galaxy-tunnel-ultimate",
        timestamp: new Date().toISOString(),
        port: clientPort,
        secure: isSecure,
        uuidConfigured: validUUIDs.length > 0,
        trojanConfigured: Boolean(trojanPassword),
        proxyPoolSize: proxyPool.size(),
        wsPath: configuredWsPath,
        rateLimitRemaining: rl.remaining
      }), { status: 200, headers: getSecurityHeaders("application/json") });
    }

    // ---- WebSocket Upgrade ----
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader === "websocket") {
      // Port whitelist (allow :80, :443, :8443 etc.)
      const portOk = CONFIG.ALLOWED_CLIENT_PORTS.includes(clientPort)
        || clientPort === "";
      if (!portOk) {
        logger.warn("WS_PORT_NOT_ALLOWED", { port: clientPort });
        return new Response(get404Page(), {
          status: 404,
          headers: getSecurityHeaders()
        });
      }

      // Path camouflage
      if (configuredWsPath && pathname !== configuredWsPath && pathname !== "") {
        logger.warn("WS_BAD_PATH", { path: pathname, expected: configuredWsPath });
        return new Response(get404Page(), {
          status: 404,
          headers: getSecurityHeaders()
        });
      }

      if (validUUIDs.length === 0 && !trojanPassword) {
        logger.warn("WS_NO_AUTH_CONFIGURED");
        return new Response(getUnauthorizedPage(), {
          status: 401,
          headers: getSecurityHeaders()
        });
      }

      logger.info("WS_UPGRADE_ACCEPT", { port: clientPort, secure: isSecure });
      try {
        return await proxyOverWSHandler(
          request, validUUIDs, trojanPassword,
          proxyIP, rawProxyListUrl, dohURL, logger
        );
      } catch (err) {
        logger.error("WS_HANDLER_ERROR", { error: err.message });
        return new Response("WebSocket error", { status: 500 });
      }
    }

    // ---- Normal web visit ----
    if (validUUIDs.length === 0 && !trojanPassword) {
      return new Response(getUnauthorizedPage(), {
        status: 401,
        headers: getSecurityHeaders()
      });
    }

    // Path camouflage for non-WS
    if (pathname !== "" && pathname !== configuredWsPath) {
      return new Response(get404Page(), {
        status: 404,
        headers: getSecurityHeaders()
      });
    }

    // ---- Config / subscription JSON ----
    if (pathname === "config") {
      return new Response(JSON.stringify({
        host: url.hostname,
        ports: {
          tls: 443,
          plain: 80
        },
        wsPath: configuredWsPath,
        earlyData: true,
        uuidConfigured: validUUIDs.length > 0,
        trojanConfigured: Boolean(trojanPassword),
        proxyPoolSize: proxyPool.size(),
        dohURL,
        timestamp: new Date().toISOString()
      }, null, 2), {
        status: 200,
        headers: getSecurityHeaders("application/json")
      });
    }

    // ---- Galaxy UI ----
    logger.info("GALAXY_PAGE", { port: clientPort, secure: isSecure });
    return new Response(getGalaxyPage(), {
      status: 200,
      headers: getSecurityHeaders()
    });
  }
};
