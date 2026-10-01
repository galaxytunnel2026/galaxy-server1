import { connect } from "cloudflare:sockets";

// ============================================
// ENV VARIABLES
// ============================================
var userID = "";                    // VLESS: UUID (optional if only TROJAN)
var trojanPass = "";              // TROJAN: password (optional if only VLESS)
var proxyIP = "213.133.116.44";
var githubProxyURL = "";
var dohURL = "https://cloudflare-gateway.com/dns-query";

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// ============================================
// SHA224 Pure JS (Cloudflare Workers compatible)
// ============================================
function sha224(str) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let result = '';
    const words = [];
    const asciiBitLength = str.length * 8;
    let hash = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let s = str;
    s += '\x80';
    while (s.length % 64 - 56) s += '\x00';
    for (let i = 0; i < s.length; i++) {
        const j = s.charCodeAt(i);
        if (j >> 8) return null;
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength);
    for (let j = 0; j < words.length;) {
        const w = words.slice(j, j += 16);
        const oldHash = hash.slice(0);
        for (let i = 0; i < 64; i++) {
            if (i >= 16) {
                const w15 = w[i - 15], w2 = w[i - 2];
                w[i] = (
                    w[i - 16] +
                    (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                    w[i - 7] +
                    (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                ) | 0;
            }
            const a = hash[0], e = hash[4];
            const temp1 = (
                hash[7] +
                (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
                ((e & hash[5]) ^ (~e & hash[6])) +
                k[i] +
                w[i]
            );
            const temp2 = (
                (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
                ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]))
            );
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
            hash.pop();
        }
        for (let i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }
    for (let i = 0; i < 7; i++) {
        const hex = hash[i];
        result += ((hex >> 28) & 0xf).toString(16) +
            ((hex >> 24) & 0xf).toString(16) +
            ((hex >> 20) & 0xf).toString(16) +
            ((hex >> 16) & 0xf).toString(16) +
            ((hex >> 12) & 0xf).toString(16) +
            ((hex >> 8) & 0xf).toString(16) +
            ((hex >> 4) & 0xf).toString(16) +
            (hex & 0xf).toString(16);
    }
    return result;
}

function hashTrojanPassword(password) {
    return sha224(password);
}

// ============================================
// ProxyIP Fetch
// ============================================
async function getDynamicProxyIP(defaultProxy, rawUrl) {
    if (!rawUrl || rawUrl.includes("YOUR_USERNAME")) return defaultProxy;
    try {
        const response = await fetch(rawUrl, { cf: { cacheTtl: 300, cacheEverything: true } });
        if (response.ok) {
            const text = await response.text();
            const ipList = text.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0 && !line.startsWith('#'));
            if (ipList.length > 0) return ipList[Math.floor(Math.random() * ipList.length)];
        }
    } catch (err) {
        console.error("GitHub ProxyIP Fetch Error:", err);
    }
    return defaultProxy;
}

// ============================================
// Main Worker
// ============================================
var worker_default = {
    async fetch(request, env, ctx) {
        userID = env.UUID || env.uuid || userID;
        trojanPass = env.TROJAN_PASS || env.trojan_pass || trojanPass;
        proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || proxyIP;
        githubProxyURL = env.PROXY_LIST_URL || githubProxyURL;
        dohURL = env.DNS_RESOLVER_URL || dohURL;

        const hasVless = isValidUUID(userID);
        const hasTrojan = !!trojanPass;

        if (!hasVless && !hasTrojan) {
            return new Response(
                `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Config Error</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;}
.box{background:#1e293b;padding:40px;border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,0.3);}
h1{color:#f87171;} code{background:#334155;padding:2px 8px;border-radius:4px;}</style>
</head>
<body>
<div class="box">
<h1>⚠️ Config Not Configured</h1>
<p>Please set <code>UUID</code> (for VLESS) or <code>TROJAN_PASS</code> (for TROJAN).</p>
</div>
</body></html>`,
                { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } }
            );
        }

        const upgradeHeader = request.headers.get("Upgrade");
        if (upgradeHeader === "websocket") {
            return await proxyOverWSHandler(request);
        }
        return new Response(getGalaxyPage(), {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" }
        });
    }
};

// ============================================
// WebSocket Handler — Dual Protocol
// ============================================
async function proxyOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const firstByte = new Uint8Array(chunk.slice(0, 1))[0];
            let result = null;
            let protocolType = "unknown";

            // Try VLESS first (version byte == 0x00)
            if (firstByte === 0x00 && isValidUUID(userID)) {
                try {
                    result = processVlessHeader(chunk, userID);
                    if (!result.hasError) protocolType = "vless";
                } catch (e) {
                    result = { hasError: true, message: e.message };
                }
            }

            // Fallback to TROJAN
            if ((!result || result.hasError) && trojanPass) {
                result = processTrojanHeader(chunk, trojanPass);
                if (result && !result.hasError) protocolType = "trojan";
            }

            if (!result || result.hasError) {
                throw new Error(result ? result.message : "Invalid protocol header");
            }

            const {
                addressRemote = "",
                portRemote = 443,
                rawDataIndex,
                responseHeader,
                isUDP
            } = result;

            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"} [${protocolType}]`;

            if (isUDP && portRemote !== 53) {
                throw new Error("UDP proxy only enabled for DNS (port 53)");
            }
            if (isUDP && portRemote === 53) isDns = true;

            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log);
        },
        close() { log("WebSocket stream closed"); },
        abort(reason) { log("WebSocket stream aborted", JSON.stringify(reason)); }
    })).catch((err) => {
        log("WebSocket pipeTo error", err);
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// TCP Outbound
// ============================================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        log(`Connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        const activeProxy = await getDynamicProxyIP(proxyIP, githubProxyURL);
        const target = activeProxy || addressRemote;
        log(`Retrying connection via ProxyIP: ${target}`);
        const tcpSocket = await connectAndWrite(target, portRemote);
        tcpSocket.closed.catch((error) => {
            console.log("Retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket, webSocket, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

// ============================================
// WebSocket Stream
// ============================================
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("WebSocket error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel(reason) {
            log(`ReadableStream canceled: ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
}

// ============================================
// VLESS Header Parser
// ============================================
function processVlessHeader(vlessBuffer, userID2) {
    if (vlessBuffer.byteLength < 24) {
        return { hasError: true, message: "Invalid VLESS data" };
    }
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
    const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim());

    if (!isValidUser) {
        return { hasError: true, message: "Invalid VLESS user" };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    let isUDP = false;
    if (command === 1) isUDP = false;
    else if (command === 2) isUDP = true;
    else return { hasError: true, message: `VLESS command ${command} not supported` };

    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
    }

    if (!addressValue) return { hasError: true, message: "VLESS address value is empty" };

    const responseHeader = new Uint8Array([version[0], 0]);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        responseHeader,
        isUDP
    };
}

// ============================================
// TROJAN Header Parser
// ============================================
function processTrojanHeader(trojanBuffer, password) {
    if (trojanBuffer.byteLength < 58) {
        return { hasError: true, message: "Invalid TROJAN data: too short" };
    }
    const bytes = new Uint8Array(trojanBuffer);
    const dataView = new DataView(trojanBuffer);

    if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
        return { hasError: true, message: "Invalid TROJAN header: missing CRLF after hash" };
    }

    const receivedHash = new TextDecoder().decode(bytes.slice(0, 56));
    const expectedHash = hashTrojanPassword(password);

    if (receivedHash !== expectedHash) {
        return { hasError: true, message: "Invalid TROJAN password" };
    }

    const command = bytes[58];
    if (command !== 0x01 && command !== 0x03) {
        return { hasError: true, message: `Unsupported TROJAN command: ${command}` };
    }

    const addressType = bytes[59];
    let addressValue, addressLength, addressValueIndex;

    switch (addressType) {
        case 0x01:
            addressLength = 4;
            addressValueIndex = 60;
            if (trojanBuffer.byteLength < addressValueIndex + addressLength + 2) {
                return { hasError: true, message: "Invalid TROJAN header: IPv4 truncated" };
            }
            addressValue = Array.from(bytes.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 0x03:
            addressLength = bytes[60];
            addressValueIndex = 61;
            if (trojanBuffer.byteLength < addressValueIndex + addressLength + 2) {
                return { hasError: true, message: "Invalid TROJAN header: domain truncated" };
            }
            addressValue = new TextDecoder().decode(bytes.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 0x04:
            addressLength = 16;
            addressValueIndex = 60;
            if (trojanBuffer.byteLength < addressValueIndex + addressLength + 2) {
                return { hasError: true, message: "Invalid TROJAN header: IPv6 truncated" };
            }
            addressValue = Array.from({ length: 8 }, (_, i) =>
                dataView.getUint16(addressValueIndex + i * 2).toString(16)
            ).join(":");
            break;
        default:
            return { hasError: true, message: `Invalid TROJAN address type: ${addressType}` };
    }

    const portIndex = addressValueIndex + addressLength;
    const portRemote = dataView.getUint16(portIndex);

    const crlfIndex = portIndex + 2;
    if (bytes[crlfIndex] !== 0x0d || bytes[crlfIndex + 1] !== 0x0a) {
        return { hasError: true, message: "Invalid TROJAN header: missing final CRLF" };
    }

    const rawDataIndex = crlfIndex + 2;
    console.log(`TROJAN: target ${addressValue}:${portRemote}, UDP: ${command === 0x03}`);

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType === 0x03 ? 2 : addressType,
        portRemote,
        rawDataIndex,
        responseHeader: new Uint8Array(0),
        isUDP: command === 0x03
    };
}

// ============================================
// Relay: Remote → WebSocket
// ============================================
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== 1) {
                controller.error("WebSocket not open");
            }
            if (header && header.byteLength > 0) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() {
            log(`Remote connection closed (had data: ${hasIncomingData})`);
        },
        abort(reason) {
            console.error("Remote readable abort", reason);
        }
    })).catch((error) => {
        console.error("remoteSocketToWS error", error.stack || error);
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        log("Retrying connection...");
        retry();
    }
}

// ============================================
// Utilities
// ============================================
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

var byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) throw TypeError("Stringified UUID is invalid");
    return uuid;
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) socket.close();
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

// ============================================
// UDP / DoH Handler
// ============================================
async function handleUDPOutBound(webSocket, responseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength; ) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {}
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dohURL, {
                method: "POST",
                headers: { "content-type": "application/dns-message" },
                body: chunk
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);

            if (webSocket.readyState === 1) {
                log(`DoH success, DNS message length: ${udpSize}`);
                if (isHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log("DNS UDP error" + error);
    });

    const writer = transformStream.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
}

// ============================================
// Galaxy UI
// ============================================
function getGalaxyPage() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Galaxy-Tunnel VLESS / TROJAN</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body, html {
      width: 100%; height: 100%;
      background: #02060d; overflow: hidden;
      font-family: 'Segoe UI', Arial, sans-serif;
      display: flex; justify-content: center; align-items: center;
    }
    .space-bg {
      position: absolute; width: 100%; height: 100%;
      background:
        radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%),
        radial-gradient(circle at 80% 80%, rgba(0, 150, 200, 0.15) 0%, transparent 50%),
        #02060d;
      z-index: 1;
    }
    .starfield {
      position: absolute; width: 100%; height: 100%;
      background-image:
        radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)),
        radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 160px 120px, rgba(0,212,255,0.9), rgba(0,0,0,0));
      background-repeat: repeat; background-size: 220px 220px;
      animation: starTwinkle 4s ease-in-out infinite alternate; opacity: 0.6;
    }
    @keyframes starTwinkle {
      0% { opacity: 0.4; transform: scale(1); }
      100% { opacity: 0.8; transform: scale(1.02); }
    }
    .card-frame {
      position: relative; z-index: 10;
      width: 90vw; max-width: 480px; aspect-ratio: 1 / 1;
      background: rgba(4, 12, 24, 0.75);
      border: 1.5px solid rgba(0, 212, 255, 0.6);
      box-shadow: 0 0 25px rgba(0, 212, 255, 0.25), inset 0 0 25px rgba(0, 212, 255, 0.1);
      backdrop-filter: blur(12px);
      display: flex; flex-direction: column; justify-content: space-between; align-items: center;
      padding: 35px 25px 25px 25px; border-radius: 4px;
    }
    .graphic-container {
      position: relative; width: 230px; height: 230px;
      display: flex; justify-content: center; align-items: center;
    }
    .ring {
      position: absolute; width: 240px; height: 75px;
      border: 2px solid rgba(0, 230, 255, 0.85); border-radius: 50%;
      transform: rotate(-28deg);
      box-shadow: 0 0 15px rgba(0, 212, 255, 0.8), inset 0 0 15px rgba(0, 212, 255, 0.5);
      pointer-events: none; animation: ringGlow 3s ease-in-out infinite alternate;
    }
    @keyframes ringGlow {
      0% { opacity: 0.7; box-shadow: 0 0 12px rgba(0,212,255,0.6); }
      100% { opacity: 1; box-shadow: 0 0 25px rgba(0,212,255,1); }
    }
    canvas { position: absolute; top: 0; left: 0; }
    .content-bottom {
      width: 100%; display: flex; flex-direction: column; align-items: center;
      text-align: center; position: relative;
    }
    .title {
      font-size: 34px; font-weight: 900; font-style: italic;
      color: #ffffff; letter-spacing: 2px; text-transform: uppercase;
      text-shadow: 0 0 12px rgba(255, 255, 255, 0.7); line-height: 1.1;
    }
    .subtitle {
      font-size: 16px; font-weight: 600; color: #7b93a7;
      letter-spacing: 5px; margin-top: 6px; text-transform: uppercase;
    }
    .access-badge {
      align-self: flex-end; margin-top: 15px; font-size: 20px;
      font-weight: 900; font-style: italic; color: #00e5ff;
      text-transform: uppercase; text-align: right; letter-spacing: 1px; line-height: 1.1;
      text-shadow: 0 0 15px rgba(0, 229, 255, 0.85); animation: statusPulse 2s infinite alternate;
    }
    @keyframes statusPulse {
      0% { opacity: 0.8; text-shadow: 0 0 8px rgba(0,229,255,0.5); }
      100% { opacity: 1; text-shadow: 0 0 20px rgba(0,229,255,1); }
    }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>
  <div class="card-frame">
    <div class="graphic-container">
      <div class="ring"></div>
      <canvas id="nodeCanvas" width="230" height="230"></canvas>
    </div>
    <div class="content-bottom">
      <h1 class="title">GALAXY-TUNNEL</h1>
      <div class="subtitle">VLESS / TROJAN</div>
      <div class="access-badge">
        GALAXY VPROXY<br>IS ACCESS
      </div>
    </div>
  </div>
  <script>
    const canvas = document.getElementById('nodeCanvas');
    const ctx = canvas.getContext('2d');
    const numNodes = 32; const nodes = []; const radius = 75;
    let angleX = 0.004; let angleY = 0.007;

    for (let i = 0; i < numNodes; i++) {
      let theta = Math.acos(Math.random() * 2 - 1);
      let phi = Math.random() * Math.PI * 2;
      nodes.push({
        x: radius * Math.sin(theta) * Math.cos(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(theta)
      });
    }

    function rotateX(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let y1 = node.y * cos - node.z * sin;
      let z1 = node.z * cos + node.y * sin;
      node.y = y1; node.z = z1;
    }

    function rotateY(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let x1 = node.x * cos - node.z * sin;
      let z1 = node.z * cos + node.x * sin;
      node.x = x1; node.z = z1;
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      let cx = canvas.width / 2; let cy = canvas.height / 2;

      nodes.forEach(node => {
        rotateX(node, angleX);
        rotateY(node, angleY);
      });

      ctx.strokeStyle = 'rgba(0, 220, 255, 0.35)';
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          let dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
          if (dist < 60) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x + cx, nodes[i].y + cy);
            ctx.lineTo(nodes[j].x + cx, nodes[j].y + cy);
            ctx.stroke();
          }
        }
      }

      nodes.forEach(node => {
        let size = (node.z + radius) / (2 * radius) * 3 + 2;
        ctx.beginPath();
        ctx.arc(node.x + cx, node.y + cy, size, 0, Math.PI * 2);
        ctx.fillStyle = '#00f0ff';
        ctx.shadowBlur = 8; ctx.shadowColor = '#00f0ff';
        ctx.fill(); ctx.shadowBlur = 0;
      });

      requestAnimationFrame(draw);
    }
    draw();
  </script>
</body>
</html>`;
}

export default worker_default;
