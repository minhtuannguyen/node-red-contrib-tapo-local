'use strict';

/**
 * Shared ONVIF SOAP utilities — zero npm deps.
 * Used by tapo-onvif-events and tapo-ptz nodes.
 */

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

// ── WSSE UsernameToken digest auth ────────────────────────────────────────────
function wsseHeader(username, password) {
    const iso     = new Date().toISOString();          // "2026-05-30T10:30:45.123Z"
    const created = iso.slice(0, 19) + 'Z';            // strip ms — no regex needed
    const nonce   = crypto.randomBytes(16);
    const digest  = crypto.createHash('sha1')
        .update(nonce)
        .update(created, 'utf8')
        .update(password, 'utf8')
        .digest('base64');
    // Template literal — single string allocation, no intermediate array.
    return `<wsse:Security s:mustUnderstand="1"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-utility-1.0.xsd">
  <wsse:UsernameToken>
    <wsse:Username>${escXml(username)}</wsse:Username>
    <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</wsse:Password>
    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonce.toString('base64')}</wsse:Nonce>
    <wsu:Created>${created}</wsu:Created>
  </wsse:UsernameToken>
</wsse:Security>`;
}

// Cached escape map and regex — avoids 4 intermediate strings per SOAP call.
const _xmlEscMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
const _xmlEscRe  = /[&<>"]/g;
function escXml(s) { return String(s).replace(_xmlEscRe, c => _xmlEscMap[c]); }

// ── SOAP 1.2 envelope (all common namespaces pre-declared) ───────────────────
function soapEnvelope(body, username, password) {
    // Template literal — single string allocation, no intermediate array.
    return `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
  xmlns:wsa="http://www.w3.org/2005/08/addressing"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
  xmlns:tev="http://www.onvif.org/ver10/events/wsdl"
  xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
  xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-utility-1.0.xsd">
  <s:Header>${wsseHeader(username, password)}</s:Header>
  <s:Body>${body}</s:Body>
</s:Envelope>`;
}

// ── Raw HTTP/HTTPS SOAP POST ──────────────────────────────────────────────────
// _onReq (optional): called immediately with the raw http.ClientRequest so the
// caller can destroy() it to abort (e.g. for PTZ interrupts or doStop()).
// Per-URL route cache — the PullMessages loop reuses the same subscriptionUrl
// every ~5 s.  Cache all derived scalars (hostname, port, path, mod) so the
// hot path allocates only the Buffer (body bytes) and nothing else for opts.
//
// MEMORY: Every CreatePullPointSubscription returns a NEW subscriptionUrl.
// Callers MUST call dropRoute(url) when they discard a subscription URL
// (Unsubscribe, SOAP fault, camera restart) — otherwise this Map grows forever
// on flaky cameras.  As a defensive backstop we also cap the map size below.
const _routeCache = new Map(); // urlStr → { hostname, port, path, isHttps, mod }
const ROUTE_CACHE_MAX = 32;    // ample for one camera (deviceUrl + eventUrl + subscriptionUrl + a few PTZ URLs)

// Remove a URL from the route cache.  Safe to call even if not present.
// Used by tapo-onvif-events to release memory tied to short-lived subscription URLs.
function dropRoute(urlStr) { _routeCache.delete(urlStr); }

function soapPost(urlStr, body, timeoutMs, _onReq) {
    return new Promise((resolve, reject) => {
        let route = _routeCache.get(urlStr);
        if (!route) {
            let parsed;
            try { parsed = new URL(urlStr); } catch (e) { return reject(new Error('Bad ONVIF URL: ' + urlStr)); }
            const isHttps = parsed.protocol === 'https:';
            route = {
                hostname: parsed.hostname,
                port:     parseInt(parsed.port, 10) || (isHttps ? 443 : 80),
                path:     parsed.pathname + (parsed.search || ''),
                isHttps,
                mod:      isHttps ? https : http,
                // Pre-allocated headers object — Content-Length is the only field
                // that varies per call; all other fields are constant for this URL.
                headers:  {
                    'Content-Type': 'application/soap+xml; charset=utf-8',
                    'Content-Length': 0,
                    'Connection':    'close',
                },
            };
            // Defensive cap: if a caller forgets to dropRoute() a discarded URL,
            // evict the oldest entry (insertion order in a Map) so the cache
            // can never leak unboundedly across many camera reconnects.
            if (_routeCache.size >= ROUTE_CACHE_MAX) {
                const oldest = _routeCache.keys().next().value;
                if (oldest !== undefined) _routeCache.delete(oldest);
            }
            _routeCache.set(urlStr, route);
        }

        const data = Buffer.from(body, 'utf8');
        // Re-use the cached headers object — only Content-Length changes per call.
        // Node.js copies header values at request() time so mutation after the call is safe.
        route.headers['Content-Length'] = data.length;
        const opts = {
            hostname:           route.hostname,
            port:               route.port,
            path:               route.path,
            method:             'POST',
            headers:            route.headers,
            timeout:            timeoutMs,
            rejectUnauthorized: false,
        };

        const MAX_RESPONSE_BYTES = 512 * 1024; // 512 KB — reject runaway responses
        const req = route.mod.request(opts, (res) => {
            const chunks = [];
            let totalBytes = 0;
            res.on('data', c => {
                totalBytes += c.length;
                if (totalBytes > MAX_RESPONSE_BYTES) {
                    req.destroy(new Error(`ONVIF response too large (>${MAX_RESPONSE_BYTES} bytes) — ${urlStr}`));
                    return;
                }
                chunks.push(c);
            });
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });
        if (_onReq) _onReq(req);
        req.on('timeout', () => req.destroy(new Error(`ONVIF SOAP timeout (${timeoutMs}ms) — ${urlStr}`)));
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

// ── Minimal XML helpers ───────────────────────────────────────────────────────
// RegExp cache — avoid recompiling the same patterns on every ONVIF poll response.
const _reInnerCache = new Map();
const _reFindCache  = new Map();
const _reAttrCache  = new Map();

function xmlFindAll(xml, tag) {
    let pair = _reFindCache.get(tag);
    if (!pair) {
        pair = [
            new RegExp(`<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?\\/>`, 'gi'),
            new RegExp(`<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`, 'gi'),
        ];
        _reFindCache.set(tag, pair);
    }
    const [reSelf, reReg] = pair;
    // Reset lastIndex — global regexps track state between calls
    reSelf.lastIndex = 0; reReg.lastIndex = 0;
    const out = [];
    let m;
    while ((m = reSelf.exec(xml)) !== null) out.push(m[0]);
    while ((m = reReg.exec(xml))  !== null) out.push(m[0]);
    return out;
}

function xmlInner(xml, tag) {
    let re = _reInnerCache.get(tag);
    if (!re) {
        re = new RegExp(`<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`, 'i');
        _reInnerCache.set(tag, re);
    }
    const m = re.exec(xml);
    return m ? m[1] : '';
}

function xmlText(xml, tag)  { return xmlInner(xml, tag).trim(); }

function xmlAttr(fragment, attr) {
    let re = _reAttrCache.get(attr);
    if (!re) {
        re = new RegExp(`\\b${attr}="([^"]*)"`, 'i');
        _reAttrCache.set(attr, re);
    }
    const m = re.exec(fragment);
    return m ? m[1] : null;
}

module.exports = { wsseHeader, escXml, soapEnvelope, soapPost, dropRoute, xmlFindAll, xmlInner, xmlText, xmlAttr };
