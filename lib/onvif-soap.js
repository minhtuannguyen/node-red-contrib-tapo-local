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
    const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const nonce   = crypto.randomBytes(16);
    const digest  = crypto.createHash('sha1')
        .update(Buffer.concat([
            nonce,
            Buffer.from(created,  'utf8'),
            Buffer.from(password, 'utf8'),
        ]))
        .digest('base64');
    return [
        '<wsse:Security s:mustUnderstand="1"',
        '  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"',
        '  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-utility-1.0.xsd">',
        '  <wsse:UsernameToken>',
        `    <wsse:Username>${escXml(username)}</wsse:Username>`,
        `    <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</wsse:Password>`,
        `    <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonce.toString('base64')}</wsse:Nonce>`,
        `    <wsu:Created>${created}</wsu:Created>`,
        '  </wsse:UsernameToken>',
        '</wsse:Security>',
    ].join('\n');
}

function escXml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── SOAP 1.2 envelope (all common namespaces pre-declared) ───────────────────
function soapEnvelope(body, username, password) {
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<s:Envelope',
        '  xmlns:s="http://www.w3.org/2003/05/soap-envelope"',
        '  xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"',
        '  xmlns:wsa="http://www.w3.org/2005/08/addressing"',
        '  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"',
        '  xmlns:tev="http://www.onvif.org/ver10/events/wsdl"',
        '  xmlns:trt="http://www.onvif.org/ver10/media/wsdl"',
        '  xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"',
        '  xmlns:tt="http://www.onvif.org/ver10/schema"',
        '  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"',
        '  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-utility-1.0.xsd">',
        `  <s:Header>${wsseHeader(username, password)}</s:Header>`,
        `  <s:Body>${body}</s:Body>`,
        '</s:Envelope>',
    ].join('\n');
}

// ── Raw HTTP/HTTPS SOAP POST ──────────────────────────────────────────────────
// _onReq (optional): called immediately with the raw http.ClientRequest so the
// caller can destroy() it to abort (e.g. for PTZ interrupts or doStop()).
function soapPost(urlStr, body, timeoutMs, _onReq) {
    return new Promise((resolve, reject) => {
        let parsed;
        try { parsed = new URL(urlStr); } catch (e) { return reject(new Error('Bad ONVIF URL: ' + urlStr)); }

        const isHttps = parsed.protocol === 'https:';
        const mod     = isHttps ? https : http;
        const data    = Buffer.from(body, 'utf8');
        const opts    = {
            hostname:           parsed.hostname,
            port:               parseInt(parsed.port, 10) || (isHttps ? 443 : 80),
            path:               parsed.pathname + (parsed.search || ''),
            method:             'POST',
            headers:            {
                'Content-Type':   'application/soap+xml; charset=utf-8',
                'Content-Length': data.length,
                'Connection':     'close',   // no keep-alive — camera has very limited sockets
            },
            timeout:            timeoutMs,
            rejectUnauthorized: false,
        };

        const req = mod.request(opts, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
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
function xmlFindAll(xml, tag) {
    const out = [];
    let m;
    const reSelf = new RegExp(`<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?\\/>`, 'gi');
    while ((m = reSelf.exec(xml)) !== null) out.push(m[0]);
    const reReg = new RegExp(
        `<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        'gi',
    );
    while ((m = reReg.exec(xml)) !== null) out.push(m[0]);
    return out;
}

function xmlInner(xml, tag) {
    const re = new RegExp(
        `<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        'i',
    );
    const m = re.exec(xml);
    return m ? m[1] : '';
}

function xmlText(xml, tag)  { return xmlInner(xml, tag).trim(); }

function xmlAttr(fragment, attr) {
    const m = new RegExp(`\\b${attr}="([^"]*)"`, 'i').exec(fragment);
    return m ? m[1] : null;
}

module.exports = { wsseHeader, escXml, soapEnvelope, soapPost, xmlFindAll, xmlInner, xmlText, xmlAttr };
