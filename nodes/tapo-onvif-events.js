'use strict';

/**
 * tapo-onvif-events — ONVIF WS-PullPoint event node for Tapo C225.
 *
 * Implements ONVIF event subscription directly via raw HTTP SOAP — no `onvif`
 * npm library.  Full control means:
 *
 *  • Zero HTTP requests sent to the camera while stopped.
 *  • Proper ONVIF Unsubscribe sent on stop (camera frees the pull-point).
 *  • Exponential back-off we control (3 s → 6 s → … → 2 min max).
 *  • Tapo C225 quirk handled: camera sends "Initialized" events batched every
 *    ~14 s while motion is present (not "Changed" events on state change).
 *    Debounce + configurable watchdog emit clean detected:true / detected:false.
 *
 * Input:  msg.action = "start" | "stop"
 * Output: { topic, payload: { detected, time, property, source, data } }
 *
 * ONVIF WS-PullPoint flow:
 *   1. GetCapabilities          → discover event service XAddr
 *   2. CreatePullPointSubscription → subscriptionUrl (valid for ttl seconds)
 *   3. PullMessages loop        → camera holds ≤pullTimeoutSec per call
 *   4. Renew every 50 s         → keep subscription alive (TTL = 60 s)
 *   5. Unsubscribe on stop      → camera cleans up immediately
 */

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

// ── WSSE UsernameToken digest auth (ONVIF §5 / WS-UsernameToken profile) ──────
function wsseHeader(username, password) {
    // Created: ISO 8601 without milliseconds (most cameras accept either)
    const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const nonce   = crypto.randomBytes(16);
    // PasswordDigest = Base64(SHA-1( nonce_bytes ‖ created_utf8 ‖ password_utf8 ))
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

// ── SOAP 1.2 envelope ─────────────────────────────────────────────────────────
function soapEnvelope(body, username, password) {
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<s:Envelope',
        '  xmlns:s="http://www.w3.org/2003/05/soap-envelope"',
        '  xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"',
        '  xmlns:wsa="http://www.w3.org/2005/08/addressing"',
        '  xmlns:tev="http://www.onvif.org/ver10/events/wsdl"',
        '  xmlns:tds="http://www.onvif.org/ver10/device/wsdl"',
        '  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"',
        '  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-utility-1.0.xsd">',
        `  <s:Header>${wsseHeader(username, password)}</s:Header>`,
        `  <s:Body>${body}</s:Body>`,
        '</s:Envelope>',
    ].join('\n');
}

// ── Raw HTTP/HTTPS SOAP POST (no keep-alive — camera has very limited sockets) ─
function soapPost(urlStr, body, timeoutMs) {
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
                'Connection':     'close',   // avoid leaving sockets open on the camera
            },
            timeout:            timeoutMs,
            rejectUnauthorized: false,
        };

        const req = mod.request(opts, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });
        req.on('timeout', () => req.destroy(new Error(`ONVIF SOAP timeout (${timeoutMs}ms) — ${urlStr}`)));
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

// ── Minimal XML helpers — zero deps ──────────────────────────────────────────
// Find all occurrences of <ns:tag .../> (self-closing) and
// <ns:tag ...>content</ns:tag> (regular) — returned as full element strings.
function xmlFindAll(xml, tag) {
    const out = [];
    let m;

    // 1. Self-closing: <ns:tag attr="..."/>
    const reSelf = new RegExp(`<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?\\/>`, 'gi');
    while ((m = reSelf.exec(xml)) !== null) out.push(m[0]);

    // 2. Regular: <ns:tag ...>content</ns:tag> — non-greedy inner content
    const reReg = new RegExp(
        `<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        'gi',
    );
    while ((m = reReg.exec(xml)) !== null) out.push(m[0]);

    return out;
}

// Return inner text of the first matching element (regular tags only).
function xmlInner(xml, tag) {
    const re = new RegExp(
        `<(?:[\\w.-]+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`,
        'i',
    );
    const m = re.exec(xml);
    return m ? m[1] : '';
}

function xmlText(xml, tag) { return xmlInner(xml, tag).trim(); }

function xmlAttr(fragment, attr) {
    const m = new RegExp(`\\b${attr}="([^"]*)"`, 'i').exec(fragment);
    return m ? m[1] : null;
}

// ── ONVIF operations ──────────────────────────────────────────────────────────
async function opGetCapabilities(deviceUrl, user, pass) {
    const xml = await soapPost(
        deviceUrl,
        soapEnvelope(
            '<tds:GetCapabilities><tds:Category>Events</tds:Category></tds:GetCapabilities>',
            user, pass,
        ),
        10000,
    );
    if (/[Ff]ault/.test(xml)) throw new Error('GetCapabilities SOAP fault: ' + xml.slice(0, 400));
    // Events XAddr is inside the <Events> or <tt:Events> element.
    const eventsEl = xmlInner(xml, 'Events');
    const xaddr    = xmlText(eventsEl || xml, 'XAddr') || xmlText(xml, 'XAddr');
    if (!xaddr) throw new Error('No Events XAddr in GetCapabilities response:\n' + xml.slice(0, 400));
    return xaddr;
}

async function opCreateSubscription(eventUrl, user, pass, ttlSecs = 60) {
    const xml = await soapPost(
        eventUrl,
        soapEnvelope(
            `<tev:CreatePullPointSubscription>\n  <tev:InitialTerminationTime>PT${ttlSecs}S</tev:InitialTerminationTime>\n</tev:CreatePullPointSubscription>`,
            user, pass,
        ),
        10000,
    );
    if (/[Ff]ault/.test(xml)) throw new Error('CreatePullPointSubscription SOAP fault: ' + xml.slice(0, 400));
    // Address is inside <SubscriptionReference><Address>…</Address></SubscriptionReference>
    const subRef = xmlInner(xml, 'SubscriptionReference');
    const addr   = xmlText(subRef || xml, 'Address') || xmlText(xml, 'Address');
    if (!addr) throw new Error('No subscription Address in response:\n' + xml.slice(0, 400));
    return addr;
}

// pullTimeoutSec: how long the camera holds the request open if no events.
// HTTP timeout is set to pullTimeoutSec + 4 s to give the camera time to reply.
async function opPullMessages(subUrl, user, pass, pullTimeoutSec, msgLimit = 100) {
    return soapPost(
        subUrl,
        soapEnvelope(
            `<tev:PullMessages>\n  <tev:Timeout>PT${pullTimeoutSec}S</tev:Timeout>\n  <tev:MessageLimit>${msgLimit}</tev:MessageLimit>\n</tev:PullMessages>`,
            user, pass,
        ),
        (pullTimeoutSec + 4) * 1000,
    );
}

async function opRenew(subUrl, user, pass, ttlSecs = 60) {
    return soapPost(
        subUrl,
        soapEnvelope(
            `<wsnt:Renew>\n  <wsnt:TerminationTime>PT${ttlSecs}S</wsnt:TerminationTime>\n</wsnt:Renew>`,
            user, pass,
        ),
        10000,
    );
}

async function opUnsubscribe(subUrl, user, pass) {
    return soapPost(
        subUrl,
        soapEnvelope('<wsnt:Unsubscribe/>', user, pass),
        5000,
    );
}

// ── Parse NotificationMessage elements from PullMessages response ─────────────
function parseEvents(xml) {
    return xmlFindAll(xml, 'NotificationMessage').map(msg => {
        // Strip namespace prefixes from topic  e.g. tns1:RuleEngine/tns1:PeopleDetector/People
        const topic    = xmlText(msg, 'Topic').replace(/[\w.-]+:/g, '').trim();
        // Inner <*:Message ...> element carries UtcTime, PropertyOperation, Source, Data
        const msgEl    = xmlInner(msg, 'Message');
        const property = xmlAttr(msgEl, 'PropertyOperation') || '';
        const time     = xmlAttr(msgEl, 'UtcTime')           || new Date().toISOString();

        const source = {};
        for (const si of xmlFindAll(xmlInner(msgEl, 'Source'), 'SimpleItem')) {
            const n = xmlAttr(si, 'Name');
            if (n) source[n] = xmlAttr(si, 'Value');
        }

        const data = {};
        for (const si of xmlFindAll(xmlInner(msgEl, 'Data'), 'SimpleItem')) {
            const n = xmlAttr(si, 'Name');
            if (n) data[n] = xmlAttr(si, 'Value');
        }

        return { topic, property, time, source, data };
    });
}

// ── Node-RED registration ─────────────────────────────────────────────────────
module.exports = function (RED) {

    function TapoOnvifEventsNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        const deviceNode      = RED.nodes.getNode(config.device);
        const onvifPort       = parseInt(config.onvifPort,    10) || 2020;
        const pullTimeoutSec  = parseInt(config.pullTimeout,  10) || 5;
        const motionTimeoutMs = (parseInt(config.motionTimeout, 10) || 30) * 1000;

        if (!deviceNode) {
            node.error('No Tapo device configured');
            node.status({ fill: 'red', shape: 'ring', text: 'no device' });
            return;
        }

        const ip      = deviceNode.ip;
        const user    = deviceNode.username;
        const getPass = () => deviceNode.credentials.password;

        const deviceUrl = `http://${ip}:${onvifPort}/onvif/device_service`;

        // ── Node state ────────────────────────────────────────────────────────
        let active          = false;   // true = poll loop should keep running
        let closed          = false;   // node has been closed/removed
        let eventUrl        = null;    // discovered event service XAddr
        let subscriptionUrl = null;    // active pull-point subscription URL
        let renewTimer      = null;    // setInterval for subscription renewal
        let wakeResolve     = null;    // resolves the current sleep() early on stop

        // Per-topic motion-detection state (reset on stop)
        let debounceTimers = {};
        let watchdogTimers = {};
        let motionActive   = {};
        let batchHasTrue   = {};
        let batchActive    = {};

        function clearMotionState() {
            Object.values(debounceTimers).forEach(clearTimeout);
            Object.values(watchdogTimers).forEach(clearTimeout);
            debounceTimers = {}; watchdogTimers = {};
            motionActive   = {}; batchHasTrue   = {}; batchActive = {};
        }

        // Interruptible sleep — wakeUp() resolves it immediately.
        function sleep(ms) {
            return new Promise(resolve => {
                const t    = setTimeout(resolve, ms);
                wakeResolve = () => { clearTimeout(t); resolve(); };
            });
        }
        function wakeUp() {
            if (wakeResolve) { wakeResolve(); wakeResolve = null; }
        }

        // Guard against sending after the node is closed.
        function safeSend(msg) {
            if (!closed) node.send(msg);
        }

        // ── Tapo C225 event processing ────────────────────────────────────────
        // The C225 does not send "Changed" events.  Instead it floods
        // "Initialized" events in batches every ~14 s while motion is present.
        // Strategy:
        //  • Reset watchdog on FIRST event of each batch (eliminates race where
        //    watchdog fires at exactly the same ms as the next batch arrives).
        //  • One 300 ms debounce per batch window to coalesce all batch events.
        //  • Watchdog (configurable, default 30 s) fires detected:false when
        //    the camera goes silent — must be > camera batch interval (~14 s).
        function processEvent(ev) {
            const key = ev.topic;

            // Resolve boolean detection from the first Data SimpleItem value.
            const vals       = Object.values(ev.data || {});
            const rawDetected = vals.length > 0 &&
                (vals[0] === 'true' || vals[0] === '1' || vals[0] === 'True');

            if (ev.property === 'Changed') {
                // Standard ONVIF camera: deduplicate same state.
                const now = !!rawDetected;
                if (motionActive[key] !== now) {
                    motionActive[key] = now;
                    safeSend({ topic: key, payload: { detected: now, time: ev.time, property: ev.property, source: ev.source, data: ev.data } });
                }
                return;
            }

            // Tapo C225 "Initialized" flood mode — batch + watchdog.
            if (rawDetected) batchHasTrue[key] = true;

            if (!batchActive[key]) {
                batchActive[key]  = true;
                const snap        = { ...ev };  // snapshot for delayed callbacks

                // If motion already active: reset watchdog immediately on the
                // FIRST event of this batch, not 300 ms later in the debounce.
                // This prevents the watchdog from racing with the next batch.
                if (motionActive[key]) {
                    clearTimeout(watchdogTimers[key]);
                    watchdogTimers[key] = setTimeout(() => {
                        motionActive[key] = false;
                        safeSend({ topic: key, payload: { detected: false, time: new Date().toISOString(), property: 'timeout', source: ev.source, data: {} } });
                    }, motionTimeoutMs);
                }

                // Debounce: wait 300 ms to collect all events in this batch.
                debounceTimers[key] = setTimeout(() => {
                    batchActive[key]   = false;
                    const detected     = batchHasTrue[key];
                    batchHasTrue[key]  = false;

                    if (detected && !motionActive[key]) {
                        // Motion just started — emit true and arm the watchdog.
                        motionActive[key] = true;
                        safeSend({ topic: snap.topic, payload: { detected: true, time: snap.time, property: snap.property, source: snap.source, data: snap.data } });
                        clearTimeout(watchdogTimers[key]);
                        watchdogTimers[key] = setTimeout(() => {
                            motionActive[key] = false;
                            safeSend({ topic: snap.topic, payload: { detected: false, time: new Date().toISOString(), property: 'timeout', source: snap.source, data: {} } });
                        }, motionTimeoutMs);
                    }
                }, 300);
            }
        }

        // ── Poll loop ─────────────────────────────────────────────────────────
        // Runs until active === false.  Manages its own subscriptions and
        // reconnects with exponential back-off on any error.
        async function pollLoop() {
            let backoffMs = 3000;
            node.status({ fill: 'blue', shape: 'dot', text: 'connecting…' });

            while (active) {

                // Step 1: discover event service URL (cached across reconnects).
                if (!eventUrl) {
                    try {
                        eventUrl  = await opGetCapabilities(deviceUrl, user, getPass());
                        backoffMs = 3000;
                    } catch (err) {
                        if (!active) break;
                        node.warn(`GetCapabilities failed — retry in ${backoffMs / 1000}s: ${err.message}`);
                        node.status({ fill: 'yellow', shape: 'ring', text: 'retrying…' });
                        await sleep(backoffMs);
                        backoffMs = Math.min(backoffMs * 2, 120000);
                        continue;
                    }
                }

                // Step 2: create pull-point subscription (re-created after any error).
                if (!subscriptionUrl) {
                    try {
                        subscriptionUrl = await opCreateSubscription(eventUrl, user, getPass());
                        // Renew subscription every 50 s (TTL = 60 s).
                        clearInterval(renewTimer);
                        renewTimer = setInterval(async () => {
                            if (!active || !subscriptionUrl) return;
                            try {
                                await opRenew(subscriptionUrl, user, getPass());
                            } catch (e) {
                                node.warn('Subscription renew failed — will re-subscribe: ' + e.message);
                                subscriptionUrl = null;   // next iteration re-subscribes
                            }
                        }, 50000);
                        node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                        backoffMs = 3000;
                    } catch (err) {
                        if (!active) break;
                        node.warn(`CreateSubscription failed — retry in ${backoffMs / 1000}s: ${err.message}`);
                        node.status({ fill: 'yellow', shape: 'ring', text: 'retrying…' });
                        await sleep(backoffMs);
                        backoffMs = Math.min(backoffMs * 2, 120000);
                        continue;
                    }
                }

                // Step 3: pull messages (camera holds the request ≤ pullTimeoutSec).
                let xml;
                try {
                    xml = await opPullMessages(subscriptionUrl, user, getPass(), pullTimeoutSec);
                } catch (err) {
                    if (!active) break;
                    node.warn(`PullMessages error — retry in ${backoffMs / 1000}s: ${err.message}`);
                    // Treat as subscription lost — re-subscribe on next iteration.
                    clearInterval(renewTimer);
                    renewTimer = null;
                    subscriptionUrl = null;
                    node.status({ fill: 'yellow', shape: 'ring', text: 'reconnecting…' });
                    await sleep(backoffMs);
                    backoffMs = Math.min(backoffMs * 2, 120000);
                    continue;
                }
                if (!active) break;

                // SOAP fault → subscription expired or invalid → re-subscribe.
                if (/[Ff]ault/.test(xml)) {
                    node.warn('PullMessages SOAP fault — re-subscribing');
                    clearInterval(renewTimer);
                    renewTimer = null;
                    subscriptionUrl = null;
                    node.status({ fill: 'yellow', shape: 'ring', text: 'reconnecting…' });
                    await sleep(3000);
                    continue;
                }

                backoffMs = 3000;   // reset after a successful pull

                const events = parseEvents(xml);
                for (const ev of events) {
                    if (!active) break;
                    processEvent(ev);
                }
            }

            // Loop exited — nothing running, nothing consuming camera resources.
        }

        // ── Public: start ─────────────────────────────────────────────────────
        function doStart() {
            if (active) return;
            active = true;
            pollLoop().catch(err => {
                node.error('Poll loop crashed unexpectedly: ' + err.message);
            });
        }

        // ── Public: stop ──────────────────────────────────────────────────────
        async function doStop() {
            if (!active && !subscriptionUrl) return;
            active = false;
            wakeUp();                   // abort any in-progress back-off sleep
            clearInterval(renewTimer);
            renewTimer = null;
            clearMotionState();

            const subUrl        = subscriptionUrl;
            subscriptionUrl     = null;

            // Tell the camera to tear down the pull-point immediately so it
            // frees its connection slot for the Tapo HTTPS API.
            if (subUrl) {
                try {
                    await opUnsubscribe(subUrl, user, getPass());
                } catch (e) {
                    node.warn('Unsubscribe failed (ignored): ' + e.message);
                }
            }
            node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
        }

        // ── Input handler ─────────────────────────────────────────────────────
        node.on('input', async (msg, send, done) => {
            const action = msg.action ?? config.action;
            if (action === 'start') {
                doStart();
                done();
            } else if (action === 'stop') {
                await doStop();
                done();
            } else {
                done(new Error(`Unknown action "${action}". Use "start" or "stop".`));
            }
        });

        // ── Cleanup on redeploy / shutdown ────────────────────────────────────
        node.on('close', (removed, done) => {
            if (typeof removed === 'function') { done = removed; }  // Node-RED < 0.19
            closed = true;
            doStop().finally(() => done());
        });

        node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
    }

    RED.nodes.registerType('tapo-onvif-events', TapoOnvifEventsNode);
};
