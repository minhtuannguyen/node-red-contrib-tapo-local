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

const { registerOnvifCallbacks, unregisterOnvifCallbacks, executeOnDevice } = require('../lib/tapo-client');
const { soapEnvelope, soapPost, xmlFindAll, xmlInner, xmlText, xmlAttr } = require('../lib/onvif-soap');

// ── ONVIF operations ──────────────────────────────────────────────────────────
async function opGetCapabilities(deviceUrl, user, pass, _onReq = null) {
    const xml = await soapPost(
        deviceUrl,
        soapEnvelope(
            '<tds:GetCapabilities><tds:Category>Events</tds:Category></tds:GetCapabilities>',
            user, pass,
        ),
        10000,
        _onReq,
    );
    if (/[Ff]ault/.test(xml)) throw new Error('GetCapabilities SOAP fault: ' + xml.slice(0, 400));
    // Events XAddr is inside the <Events> or <tt:Events> element.
    const eventsEl = xmlInner(xml, 'Events');
    const xaddr    = xmlText(eventsEl || xml, 'XAddr') || xmlText(xml, 'XAddr');
    if (!xaddr) throw new Error('No Events XAddr in GetCapabilities response:\n' + xml.slice(0, 400));
    return xaddr;
}

async function opCreateSubscription(eventUrl, user, pass, ttlSecs = 60, _onReq = null) {
    const xml = await soapPost(
        eventUrl,
        soapEnvelope(
            `<tev:CreatePullPointSubscription>\n  <tev:InitialTerminationTime>PT${ttlSecs}S</tev:InitialTerminationTime>\n</tev:CreatePullPointSubscription>`,
            user, pass,
        ),
        10000,
        _onReq,
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
// _onReq: optional callback receiving the raw http.ClientRequest (for aborting).
async function opPullMessages(subUrl, user, pass, pullTimeoutSec, msgLimit = 100, _onReq) {
    return soapPost(
        subUrl,
        soapEnvelope(
            `<tev:PullMessages>\n  <tev:Timeout>PT${pullTimeoutSec}S</tev:Timeout>\n  <tev:MessageLimit>${msgLimit}</tev:MessageLimit>\n</tev:PullMessages>`,
            user, pass,
        ),
        (pullTimeoutSec + 4) * 1000,
        _onReq,
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

    // ── Config node: ONVIF device ─────────────────────────────────────────────
    function TapoOnvifDeviceNode(config) {
        RED.nodes.createNode(this, config);
        this.ip       = config.ip;
        this.username = config.username;
        // password stored in credentials (encrypted by Node-RED)
    }
    RED.nodes.registerType('tapo-onvif-device', TapoOnvifDeviceNode, {
        credentials: { password: { type: 'password' } },
    });

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
        let stopping        = false;   // true while doStop() is in its async cleanup phase
        let closed          = false;   // node has been closed/removed
        let eventUrl        = null;    // discovered event service XAddr
        let subscriptionUrl = null;    // active pull-point subscription URL
        let renewTimer      = null;    // setInterval for subscription renewal
        let wakeResolve     = null;    // resolves the current sleep() early on stop
        let currentReq      = null;    // the live http.ClientRequest for any poll-loop op
                                       // (GetCapabilities, CreateSubscription, or PullMessages)
                                       // doStop() destroys it to free the camera's connection slot
        let retryMs         = 5000;    // GetCapabilities back-off: 5→10→20→40→60 s max


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
                const snap        = ev;  // ev is a fresh unique object from parseEvents — reference is safe

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
        // Runs until active === false.
        // On any ONVIF error: Unsubscribe (best effort), wait 5 s, then re-probe
        // with GetCapabilities.  Flat 5 s retry — no exponential back-off — so
        // the node recovers promptly without flooding the C225 with rapid requests.
        async function pollLoop() {
            node.status({ fill: 'blue', shape: 'dot', text: 'connecting…' });

            while (active) {

                // Step 1: GetCapabilities — cached across reconnects; also acts as
                // a liveness probe after any error (reset to null on error below).
                if (!eventUrl) {
                    try {
                        eventUrl = await opGetCapabilities(
                            deviceUrl, user, getPass(),
                            (req) => { currentReq = req; },
                        );
                        currentReq = null;
                        retryMs    = 5000;   // camera is reachable — reset back-off
                    } catch (err) {
                        currentReq = null;
                        if (!active) break;
                        const label = `${retryMs / 1000}s`;
                        node.warn(`GetCapabilities failed — retry in ${label}: ${err.message}`);
                        node.status({ fill: 'yellow', shape: 'ring', text: `offline — retry in ${label}` });
                        await sleep(retryMs);
                        retryMs = Math.min(retryMs * 2, 60000);  // cap at 60 s
                        continue;
                    }
                }

                // Step 2: create pull-point subscription.
                if (!subscriptionUrl) {
                    try {
                        subscriptionUrl = await opCreateSubscription(
                            eventUrl, user, getPass(), 120,
                            (req) => { currentReq = req; },
                        );
                        currentReq = null;
                        // Renew subscription every 90 s (TTL = 120 s).
                        clearInterval(renewTimer);
                        renewTimer = setInterval(async () => {
                            if (!active || !subscriptionUrl) return;
                            try {
                                await opRenew(subscriptionUrl, user, getPass(), 120);
                            } catch (e) {
                                node.warn('Subscription renew failed — will re-subscribe: ' + e.message);
                                subscriptionUrl = null;
                            }
                        }, 90000);
                        node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                    } catch (err) {
                        if (!active) break;
                        eventUrl = null;  // force re-probe on next iteration
                        node.warn(`CreateSubscription failed — retry in 5s: ${err.message}`);
                        node.status({ fill: 'yellow', shape: 'ring', text: 'offline — retry in 5s' });
                        await sleep(5000);
                        continue;
                    }
                }

                // Step 3: pull messages (camera holds the connection ≤ pullTimeoutSec).
                // currentReq is tracked so doStop() can TCP-RST it immediately
                // before opening the Unsubscribe connection.
                let xml;
                try {
                    xml = await opPullMessages(
                        subscriptionUrl, user, getPass(), pullTimeoutSec, 100,
                        (req) => { currentReq = req; },
                    );
                } catch (err) {
                    currentReq = null;
                    if (!active) break;   // destroyed by doStop() — exit cleanly

                    // PTZ interrupt — slot freed for PTZ command; resume immediately.
                    if (err.message === 'ptz-interrupt') continue;

                    // Camera unresponsive or subscription lost.
                    // Unsubscribe (best effort), wait 5 s, then re-probe.
                    clearInterval(renewTimer);
                    renewTimer      = null;
                    const subUrl    = subscriptionUrl;
                    subscriptionUrl = null;
                    eventUrl        = null;  // re-probe on next iteration
                    node.warn(`ONVIF error — retry in 5s: ${err.message}`);
                    node.status({ fill: 'yellow', shape: 'ring', text: 'offline — retry in 5s' });
                    if (subUrl) {
                        try { await opUnsubscribe(subUrl, user, getPass()); } catch (_) {}
                    }
                    await sleep(5000);
                    continue;
                }
                currentReq = null;
                if (!active) break;

                // SOAP fault → subscription expired or invalid → re-subscribe.
                if (/[Ff]ault/.test(xml)) {
                    node.warn('PullMessages SOAP fault — re-subscribing in 5s');
                    clearInterval(renewTimer);
                    renewTimer      = null;
                    subscriptionUrl = null;
                    node.status({ fill: 'yellow', shape: 'ring', text: 'offline — retry in 5s' });
                    await sleep(5000);
                    continue;
                }

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
            // `stopping`: doStop() is in its async cleanup phase — a new loop
            // must not start until cleanup finishes, otherwise two loops could run
            // concurrently and the old loop sees active=true and never exits.
            if (active || stopping || closed) return;
            active  = true;
            retryMs = 5000;   // always start fresh with minimum back-off
            pollLoop().catch(err => {
                node.error('Poll loop crashed unexpectedly: ' + err.message);
            });
        }

        // ── Public: stop ──────────────────────────────────────────────────────
        // skipUnsubscribe=true → used by privacy-on coordination: we just RST the
        // live request and let the subscription expire via TTL (120 s).  Sending an
        // Unsubscribe would open a new connection immediately after the RST and
        // occupy the C225's single connection slot, causing the subsequent Tapo
        // HTTPS command to time out.
        async function doStop(skipUnsubscribe = false) {
            if (!active && !subscriptionUrl) return;
            active   = false;
            stopping = true;   // block doStart() until cleanup is complete
            wakeUp();          // abort any in-progress back-off sleep
            clearInterval(renewTimer);
            renewTimer = null;

            // When stopping due to privacy-on the camera's motion sensor is
            // disabled, so emit detected:false for any topic that was active.
            if (skipUnsubscribe) {
                for (const key of Object.keys(motionActive)) {
                    if (motionActive[key]) {
                        safeSend({ topic: key, payload: {
                            detected: false,
                            time:     new Date().toISOString(),
                            property: 'privacy',
                            source:   ip,
                            data:     {},
                        }});
                    }
                }
            }
            clearMotionState();

            // ── Abort any in-flight poll-loop request NOW (TCP RST). ─────────
            // This covers GetCapabilities, CreateSubscription, and PullMessages.
            if (currentReq) {
                currentReq.destroy(new Error('stopped'));
                currentReq = null;
            }
            // Give the camera's firmware time to fully release the TCP slot
            // before the next connection (Unsubscribe or Tapo HTTPS).
            await new Promise(r => setTimeout(r, 600));

            const subUrl    = subscriptionUrl;
            subscriptionUrl = null;

            if (!skipUnsubscribe && subUrl) {
                try {
                    await opUnsubscribe(subUrl, user, getPass());
                } catch (e) {
                    node.warn('Unsubscribe failed (ignored): ' + e.message);
                }
            }
            node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
            stopping = false;  // cleanup done — doStart() may proceed
        }

        // ── Auto-coordination with tapo-local ─────────────────────────────────
        // tapo-client awaits stop() before privacy-on (so the camera has one free
        // connection slot) and calls start() after privacy-off succeeds.
        registerOnvifCallbacks(ip, {
            // skip Unsubscribe — sending it would open a connection right before
            // the Tapo HTTPS command and freeze the C225 (one-connection limit).
            stop:  () => doStop(true),
            start: () => doStart(),  // non-blocking — kicks off the poll loop
            // PTZ coordination: abort the in-flight PullMessages so the camera's
            // connection slot is free immediately for the PTZ SOAP command.
            // The poll loop detects the 'ptz-interrupt' error and restarts cleanly.
            interrupt: async () => {
                if (!active || !currentReq) return;
                currentReq.destroy(new Error('ptz-interrupt'));
                currentReq = null;
                // Brief pause — let the camera process the TCP RST before PTZ connects.
                await new Promise(r => setTimeout(r, 200));
            },
        });

        // ── Input handler ─────────────────────────────────────────────────────
        node.on('input', async (msg, send, done) => {
            const action = msg.action;
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
            unregisterOnvifCallbacks(ip);
            doStop(false).finally(() => done());  // full stop — send Unsubscribe on shutdown
        });

        // Auto-start unless explicitly disabled in config.
        // On startup we don't know whether the camera is currently in privacy mode,
        // so query the Tapo API first.  If privacy is on, stay idle — the tapo-local
        // node will call doStart() via the registry when privacy-off is sent.
        // If the query fails for any reason (wrong creds, camera offline), start
        // the poll loop anyway so the node self-heals once the camera is reachable.
        if (config.autoStart !== false) {
            node.status({ fill: 'blue', shape: 'ring', text: 'checking privacy…' });
            // Race the Tapo query against a 5 s deadline so the node starts the
            // poll loop quickly when the camera is offline (default REQUEST_TIMEOUT_MS
            // is 12 s which leaves the node stuck on "checking privacy…" too long).
            const checkDone    = executeOnDevice(ip, user, getPass(), { method: 'getLensMaskConfig' });
            const checkTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error('startup check timeout')), 5000));
            Promise.race([checkDone, checkTimeout])
                .then(r => {
                    const privacyOn = r?.lens_mask?.lens_mask_info?.enabled === 'on';
                    if (privacyOn) {
                        node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                    } else {
                        doStart();
                    }
                })
                .catch(() => {
                    // Camera offline or slow — start the poll loop and let exponential
                    // back-off handle recovery (5 → 10 → 20 → 40 → 60 s cap).
                    doStart();
                });
        } else {
            node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
        }
    }

    RED.nodes.registerType('tapo-onvif-events', TapoOnvifEventsNode);
};
