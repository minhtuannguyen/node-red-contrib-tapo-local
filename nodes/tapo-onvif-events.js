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

const { registerOnvifCallbacks, unregisterOnvifCallbacks, executeOnDevice, releaseSession } = require('../lib/tapo-client');
const { soapEnvelope, soapPost, dropRoute, xmlFindAll, xmlInner, xmlText, xmlAttr } = require('../lib/onvif-soap');

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

async function opRenew(subUrl, user, pass, ttlSecs = 60, _onReq = null) {
    return soapPost(
        subUrl,
        soapEnvelope(
            `<wsnt:Renew>\n  <wsnt:TerminationTime>PT${ttlSecs}S</wsnt:TerminationTime>\n</wsnt:Renew>`,
            user, pass,
        ),
        10000,
        _onReq,
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
        // Default 25 s matches the HTML default in tapo-onvif-events.html.  This
        // controls ONVIF PullMessages long-poll duration.  Higher = fewer requests
        // per minute (25 s ≈ 2–3 req/min; 5 s ≈ 12 req/min).  Event delivery
        // latency is unaffected — the camera flushes the response as soon as
        // events arrive, regardless of the timeout ceiling.
        const pullTimeoutSec  = parseInt(config.pullTimeout,  10) || 25;
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
        // Nulls wakeResolve on natural completion so the closure (holding the
        // fired timer + settled resolve) can be GC'd promptly instead of hanging
        // around until the next sleep() overwrites it.
        function sleep(ms) {
            return new Promise(resolve => {
                const t = setTimeout(() => { wakeResolve = null; resolve(); }, ms);
                wakeResolve = () => { clearTimeout(t); wakeResolve = null; resolve(); };
            });
        }
        function wakeUp() {
            if (wakeResolve) wakeResolve();  // wakeResolve nulls itself
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

            // Tracks whether we have already done the privacy-guard check for the
            // current reconnect cycle.  Reset to false after a successful
            // GetCapabilities so we re-check on the next disconnect/reconnect.
            // Kept true during exponential back-off retries (camera still offline)
            // to avoid adding a full 12 s REQUEST_TIMEOUT_MS per retry attempt.
            let privacyGuardDone = false;

            while (active) {

                // Step 1: GetCapabilities — cached across reconnects; also acts as
                // a liveness probe after any error (reset to null on error below).
                if (!eventUrl) {

                    // ── Privacy guard before each ONVIF reconnect ────────────────
                    // Before opening an ONVIF subscription, verify the camera is not
                    // in privacy mode.  Running a PullMessages long-poll against a
                    // C225 in privacy mode causes gradual firmware resource exhaustion
                    // and an eventual crash — observed reproducibly after hours of
                    // sustained ONVIF subscriptions with no motion events.
                    //
                    // This catches two scenarios the startup check cannot cover:
                    //   A. Camera reboots slowly (>12 s to start HTTPS service) →
                    //      startup check times out → doStart() fires → camera comes
                    //      up in privacy mode → ONVIF loop reconnects → crash.
                    //   B. Camera loses power while ONVIF is running → comes back in
                    //      privacy mode → backoff loop reconnects without a privacy
                    //      check → ONVIF subscription created → crash.
                    //
                    // Runs only ONCE per reconnect cycle (not on every retry while
                    // the camera is still offline) to avoid a 12 s overhead per retry.
                    if (!privacyGuardDone) {
                        privacyGuardDone = true;
                        let privacyOn = false;
                        try {
                            const lm = await executeOnDevice(ip, user, getPass(),
                                { method: 'getLensMaskConfig' });
                            privacyOn = lm?.lens_mask?.lens_mask_info?.enabled === 'on';
                        } catch (_) {
                            // Camera unreachable — privacy state unknown.  Proceed to
                            // GetCapabilities which handles offline retry with
                            // exponential back-off.
                        } finally {
                            // Always release the HTTPS session so the camera's single
                            // TCP slot is free for the upcoming ONVIF SOAP calls.
                            // The Tapo HTTPS agent holds an idle keep-alive socket
                            // that would otherwise block the ONVIF connection attempt.
                            releaseSession(ip, user);
                        }
                        if (!active) break;

                        if (privacyOn) {
                            // Camera is in privacy mode — stay idle.
                            // The tapo-local privacy-off command will call doStart()
                            // via the registry when privacy is disabled.
                            node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                            active = false;
                            break;
                        }

                        // Brief pause for the camera's TCP stack to fully release
                        // the HTTPS slot after agent.destroy() (the RST may leave
                        // the slot in a transient FIN_WAIT state for a short time).
                        await new Promise(r => setTimeout(r, 300));
                        if (!active) break;
                    }

                    try {
                        eventUrl = await opGetCapabilities(
                            deviceUrl, user, getPass(),
                            (req) => { currentReq = req; },
                        );
                        currentReq = null;
                        retryMs    = 5000;   // camera is reachable — reset back-off
                        privacyGuardDone = false;  // reconnected — re-arm guard for next disconnect
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
                                // Store the renewal request in currentReq so doStop() can
                                // abort it immediately via TCP RST.  Without this, doStop()
                                // would declare "slot free" after only 600 ms while an
                                // opRenew() with a 10 s timeout is still in flight — causing
                                // the subsequent privacy-on HTTPS command to collide on the
                                // camera's single TCP connection slot.
                                await opRenew(subscriptionUrl, user, getPass(), 120,
                                    req => { currentReq = req; });
                                currentReq = null;
                            } catch (e) {
                                currentReq = null;
                                if (!active) return;  // doStop() aborted the request — expected
                                node.warn('Subscription renew failed — will re-subscribe: ' + e.message);
                                if (subscriptionUrl) dropRoute(subscriptionUrl);  // release cached route
                                subscriptionUrl = null;
                                // Stop the interval NOW — otherwise it keeps firing every 90 s
                                // as no-ops until the concurrent PullMessages finally errors out
                                // and clears it.  On a broken camera those idle wake-ups pile up.
                                clearInterval(renewTimer);
                                renewTimer = null;
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
                    // Skip Unsubscribe here on purpose:
                    //   • If the camera is offline, opUnsubscribe would just burn
                    //     its own 5 s timeout and add another wasted request to
                    //     an already-struggling device.
                    //   • If only the subscription died, the pull-point still
                    //     expires naturally via its 120 s TTL — no cleanup needed.
                    // doStop() (intentional shutdown) still sends Unsubscribe.
                    clearInterval(renewTimer);
                    renewTimer      = null;
                    const subUrl    = subscriptionUrl;
                    subscriptionUrl = null;
                    eventUrl        = null;  // re-probe on next iteration
                    node.warn(`ONVIF error — retry in 5s: ${err.message}`);
                    node.status({ fill: 'yellow', shape: 'ring', text: 'offline — retry in 5s' });
                    if (subUrl) dropRoute(subUrl);  // release cached route — URL is unique per subscription
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
                    if (subscriptionUrl) dropRoute(subscriptionUrl);  // release cached route
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
            // Release the cached SOAP route for this subscription URL.  Each
            // CreatePullPointSubscription mints a new URL, so without this the
            // route cache would grow by one entry every stop/start (privacy
            // toggle, camera reboot, PullMessages error, node-red restart …).
            if (subUrl) dropRoute(subUrl);
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
            doStop(false).finally(() => {
                // Drop the stable per-camera routes from the shared route cache.
                // ROUTE_CACHE_MAX already caps growth defensively, but on a redeploy
                // the new instance will re-populate the cache anyway — so freeing the
                // old entries costs nothing and keeps the cache clean.
                dropRoute(deviceUrl);
                if (eventUrl) dropRoute(eventUrl);
                done();
            });
        });

        // Auto-start unless explicitly disabled in config.
        // On startup we don't know whether the camera is currently in privacy mode,
        // so query the Tapo API first.  If privacy is on, stay idle — the tapo-local
        // node will call doStart() via the registry when privacy-off is sent.
        // If the query fails for any reason (wrong creds, camera offline), start
        // the poll loop anyway so the node self-heals once the camera is reachable.
        if (config.autoStart !== false) {
            node.status({ fill: 'blue', shape: 'ring', text: 'checking privacy…' });
            // Race the Tapo query against a 15 s deadline.  15 s > REQUEST_TIMEOUT_MS
            // (12 s) so the executeOnDevice timeout always fires first on an offline
            // camera — the artificial timeout is a safety net only.  This prevents the
            // previous 5 s race from firing prematurely when the camera is slow to
            // respond (e.g. still booting after a power-cycle while in privacy mode),
            // which would cause doStart() to launch the ONVIF poll loop incorrectly and
            // hammer the camera before it has fully initialised.
            const checkDone    = executeOnDevice(ip, user, getPass(), { method: 'getLensMaskConfig' });
            let startupTimer   = null;
            const checkTimeout = new Promise((_, rej) => {
                startupTimer = setTimeout(() => rej(new Error('startup check timeout')), 15000);
            });
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
                    // Camera offline (12 s REQUEST_TIMEOUT_MS elapsed) — start the poll
                    // loop and let exponential back-off handle recovery (5 → 60 s cap).
                    doStart();
                })
                .finally(() => {
                    // Clear the losing arm of the race so its setTimeout does not stay
                    // armed for the full 15 s after checkDone already resolved.
                    if (startupTimer) clearTimeout(startupTimer);
                    // Attach no-op catches to BOTH arms.  Whichever one lost the race
                    // is still pending (or already rejected) and would otherwise emit
                    // an "unhandledRejection" on Node when it eventually settles:
                    //   - checkTimeout won → checkDone still in flight against a slow
                    //     camera; will reject 12+ s later with no listener.
                    //   - checkDone won   → checkTimeout still armed; will reject at 15 s.
                    checkDone.catch(() => {});
                    checkTimeout.catch(() => {});
                });
        } else {
            node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
        }
    }

    RED.nodes.registerType('tapo-onvif-events', TapoOnvifEventsNode);
};
