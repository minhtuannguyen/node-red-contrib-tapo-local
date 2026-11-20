'use strict';

/**
 * tapo-onvif-events — ONVIF WS-PullPoint event node for Tapo C225.
 *
 * Implements ONVIF event subscription directly via raw HTTP SOAP — no `onvif`
 * npm library.  Full control means:
 *
 *  • Zero HTTP requests sent to the camera while stopped.
 *  • Proper ONVIF Unsubscribe sent on stop (camera frees the pull-point).
 *  • Exponential back-off on every failure path (5 s → 10 s → … → 60 s max).
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
 *   4. Renew inline between pulls → keep subscription alive (TTL ≥ 120 s)
 *   5. Unsubscribe on stop      → camera cleans up immediately
 */

const { registerOnvifCallbacks, unregisterOnvifCallbacks, executeOnDevice, acquireLease, noteDeviceReachable, COMMANDS } = require('../lib/tapo-client');
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
        const pullTimeoutSec  = Math.min(Math.max(parseInt(config.pullTimeout, 10) || 25, 5), 120);
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
        // Each running poll loop owns a context object.  doStop() marks it
        // stopped, so a loop still awaiting a slow request can never resume
        // after a quick stop→start (which previously left two loops running).
        //   ctx = { stopped, req, isPull, interrupted, subUrl, wake }
        let loop            = null;    // context of the current poll loop (null = idle)
        let stopping        = null;    // Promise while doStop() cleanup runs
        let intent          = 0;       // bumped on every start/stop request; orders deferred starts
        let closed          = false;   // node has been closed/removed
        let eventUrl        = null;    // discovered event service XAddr (stable per camera)
        let ptzHolds        = 0;       // >0 while a PTZ command needs the connection slot
        let ptzWaiters      = [];      // loops paused until PTZ releases the slot

        const SUB_TTL_SECS         = Math.max(120, (pullTimeoutSec + 10) * 3);
        // Renew inline between pulls; leaves room for one full pull + a PTZ pause inside the TTL.
        const RENEW_EVERY_MS       = Math.max(20, SUB_TTL_SECS - pullTimeoutSec - 45) * 1000;
        const PULL_MIN_INTERVAL_MS = 1000;   // never spin if the camera answers PullMessages instantly
        const PTZ_GRACE_MS         = 3000;   // keep the slot free briefly: a Stop usually follows a move
        const PTZ_HOLD_MAX_MS      = 30000;  // safety: never pause polling forever
        const HANDOFF_MS           = 1500;   // HTTPS commands wait this long while ONVIF connects

        // Close idle HTTPS sockets and keep HTTPS commands queued briefly, so the next ONVIF
        // request does not compete with an HTTPS login.
        async function handoff() {
            const lease = await acquireLease(ip, { dropSessions: true });
            if (!lease) { node.warn('HTTPS queue busy — ONVIF continuing without hand-off'); return; }
            setTimeout(lease.release, HANDOFF_MS);
        }

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

        const delay = ms => new Promise(r => setTimeout(r, ms));

        // Interruptible sleep — doStop() calls ctx.wake() to resolve it immediately.
        function sleep(ctx, ms) {
            return new Promise(resolve => {
                const t = setTimeout(done, ms);
                function done() { clearTimeout(t); if (ctx.wake === done) ctx.wake = null; resolve(); }
                ctx.wake = done;
            });
        }
        function waitForPtz(ctx) {
            return new Promise(resolve => {
                function done() { if (ctx.wake === done) ctx.wake = null; resolve(); }
                ctx.wake = done;
                ptzWaiters.push(done);
            });
        }
        function flushPtzWaiters() {
            const w = ptzWaiters;
            ptzWaiters = [];
            w.forEach(f => f());
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
        // Runs until ctx.stopped.  Every failure path (GetCapabilities, subscribe,
        // renew, pull, SOAP fault) shares ONE exponential back-off (5 s → 60 s),
        // reset only after a successful PullMessages.  Previously a camera that
        // accepted subscriptions but failed pulls was hit every 5 s with an HTTPS
        // login + GetCapabilities + a NEW pull-point (old ones never released),
        // which exhausts the C225's subscription table and crashes it.
        async function pollLoop(ctx, privacyKnownOff) {
            const alive = () => !ctx.stopped && !closed;
            const track = req => { ctx.req = req; };
            let failures         = 0;
            let needPrivacyCheck = !privacyKnownOff;
            let renewAt          = 0;

            async function failAndWait(what, err, lostCamera) {
                failures++;
                if (ctx.subUrl) dropRoute(ctx.subUrl);
                ctx.subUrl = null;
                if (lostCamera) { eventUrl = null; needPrivacyCheck = true; }
                const ms    = Math.min(5000 * 2 ** Math.min(failures - 1, 4), 60000);
                const label = `${ms / 1000}s`;
                node.warn(`${what} failed — retry in ${label}: ${err.message}`);
                node.status({ fill: 'yellow', shape: 'ring', text: `offline — retry in ${label}` });
                await sleep(ctx, ms);
            }

            node.status({ fill: 'blue', shape: 'dot', text: 'connecting…' });

            while (alive()) {
                // A PTZ command owns the connection slot — wait until it is done.
                if (ptzHolds > 0) { await waitForPtz(ctx); continue; }

                // Step 1: GetCapabilities — cached across reconnects; also acts as
                // a liveness probe after a connection loss (reset to null there).
                if (!eventUrl) {
                    try {
                        eventUrl = await opGetCapabilities(deviceUrl, user, getPass(), track);
                    } catch (err) {
                        ctx.req = null;
                        if (!alive()) break;
                        await failAndWait('GetCapabilities', err, true);
                        continue;
                    }
                    ctx.req = null;
                    if (!alive()) break;
                    noteDeviceReachable(ip);
                }

                // Step 2: privacy guard — once per (re)connect, only after the camera
                // has proven reachable (so the check isn't wasted on an offline camera
                // and a camera that comes back in privacy mode is always caught).
                // A PullMessages long-poll against a C225 in privacy mode causes
                // gradual firmware resource exhaustion and an eventual crash.
                if (needPrivacyCheck) {
                    needPrivacyCheck = false;
                    let privacyOn = false;
                    try {
                        const lm  = await executeOnDevice(ip, user, getPass(), COMMANDS['get-lens-mask']);
                        privacyOn = lm?.lens_mask?.lens_mask_info?.enabled === 'on';
                    } catch (_) {
                        // HTTPS API unavailable — privacy state unknown, proceed.
                    }
                    // Free the HTTPS keep-alive socket before the ONVIF calls.
                    await handoff();
                    if (!alive()) break;
                    if (privacyOn) {
                        // Stay idle; privacy-off via tapo-local restarts us through the registry.
                        node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                        ctx.stopped = true;
                        if (loop === ctx) loop = null;
                        break;
                    }
                    await sleep(ctx, 300);  // let the camera release the HTTPS slot
                    continue;
                }

                // Step 3: create the pull-point subscription, or renew it inline.
                // Renewing between pulls (not from a timer) guarantees we never hold
                // two connections to the camera at once.
                if (!ctx.subUrl) {
                    try {
                        ctx.subUrl = await opCreateSubscription(eventUrl, user, getPass(), SUB_TTL_SECS, track);
                    } catch (err) {
                        ctx.req = null;
                        if (!alive()) break;
                        await failAndWait('CreateSubscription', err, !/fault/i.test(err.message));
                        continue;
                    }
                    ctx.req = null;
                    renewAt = Date.now() + RENEW_EVERY_MS;
                    if (!alive()) break;
                    node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                } else if (Date.now() >= renewAt) {
                    try {
                        const xml = await opRenew(ctx.subUrl, user, getPass(), SUB_TTL_SECS, track);
                        if (/[Ff]ault/.test(xml)) throw new Error('Renew SOAP fault: ' + xml.slice(0, 300));
                    } catch (err) {
                        ctx.req = null;
                        if (!alive()) break;
                        await failAndWait('Renew', err, !/fault/i.test(err.message));
                        continue;
                    }
                    ctx.req = null;
                    renewAt = Date.now() + RENEW_EVERY_MS;
                    if (!alive()) break;
                }

                // Step 4: pull messages (camera holds the connection ≤ pullTimeoutSec).
                // ctx.req is tracked so doStop()/PTZ can TCP-RST it immediately.
                if (ptzHolds > 0) continue;  // PTZ arrived during subscribe/renew — yield first
                const pullStart = Date.now();
                let xml;
                ctx.isPull      = true;
                ctx.interrupted = false;
                try {
                    xml = await opPullMessages(ctx.subUrl, user, getPass(), pullTimeoutSec, 100, track);
                } catch (err) {
                    if (!alive()) break;
                    // PTZ interrupt — slot handed to PTZ; the loop pauses at the top.
                    if (ctx.interrupted) continue;
                    // Skip Unsubscribe: the camera is likely unreachable, and the
                    // pull-point expires via its TTL anyway.
                    await failAndWait('PullMessages', err, true);
                    continue;
                } finally {
                    ctx.isPull = false;
                    ctx.req    = null;
                }
                if (!alive()) break;

                // SOAP fault → subscription expired or invalid → re-subscribe (with back-off).
                if (/[Ff]ault/.test(xml)) {
                    await failAndWait('PullMessages', new Error('SOAP fault: ' + xml.slice(0, 200)), false);
                    continue;
                }
                if (failures > 0) node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                failures = 0;

                const events = parseEvents(xml);
                for (const ev of events) {
                    if (!alive()) break;
                    processEvent(ev);
                }

                const elapsed = Date.now() - pullStart;
                if (elapsed < PULL_MIN_INTERVAL_MS && alive()) await sleep(ctx, PULL_MIN_INTERVAL_MS - elapsed);
            }

            // Loop exited — nothing running, nothing consuming camera resources.
        }

        // ── Public: start ─────────────────────────────────────────────────────
        // privacyKnownOff=true skips the privacy guard (caller just confirmed it).
        function doStart(privacyKnownOff = false) {
            const myIntent = ++intent;
            if (closed || loop) return;
            // Cleanup still running — start afterwards unless a newer stop/start superseded us.
            if (stopping) {
                stopping.then(() => { if (intent === myIntent) doStart(privacyKnownOff); });
                return;
            }
            const ctx = { stopped: false, req: null, isPull: false, interrupted: false, subUrl: null, wake: null };
            loop = ctx;
            pollLoop(ctx, privacyKnownOff)
                .catch(err => node.error('Poll loop crashed unexpectedly: ' + err.message))
                .finally(() => { if (loop === ctx) loop = null; });
        }

        // ── Public: stop ──────────────────────────────────────────────────────
        // skipUnsubscribe=true → used by privacy-on coordination: we just RST the
        // live request and let the subscription expire via TTL (120 s).  Sending an
        // Unsubscribe would open a new connection immediately after the RST and
        // occupy the C225's single connection slot, causing the subsequent Tapo
        // HTTPS command to time out.
        // Resolves true if a running loop was stopped.
        async function doStop(skipUnsubscribe = false) {
            intent++;
            const ctx = loop;
            if (!ctx) { if (stopping) await stopping; return false; }
            ctx.stopped = true;
            loop        = null;
            stopping    = stopCleanup(ctx, skipUnsubscribe);
            try { await stopping; } finally { stopping = null; }
            return true;
        }

        async function stopCleanup(ctx, skipUnsubscribe) {
            if (ctx.wake) ctx.wake();  // abort any back-off sleep / PTZ wait

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
            // This covers GetCapabilities, CreateSubscription, Renew and PullMessages.
            if (ctx.req) {
                ctx.req.destroy(new Error('stopped'));
                ctx.req = null;
            }
            // Give the camera's firmware time to fully release the TCP slot
            // before the next connection (Unsubscribe or Tapo HTTPS).
            await delay(600);

            const subUrl = ctx.subUrl;
            ctx.subUrl   = null;

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
            if (!closed) node.status({ fill: 'grey', shape: 'ring', text: 'stopped' });
        }

        // ── Auto-coordination with tapo-local / tapo-ptz ────────────────────────
        // tapo-client awaits stop() before privacy-on (so the camera has one free
        // connection slot) and calls start(true) after privacy-off succeeds.
        const callbacks = {
            // skip Unsubscribe — sending it would open a connection right before
            // the Tapo HTTPS command and freeze the C225 (one-connection limit).
            stop:  () => doStop(true),
            start: (privacyKnownOff) => doStart(!!privacyKnownOff),
            // PTZ coordination: pause the poll loop and abort an in-flight
            // PullMessages so the connection slot is free for the PTZ command.
            // Returns release(); polling resumes PTZ_GRACE_MS after the last release.
            interrupt: async () => {
                ptzHolds++;
                let released = false;
                const safety = setTimeout(() => release(), PTZ_HOLD_MAX_MS);
                function release() {
                    if (released) return;
                    released = true;
                    clearTimeout(safety);
                    setTimeout(() => { if (--ptzHolds === 0) flushPtzWaiters(); }, PTZ_GRACE_MS);
                }
                const ctx = loop;
                if (ctx && ctx.isPull && ctx.req) {
                    ctx.interrupted = true;
                    ctx.req.destroy(new Error('ptz-interrupt'));
                    ctx.req = null;
                    // Brief pause — let the camera process the TCP RST before PTZ connects.
                    await delay(200);
                }
                return release;
            },
        };
        registerOnvifCallbacks(ip, callbacks);

        // ── Input handler ─────────────────────────────────────────────────────
        node.on('input', async (msg, send, done) => {
            const action = msg.action;
            if (action === 'start') {
                doStart(false);
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
            unregisterOnvifCallbacks(ip, callbacks);
            flushPtzWaiters();
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
            const startupIntent = intent;
            node.status({ fill: 'blue', shape: 'ring', text: 'checking privacy…' });
            // Race the Tapo query against a 15 s deadline.  15 s > REQUEST_TIMEOUT_MS
            // (12 s) so the executeOnDevice timeout always fires first on an offline
            // camera — the artificial timeout is a safety net only.  This prevents the
            // previous 5 s race from firing prematurely when the camera is slow to
            // respond (e.g. still booting after a power-cycle while in privacy mode),
            // which would cause doStart() to launch the ONVIF poll loop incorrectly and
            // hammer the camera before it has fully initialised.
            const checkDone    = executeOnDevice(ip, user, getPass(), COMMANDS['get-lens-mask']);
            let startupTimer   = null;
            const checkTimeout = new Promise((_, rej) => {
                startupTimer = setTimeout(() => rej(new Error('startup check timeout')), 15000);
            });
            Promise.race([checkDone, checkTimeout])
                .then(async r => {
                    // Free the HTTPS keep-alive socket before ONVIF opens its connection.
                    await handoff();
                    if (closed || intent !== startupIntent) return;  // user/registry already decided
                    const privacyOn = r?.lens_mask?.lens_mask_info?.enabled === 'on';
                    if (privacyOn) {
                        node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                    } else {
                        doStart(true);
                    }
                })
                .catch(async () => {
                    await handoff();
                    if (closed || intent !== startupIntent) return;
                    // Privacy state unknown — the poll loop re-checks it once the
                    // camera answers ONVIF, with exponential back-off (5 → 60 s cap).
                    doStart(false);
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
