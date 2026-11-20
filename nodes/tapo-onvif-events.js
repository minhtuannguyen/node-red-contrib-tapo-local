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
const { performance } = require('perf_hooks');

// Relative timing must survive wall-clock adjustments; event timestamps keep using Date.
const monotonicNow = () => performance.now();

// Lifetime granted by the camera, as a duration so clock offsets don't matter; capped at what we asked for.
function terminationTtlMs(xml, requestedSecs) {
    const granted = Date.parse(xmlText(xml, 'TerminationTime')) - Date.parse(xmlText(xml, 'CurrentTime'));
    return (granted > 0 ? Math.min(granted / 1000, requestedSecs) : requestedSecs) * 1000;
}

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
    return { addr, ttlMs: terminationTtlMs(xml, ttlSecs) };
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

async function opUnsubscribe(subUrl, user, pass, _onReq = null) {
    const xml = await soapPost(
        subUrl,
        soapEnvelope('<wsnt:Unsubscribe/>', user, pass),
        5000,
        _onReq,
    );
    if (/[Ff]ault/.test(xml) || !xmlFindAll(xml, 'UnsubscribeResponse').length) {
        throw new Error('Unsubscribe not confirmed: ' + xml.slice(0, 400));
    }
    return xml;
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
        //   ctx = { stopped, req, interrupted, handoffLease, wake }
        let loop            = null;    // context of the current poll loop (null = idle)
        let stopping        = null;    // Promise while doStop() cleanup runs
        let cleanupCtx      = null;    // context whose stop cleanup (Unsubscribe) is running
        let intent          = 0;       // bumped on every start/stop request; orders deferred starts
        let closed          = false;   // node has been closed/removed
        let eventUrl        = null;    // discovered event service XAddr (stable per camera)
        let sub             = null;    // { url, expiresAt } the one live pull-point this node may own; reused across loops
        let uncertainSubUntil = 0;
        let ptzHolds        = 0;       // >0 while a PTZ command needs the connection slot
        let ptzWaiters      = [];      // loops paused until PTZ releases the slot

        const SUB_TTL_SECS         = Math.max(120, (pullTimeoutSec + 10) * 3);
        // Renew inline between pulls; leaves room for one full pull + a PTZ pause inside the TTL.
        const RENEW_EVERY_MS       = Math.max(20, SUB_TTL_SECS - pullTimeoutSec - 45) * 1000;
        const PULL_MIN_INTERVAL_MS = 1000;   // never spin if the camera answers PullMessages instantly
        const PTZ_GRACE_MS         = 3000;   // keep the slot free briefly: a Stop usually follows a move
        const PTZ_HOLD_MAX_MS      = 30000;  // safety: never pause polling forever
        const HANDOFF_MAX_MS       = 5000;   // HTTPS commands wait at most this long for ONVIF to connect
        const PRIVACY_RECHECK_MS   = 5 * 60 * 1000;  // privacy can change outside this plugin

        const ctxAlive = c => !c.stopped && !closed;
        const subExpired = () => !!sub && monotonicNow() >= sub.expiresAt;
        function dropSub() { if (sub) dropRoute(sub.url); sub = null; }

        function releaseHandoff(ctx) {
            const lease = ctx.handoffLease;
            ctx.handoffLease = null;
            if (lease) lease.release();
        }

        // Close idle HTTPS sockets and keep HTTPS commands queued until the next ONVIF request connects.
        // 'ready' = lease held by ctx; 'busy' = HTTPS queue unavailable; 'cancelled' = no longer wanted.
        async function handoff(ctx) {
            const wanted = () => ctxAlive(ctx) && ptzHolds === 0;
            const lease = await acquireLease(ip, { dropSessions: true, holdMs: HANDOFF_MAX_MS, stillWanted: wanted });
            if (!lease) return wanted() ? 'busy' : 'cancelled';
            if (!wanted()) { lease.release(); return 'cancelled'; }
            releaseHandoff(ctx);
            ctx.handoffLease = lease;
            return 'ready';
        }

        function releaseOnConnect(ctx, req) {
            const lease = ctx.handoffLease;
            if (!lease) return;
            ctx.handoffLease = null;
            let offExpiry = null, socket = null, connectEvent = null, released = false;
            const release = () => {
                if (released) return;
                released = true;
                if (offExpiry) offExpiry();
                if (socket && connectEvent) socket.removeListener(connectEvent, release);
                lease.release();
            };
            req.once('close', release);
            req.once('error', () => { if (!lease.signal.aborted) release(); });
            offExpiry = lease.signal.on(reason => req.destroy(reason));
            req.once('socket', connectedSocket => {
                if (req.destroyed || lease.signal.aborted) return;
                socket = connectedSocket;
                connectEvent = socket.encrypted ? 'secureConnect' : 'connect';
                if (socket.connecting || (socket.encrypted && !req.reusedSocket)) socket.once(connectEvent, release);
                else release();
            });
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
        // Runs until ctx.stopped.  Every failure path shares ONE exponential back-off
        // (5 s → 60 s), reset only after a successful PullMessages.  A live subscription
        // survives transient failures and is renewed instead of replaced, so the camera's
        // pull-point table is not refilled.
        async function queryPrivacy() {
            try {
                const lm = await executeOnDevice(ip, user, getPass(), COMMANDS['get-lens-mask']);
                const v  = lm?.lens_mask?.lens_mask_info?.enabled;
                if (v === 'on' || v === 'off') return { state: v };
                return { state: 'unknown', err: new Error('unexpected lens-mask reply') };
            } catch (err) {
                return { state: 'unknown', err };
            }
        }

        async function pollLoop(ctx, privacyKnownOff) {
            const alive = () => ctxAlive(ctx);
            const track = req => { ctx.req = req; releaseOnConnect(ctx, req); };
            let failures         = 0;
            let needPrivacyCheck = !privacyKnownOff;
            let privacyCheckedAt = monotonicNow();
            let needHandoff      = true;   // an HTTPS socket may have opened since the last ONVIF connection
            let settle           = false;  // pause briefly after the HTTPS sockets were closed
            let renewAt          = 0;

            const renewDelayMs = ttlMs => Math.min(RENEW_EVERY_MS, Math.max(5000, ttlMs - (pullTimeoutSec + 45) * 1000));

            async function backoff(what, err, label = 'offline') {
                failures++;
                const ms = Math.min(5000 * 2 ** Math.min(failures - 1, 4), 60000);
                node.warn(`${what} failed — retry in ${ms / 1000}s: ${err.message}`);
                node.status({ fill: 'yellow', shape: 'ring', text: `${label} — retry in ${ms / 1000}s` });
                await sleep(ctx, ms);
            }

            // subInvalid: the camera said the subscription is gone; otherwise it is kept for reuse until it expires.
            async function failAndWait(what, err, lostCamera, subInvalid = false) {
                if (subInvalid || subExpired()) dropSub();
                else renewAt = 0;
                if (lostCamera) { eventUrl = null; needPrivacyCheck = true; }
                needHandoff = true;
                await backoff(what, err);
            }

            // True when an ONVIF connection may open now; event traffic is never sent without coordination.
            async function coordinated() {
                if (needHandoff) {
                    const h = await handoff(ctx);
                    if (h === 'busy') { await backoff('Hand-off', new Error('HTTPS queue busy'), 'waiting'); return false; }
                    if (h !== 'ready') return false;
                    needHandoff = false;
                    if (settle) { settle = false; await sleep(ctx, 300); }
                }
                if (!alive() || ptzHolds > 0) { releaseHandoff(ctx); needHandoff = true; return false; }
                return true;
            }

            // The hold check and request creation are synchronous, so a PTZ pause cannot slip in between.
            async function call(op) {
                if (!alive() || ptzHolds > 0) { releaseHandoff(ctx); needHandoff = true; return { paused: true }; }
                ctx.interrupted = false;
                try { return { value: await op() }; }
                catch (err) { return { err, paused: ctx.interrupted }; }
                finally { ctx.req = null; }
            }

            node.status({ fill: 'blue', shape: 'dot', text: 'connecting…' });

            while (alive()) {
                // A PTZ command owns the connection slot — wait until it is done.
                if (ptzHolds > 0) { await waitForPtz(ctx); continue; }
                const uncertainWait = uncertainSubUntil - monotonicNow();
                if (!sub && uncertainWait > 0) {
                    node.status({ fill: 'yellow', shape: 'ring', text: 'waiting for uncertain subscription expiry' });
                    await sleep(ctx, uncertainWait);
                    continue;
                }

                // Step 1: GetCapabilities — cached across reconnects; also acts as
                // a liveness probe after a connection loss (reset to null there).
                if (!eventUrl) {
                    if (!(await coordinated())) continue;
                    const r = await call(() => opGetCapabilities(deviceUrl, user, getPass(), track));
                    if (!alive()) break;
                    if (r.paused) continue;
                    if (r.err) { await failAndWait('GetCapabilities', r.err, true); continue; }
                    eventUrl = r.value;
                    noteDeviceReachable(ip);
                }

                // Step 2: privacy guard — after every (re)connect and periodically, once the camera
                // has answered ONVIF.  Unknown is not "off": a PullMessages long-poll against a C225
                // in privacy mode causes firmware resource exhaustion and an eventual crash.
                if (needPrivacyCheck || monotonicNow() - privacyCheckedAt >= PRIVACY_RECHECK_MS) {
                    const { state, err } = await queryPrivacy();
                    if (!alive()) break;
                    needHandoff = true;
                    settle      = true;
                    if (state === 'on') {
                        // Stay idle; privacy-off via tapo-local restarts us through the registry.
                        await doStop(true);
                        if (!closed) node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                        break;
                    }
                    if (state === 'off') {
                        needPrivacyCheck = false;
                        privacyCheckedAt = monotonicNow();
                    } else {
                        needPrivacyCheck = true;
                        await backoff('Privacy check', err, 'privacy unknown');
                        continue;
                    }
                }

                // Step 3: create the pull-point subscription, or renew it inline.
                // Renewing between pulls (not from a timer) guarantees we never hold
                // two connections to the camera at once.
                if (subExpired()) dropSub();
                if (ptzHolds > 0) continue;
                if (!(await coordinated())) continue;

                if (!sub) {
                    let attempted = false;
                    const r = await call(() => {
                        attempted = true;
                        return opCreateSubscription(eventUrl, user, getPass(), SUB_TTL_SECS, track);
                    });
                    if (r.value) {
                        uncertainSubUntil = 0;
                        sub     = { url: r.value.addr, expiresAt: monotonicNow() + r.value.ttlMs };
                        renewAt = monotonicNow() + renewDelayMs(r.value.ttlMs);
                    } else if (attempted) {
                        uncertainSubUntil = monotonicNow() + SUB_TTL_SECS * 1000;
                    }
                    if (!alive()) break;
                    if (r.paused) continue;
                    if (r.err) { await failAndWait('CreateSubscription', r.err, !/fault/i.test(r.err.message)); continue; }
                    node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                } else if (monotonicNow() >= renewAt) {
                    const cur = sub;
                    const r   = await call(() => opRenew(cur.url, user, getPass(), SUB_TTL_SECS, track));
                    let err   = r.err;
                    let fault = false;
                    if (!err && !r.paused) {
                        if (/[Ff]ault/.test(r.value)) {
                            err   = new Error('Renew SOAP fault: ' + r.value.slice(0, 300));
                            fault = true;
                        } else {
                            const ttlMs = terminationTtlMs(r.value, SUB_TTL_SECS);
                            cur.expiresAt = monotonicNow() + ttlMs;
                            renewAt       = monotonicNow() + renewDelayMs(ttlMs);
                        }
                    }
                    if (!alive()) break;
                    if (r.paused) continue;
                    if (err) { await failAndWait('Renew', err, !/fault/i.test(err.message), fault); continue; }
                }

                // Step 4: pull messages (camera holds the connection ≤ pullTimeoutSec).
                // ctx.req is tracked so doStop()/PTZ can TCP-RST it immediately.
                if (!sub) continue;
                const cur       = sub;
                const pullStart = monotonicNow();
                const r = await call(() => opPullMessages(cur.url, user, getPass(), pullTimeoutSec, 100, track));
                if (!alive()) break;
                // PTZ interrupt — slot handed to PTZ; the loop pauses at the top.
                if (r.paused) continue;
                // A transport failure keeps the subscription: it may be fine and only expires via its TTL.
                if (r.err) { await failAndWait('PullMessages', r.err, true); continue; }

                // SOAP fault → subscription expired or invalid → re-subscribe (with back-off).
                if (/[Ff]ault/.test(r.value)) {
                    await failAndWait('PullMessages', new Error('SOAP fault: ' + r.value.slice(0, 200)), false, true);
                    continue;
                }
                if (failures > 0) node.status({ fill: 'green', shape: 'dot', text: 'listening' });
                failures = 0;

                const events = parseEvents(r.value);
                for (const ev of events) {
                    if (!alive()) break;
                    processEvent(ev);
                }

                const elapsed = monotonicNow() - pullStart;
                if (elapsed < PULL_MIN_INTERVAL_MS && alive()) await sleep(ctx, PULL_MIN_INTERVAL_MS - elapsed);
            }

            // Loop exited — nothing running, nothing consuming camera resources.
            releaseHandoff(ctx);
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
            const ctx = { stopped: false, req: null, interrupted: false, handoffLease: null, wake: null };
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
            releaseHandoff(ctx);
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

            // Without a confirmed Unsubscribe the subscription stays recorded, so the next loop
            // renews it instead of creating another one; it is forgotten once its TTL has passed.
            const cur = sub;
            if (!skipUnsubscribe && cur && ptzHolds === 0 && !subExpired()) {
                cleanupCtx = ctx;
                try {
                    await opUnsubscribe(cur.url, user, getPass(), req => { ctx.req = req; });
                    if (sub === cur) dropSub();
                } catch (e) {
                    node.warn('Unsubscribe failed (ignored): ' + e.message);
                } finally {
                    cleanupCtx = null;
                    ctx.req    = null;
                }
            }
            if (subExpired()) dropSub();
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
            // PTZ coordination: pause the poll loop and abort whatever ONVIF request is in
            // flight (discovery, subscribe, renew, pull, Unsubscribe) so the connection slot
            // is free for the PTZ command.
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
                let cancelled = false;
                for (const c of [loop, cleanupCtx]) {
                    if (!c || !c.req) continue;
                    c.interrupted = true;
                    c.req.destroy(new Error('ptz-interrupt'));
                    c.req = null;
                    cancelled = true;
                }
                // Brief pause — let the camera process the TCP RST before PTZ connects.
                if (cancelled) await delay(200);
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
                dropSub();
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
                .then(r => r?.lens_mask?.lens_mask_info?.enabled, () => undefined)
                .then(privacy => {
                    if (closed || intent !== startupIntent) return;  // user/registry already decided
                    if (privacy === 'on') {
                        node.status({ fill: 'grey', shape: 'ring', text: 'privacy — idle' });
                    } else {
                        // Unknown privacy state: the poll loop re-checks it (fail closed) with back-off.
                        doStart(privacy === 'off');
                    }
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
