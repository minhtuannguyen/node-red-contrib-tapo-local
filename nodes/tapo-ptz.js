'use strict';

/**
 * tapo-ptz — ONVIF PTZ control node for Tapo C225.
 *
 * Zero npm deps — raw SOAP over HTTP using lib/onvif-soap.js.
 *
 * Supported actions (set in node config or override via msg.action):
 *   continuousMove  — move at pan/tilt speed until stop
 *   stop            — stop all movement
 *   gotoPreset      — move to a named/token preset position
 *   getPresets      — return list of presets as msg.payload
 *
 * Runtime overrides:
 *   msg.action  — override configured action
 *   msg.pan     — pan speed  (-1 = full left,  1 = full right, 0 = none)
 *   msg.tilt    — tilt speed (-1 = full down,  1 = full up,    0 = none)
 *   msg.preset  — preset token or name for gotoPreset
 *
 * Uses the same tapo-onvif-device config node as tapo-onvif-events.
 * Coordinates with tapo-onvif-events via interrupt mechanism so PTZ commands
 * are not delayed by an in-flight PullMessages hold.
 */

const { soapPost, soapEnvelope, xmlText, xmlFindAll, xmlAttr, xmlInner, escXml } = require('../lib/onvif-soap');
const { interruptOnvifForPtz, acquireLease } = require('../lib/tapo-client');
const { performance } = require('perf_hooks');

const monotonicNow = () => performance.now();

// ── Per-camera PTZ coordination (shared by all tapo-ptz nodes) ───────────────
// One HomeKit button = one tapo-ptz node, so serialization must be per IP,
// not per node.  Commands run one at a time; a waiting move/stop is dropped
// when a newer move/stop arrives (only the latest direction matters), and
// after a network failure commands fail fast until the back-off expires.
const PTZ_QUEUE_MAX   = 4;
const PTZ_ACTIONS     = new Set(['continuousMove', 'stop', 'gotoPreset', 'getPresets']);
const PTZ_BACKOFF_MIN = 3000;
const PTZ_BACKOFF_MAX = 30000;
const NET_ERR_RE      = /timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|EHOSTDOWN|ENETUNREACH|ENOTFOUND|EAI_AGAIN|socket hang up|closed before response|ONVIF HTTP/;
const _ptzDevices     = new Map(); // ip → { tail, waiting: [], failures, blockedUntil }

function ptzDevice(ip) {
    let d = _ptzDevices.get(ip);
    if (!d) { d = { tail: Promise.resolve(), waiting: [], failures: 0, blockedUntil: 0 }; _ptzDevices.set(ip, d); }
    return d;
}

function assertPtzAvailable(ip, d) {
    if (monotonicNow() < d.blockedUntil) {
        const secs = Math.ceil((d.blockedUntil - monotonicNow()) / 1000);
        throw new Error(`Camera ${ip} unreachable — PTZ not sent, retry in ${secs}s`);
    }
}

// Resolves with the result, or with { superseded: true } if a newer move/stop replaced it.
function enqueuePtz(ip, action, run) {
    const d = ptzDevice(ip);
    assertPtzAvailable(ip, d);
    const movement = action === 'continuousMove' || action === 'stop';
    if (movement) {
        for (const w of d.waiting) if (w.movement && !w.cancelled) w.cancelled = true;
    }
    if (d.waiting.filter(w => !w.cancelled).length >= PTZ_QUEUE_MAX) {
        throw new Error(`PTZ queue for ${ip} is full — command dropped`);
    }
    const entry = { movement, cancelled: false };
    d.waiting.push(entry);
    const op = d.tail.then(async () => {
        d.waiting.splice(d.waiting.indexOf(entry), 1);
        if (entry.cancelled) return { superseded: true };
        assertPtzAvailable(ip, d);
        try {
            const result = await run();
            d.failures = 0;
            d.blockedUntil = 0;
            return result;
        } catch (err) {
            if (NET_ERR_RE.test(err.message)) {
                d.failures++;
                d.blockedUntil = monotonicNow() + Math.min(PTZ_BACKOFF_MIN * 2 ** Math.min(d.failures - 1, 10), PTZ_BACKOFF_MAX);
            }
            throw err;
        }
    });
    d.tail = op.catch(() => {});
    return op;
}

module.exports = function (RED) {

    function TapoPtzNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        const deviceNode = RED.nodes.getNode(config.device);
        const onvifPort  = parseInt(config.onvifPort, 10) || 2020;

        if (!deviceNode) {
            node.error('No device configured');
            node.status({ fill: 'red', shape: 'ring', text: 'no device' });
            return;
        }

        const ip      = deviceNode.ip;
        const user    = deviceNode.username;
        const getPass = () => deviceNode.credentials.password;

        const deviceUrl = `http://${ip}:${onvifPort}/onvif/device_service`;

        // Profile token is configured directly (default: MediaProfile000 for C225).
        // PTZ service URL is discovered once from GetCapabilities then cached.
        const profileToken = escXml(config.profileToken || 'MediaProfile000');
        let ptzUrl         = null;   // PTZ service XAddr from GetCapabilities
        let closed         = false;

        // Aborts the in-flight SOAP request once the lease has expired, so PTZ never overlaps HTTPS work.
        let ptzReq = null, leaseExpired = false;
        const trackReq = req => {
            if (closed) req.destroy(new Error('PTZ node closed'));
            else if (leaseExpired) req.destroy(new Error('PTZ lease expired'));
            else ptzReq = req;
        };

        // ── Service discovery ─────────────────────────────────────────────────
        async function discoverServices() {
            const xml = await soapPost(
                deviceUrl,
                soapEnvelope('<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>', user, getPass()),
                8000,
                trackReq,
            );
            if (/[Ff]ault/.test(xml)) throw new Error('GetCapabilities SOAP fault: ' + xml.slice(0, 300));
            // Extract PTZ XAddr (inside <PTZ> element)
            const ptzEl = xmlInner(xml, 'PTZ');
            ptzUrl = xmlText(ptzEl, 'XAddr') || `http://${ip}:${onvifPort}/onvif/ptz_service`;
        }

        // Lazy-discover PTZ URL on first command; skip if already known.
        async function ensureDiscovered() {
            if (!ptzUrl) await discoverServices();
        }

        // ── PTZ command execution ─────────────────────────────────────────────
        async function execPtz(action, pan, tilt, preset) {
            if (closed) throw new Error('PTZ node closed');
            // Exclusive hold on the camera's HTTPS queue, so no HTTPS login/command overlaps this PTZ call.
            // A Stop is never withheld: without the lease or the ONVIF pause it is still sent.
            const mustSend = action === 'stop';
            const lease = await acquireLease(ip, { waitMs: mustSend ? 1500 : 5000, stillWanted: () => !closed });
            let release = null;
            leaseExpired = false;
            ptzReq       = null;
            const offExpiry = lease && lease.signal.on(() => {
                leaseExpired = true;
                if (ptzReq) ptzReq.destroy(new Error('PTZ lease expired'));
            });
            try {
                if (closed) throw new Error('PTZ node closed');
                if (!lease && !mustSend) throw new Error(`Camera ${ip} control busy \u2014 PTZ not sent`);
                // Pause tapo-onvif-events (aborting its in-flight PullMessages) so the
                // camera's connection slot is free for PTZ; resume when done.
                try {
                    release = await interruptOnvifForPtz(ip);
                } catch (err) {
                    if (!mustSend) throw err;
                }
                if (closed) throw new Error('PTZ node closed');
                return await execPtzCommand(action, pan, tilt, preset);
            } finally {
                ptzReq = null;
                if (offExpiry) offExpiry();
                if (release) release();
                if (lease) lease.release();
            }
        }

        async function execPtzCommand(action, pan, tilt, preset) {
            await ensureDiscovered();

            let xml;

            if (action === 'continuousMove') {
                xml = await soapPost(
                    ptzUrl,
                    soapEnvelope(
                        `<tptz:ContinuousMove>` +
                        `<tptz:ProfileToken>${profileToken}</tptz:ProfileToken>` +
                        `<tptz:Velocity><tt:PanTilt x="${pan}" y="${tilt}"/></tptz:Velocity>` +
                        `</tptz:ContinuousMove>`,
                        user, getPass(),
                    ),
                    8000,
                    trackReq,
                );

            } else if (action === 'stop') {
                xml = await soapPost(
                    ptzUrl,
                    soapEnvelope(
                        `<tptz:Stop>` +
                        `<tptz:ProfileToken>${profileToken}</tptz:ProfileToken>` +
                        `<tptz:PanTilt>true</tptz:PanTilt>` +
                        `<tptz:Zoom>true</tptz:Zoom>` +
                        `</tptz:Stop>`,
                        user, getPass(),
                    ),
                    8000,
                    trackReq,
                );

            } else if (action === 'gotoPreset') {
                if (!preset) throw new Error('msg.preset or node preset token is required for gotoPreset');
                xml = await soapPost(
                    ptzUrl,
                    soapEnvelope(
                        `<tptz:GotoPreset>` +
                        `<tptz:ProfileToken>${profileToken}</tptz:ProfileToken>` +
                        `<tptz:PresetToken>${escXml(String(preset))}</tptz:PresetToken>` +
                        `</tptz:GotoPreset>`,
                        user, getPass(),
                    ),
                    8000,
                    trackReq,
                );

            } else if (action === 'getPresets') {
                xml = await soapPost(
                    ptzUrl,
                    soapEnvelope(
                        `<tptz:GetPresets>` +
                        `<tptz:ProfileToken>${profileToken}</tptz:ProfileToken>` +
                        `</tptz:GetPresets>`,
                        user, getPass(),
                    ),
                    8000,
                    trackReq,
                );
                if (/[Ff]ault/.test(xml)) throw new Error('GetPresets SOAP fault: ' + xml.slice(0, 300));
                return xmlFindAll(xml, 'Preset').map(p => ({
                    token: xmlAttr(p, 'token'),
                    name:  xmlText(p, 'Name'),
                }));

            } else {
                throw new Error(`Unknown PTZ action: "${action}". Use continuousMove, stop, gotoPreset, or getPresets.`);
            }

            if (/[Ff]ault/.test(xml)) {
                throw new Error(`${action} SOAP fault: ` + xml.slice(0, 300));
            }
            return {};
        }

        // Speeds outside [-1, 1] or NaN produce SOAP faults on every press.
        const speed = v => { const n = Number(v); return Number.isFinite(n) ? Math.max(-1, Math.min(1, n)) : 0; };

        // ── Input handler ─────────────────────────────────────────────────────
        node.on('input', async (msg, send, done) => {
            if (closed) { done(new Error('PTZ node closed')); return; }
            const action = msg.action  !== undefined ? msg.action  : (config.action || 'continuousMove');
            const pan    = speed(msg.pan  !== undefined ? msg.pan  : (config.pan  || 0));
            const tilt   = speed(msg.tilt !== undefined ? msg.tilt : (config.tilt || 0));
            const preset = msg.preset  !== undefined ? msg.preset  : (config.preset  || '');

            // Reject bad input before pausing ONVIF or contacting the camera.
            if (!PTZ_ACTIONS.has(action)) {
                done(new Error(`Unknown PTZ action: "${action}". Use continuousMove, stop, gotoPreset, or getPresets.`));
                return;
            }
            if (action === 'gotoPreset' && !preset) {
                done(new Error('msg.preset or node preset token is required for gotoPreset'));
                return;
            }

            node.status({ fill: 'blue', shape: 'dot', text: action });
            try {
                const result = await enqueuePtz(ip, action, () => execPtz(action, pan, tilt, preset));
                if (closed) { done(); return; }
                if (result && result.superseded) {
                    node.status({ fill: 'grey', shape: 'dot', text: `${action} (superseded)` });
                    done();
                    return;
                }
                node.status({ fill: 'green', shape: 'dot', text: action });
                msg.payload = { action, result };
                send(msg);
                done();
            } catch (err) {
                // Wrong endpoint (e.g. 404) — rediscover on the next command.
                if (/ONVIF HTTP/.test(err.message)) ptzUrl = null;
                if (!closed) node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 50) });
                done(err);
            }
        });

        node.on('close', () => {
            closed = true;
            if (ptzReq) ptzReq.destroy(new Error('PTZ node closed'));
            ptzUrl = null;
        });
    }

    RED.nodes.registerType('tapo-ptz', TapoPtzNode);
};
