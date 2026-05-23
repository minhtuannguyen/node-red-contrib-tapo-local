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

const { soapPost, soapEnvelope, xmlText, xmlFindAll, xmlAttr, xmlInner } = require('../lib/onvif-soap');
const { interruptOnvifForPtz } = require('../lib/tapo-client');

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
        const profileToken = config.profileToken || 'MediaProfile000';
        let ptzUrl         = null;   // PTZ service XAddr from GetCapabilities

        // ── Service discovery ─────────────────────────────────────────────────
        async function discoverServices() {
            const xml = await soapPost(
                deviceUrl,
                soapEnvelope('<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>', user, getPass()),
                8000,
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
            // Abort any in-flight PullMessages in tapo-onvif-events so the camera's
            // single connection slot is immediately available for PTZ.
            await interruptOnvifForPtz(ip);

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
                );

            } else if (action === 'gotoPreset') {
                if (!preset) throw new Error('msg.preset or node preset token is required for gotoPreset');
                xml = await soapPost(
                    ptzUrl,
                    soapEnvelope(
                        `<tptz:GotoPreset>` +
                        `<tptz:ProfileToken>${profileToken}</tptz:ProfileToken>` +
                        `<tptz:PresetToken>${escXmlSimple(String(preset))}</tptz:PresetToken>` +
                        `</tptz:GotoPreset>`,
                        user, getPass(),
                    ),
                    8000,
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
                // SOAP fault — clear cached PTZ URL so next call re-discovers.
                ptzUrl = null;
                throw new Error(`${action} SOAP fault: ` + xml.slice(0, 300));
            }
            return {};
        }

        // ── Input handler ─────────────────────────────────────────────────────
        node.on('input', async (msg, send, done) => {
            const action = msg.action  !== undefined ? msg.action  : (config.action || 'continuousMove');
            const pan    = msg.pan     !== undefined ? Number(msg.pan)    : Number(config.pan    || 0);
            const tilt   = msg.tilt    !== undefined ? Number(msg.tilt)   : Number(config.tilt   || 0);
            const preset = msg.preset  !== undefined ? msg.preset  : (config.preset  || '');

            node.status({ fill: 'blue', shape: 'dot', text: action });
            try {
                const result = await execPtz(action, pan, tilt, preset);
                node.status({ fill: 'green', shape: 'dot', text: action });
                msg.payload = { action, result };
                send(msg);
                done();
            } catch (err) {
                // On any connection failure clear cached URLs so next attempt re-discovers.
                if (/timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND/.test(err.message)) {
                    ptzUrl = mediaUrl = profileToken = null;
                }
                node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 50) });
                done(err);
            }
        });

        node.on('close', () => {
            ptzUrl = null;
        });
    }

    RED.nodes.registerType('tapo-ptz', TapoPtzNode);
};

// Minimal XML escape for runtime values inserted into SOAP body.
function escXmlSimple(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
