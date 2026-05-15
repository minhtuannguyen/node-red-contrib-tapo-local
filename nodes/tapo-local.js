'use strict';

const { executeOnDevice, COMMANDS, getDetections } = require('../lib/tapo-client');

module.exports = function (RED) {

    // ── Config node: device registry ─────────────────────────────────────────
    function TapoDeviceNode(config) {
        RED.nodes.createNode(this, config);
        this.ip       = config.ip;
        this.username = config.username;
        // password stored in credentials (encrypted by Node-RED)
    }
    RED.nodes.registerType('tapo-device', TapoDeviceNode, {
        credentials: { password: { type: 'password' } },
    });

    // ── Command node ──────────────────────────────────────────────────────────
    function TapoC225Node(config) {
        RED.nodes.createNode(this, config);
        const node       = this;
        const deviceNode = RED.nodes.getNode(config.device);

        if (!deviceNode) {
            node.error('No Tapo device configured');
            return;
        }

        node.on('input', async (msg, send, done) => {
            const commandKey = msg.command ?? config.command;

            // Special: poll recent detection events from the camera's event log
            if (commandKey === 'get-detections') {
                const minutes = typeof msg.minutes === 'number' ? msg.minutes : 5;
                node.status({ fill: 'blue', shape: 'dot', text: 'get-detections' });
                try {
                    const events = await getDetections(
                        deviceNode.ip, deviceNode.username,
                        deviceNode.credentials.password, minutes,
                    );
                    msg.payload = { command: 'get-detections', events };
                    node.status({ fill: 'green', shape: 'dot', text: `✓ ${events.length} event(s)` });
                    send(msg);
                    done();
                } catch (err) {
                    node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 50) });
                    done(err);
                }
                return;
            }

            const apiCmd     = COMMANDS[commandKey];

            if (!apiCmd) {
                done(new Error(`Unknown command: "${commandKey}". Valid: ${Object.keys(COMMANDS).concat('get-detections').join(', ')}`));
                return;
            }

            node.status({ fill: 'blue', shape: 'dot', text: commandKey });
            try {
                const result = await executeOnDevice(
                    deviceNode.ip,
                    deviceNode.username,
                    deviceNode.credentials.password,
                    apiCmd,
                );
                msg.payload  = { command: commandKey, result };
                node.status({ fill: 'green', shape: 'dot', text: `✓ ${commandKey}` });
                send(msg);
                done();
            } catch (err) {
                node.status({ fill: 'red', shape: 'ring', text: err.message.slice(0, 50) });
                done(err);
            }
        });

        node.on('close', () => node.status({}));
    }
    RED.nodes.registerType('tapo-local', TapoC225Node);
};
