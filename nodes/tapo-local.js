'use strict';

const { authenticate, COMMANDS } = require('../lib/tapo-client');

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
            const apiCmd     = COMMANDS[commandKey];

            if (!apiCmd) {
                done(new Error(`Unknown command: "${commandKey}". Valid: ${Object.keys(COMMANDS).join(', ')}`));
                return;
            }

            node.status({ fill: 'blue', shape: 'dot', text: commandKey });
            try {
                const { sendCmd } = await authenticate(
                    deviceNode.ip,
                    deviceNode.username,
                    deviceNode.credentials.password,
                );
                const result = await sendCmd(apiCmd);
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
