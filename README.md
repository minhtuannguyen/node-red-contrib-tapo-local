# node-red-contrib-tapo-local

Node-RED node for **local** control of Tapo C225 cameras — no cloud required

> **Tested with:** Tapo C225 (firmware 1.2.x). May work with other Tapo cameras that use the same local HTTPS API.

---

## Nodes

### `tapo-device` (config node)

Registers a camera. Select it from any `tapo-c225` node.

| Field    | Description |
|----------|-------------|
| Name     | Optional display label |
| IP       | Camera's local IP address, e.g. `192.168.1.100` |
| Username | `admin` |
| Password | Camera account password — find it in **Tapo app → Settings → Advanced → Camera Account** (may differ from your TP-Link cloud password) |

---

### `tapo-c225`

Sends a command to the camera when triggered by any input message.

**Node settings:**

| Field   | Description |
|---------|-------------|
| Device  | Select a `tapo-device` config node |
| Command | Default command to run (see table below) |

**Override at runtime** — set `msg.command` before triggering:

```json
{ "command": "privacy-off" }
```

**Available commands:**

| `msg.command` | Description |
|---|---|
| `privacy-on` | Cover the lens (privacy mode on) |
| `privacy-off` | Uncover the lens |
| `alarm-on` | Enable alarm on detected events (sound + light) |
| `alarm-off` | Disable alarm on detected events |
| `alarm-trigger` | Immediately sound siren + light (manual trigger) |
| `alarm-stop` | Stop a manually triggered alarm |
| `motion-on` | Enable motion detection |
| `motion-off` | Disable motion detection |
| `person-on` | Enable AI person detection |
| `person-off` | Disable AI person detection |
| `led-on` | Turn the status LED on |
| `led-off` | Turn the status LED off |
| `night-vision-on` | Night vision always-on (IR active) |
| `night-vision-off` | Night vision off (always day mode) |
| `night-vision-auto` | Night vision auto-switch |
| `reboot` | Reboot the camera |

**Output `msg.payload`:**

```json
{ "command": "privacy-on", "result": {} }
```

---

## Adding commands

Open `lib/tapo-client.js` and append an entry to `COMMANDS`. No other file changes needed unless you want the command in the editor dropdown (`nodes/tapo-local.html`).

```javascript
const COMMANDS = {
    // _direct: false (default) → wrapped in multipleRequest (pytapo executeFunction path)
    // _direct: true            → sent as-is (pytapo performRequest path, for method:'set'/'do')

    'my-command': { method: 'someMethod', params: { ... } },
};
```

---

## CLI utility

`scripts/tapo_privacy.js` is a standalone Node.js script for testing from the command line (no deps):

```bash
node scripts/tapo_privacy.js <ip> <username> <password> <command>

# Examples:
node scripts/tapo_privacy.js 192.168.1.100 admin mypassword privacy-off
node scripts/tapo_privacy.js 192.168.1.100 admin mypassword reboot
```

---

## License

MIT
