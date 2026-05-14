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
|---------------|-------------|
| `privacy-on`  | Cover the lens (privacy mode on) |
| `privacy-off` | Uncover the lens |
| `reboot`      | Reboot the camera |

**Output `msg.payload`:**

```json
{ "command": "privacy-on", "result": {} }
```

---

## Adding commands

Open `lib/tapo-client.js` and append an entry to `COMMANDS`. No other files need to change except adding the option to the dropdown in `nodes/tapo-c225.html`.

```javascript
const COMMANDS = {
    'privacy-on':  { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'on'  } } } },
    'privacy-off': { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'off' } } } },
    'reboot':      { method: 'reboot' },
    // add here:
    'my-command':  { method: 'someMethod', params: { ... } },
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
