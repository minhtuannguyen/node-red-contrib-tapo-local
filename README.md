# node-red-contrib-tapo-local
[![npm](https://img.shields.io/npm/v/@minguyen68/node-red-contrib-tapo-local.svg?style=flat-square)](https://www.npmjs.com/package/@minguyen68/node-red-contrib-tapo-local)
[![npm](https://img.shields.io/npm/dt/@minguyen68/node-red-contrib-tapo-local.svg?style=flat-square)](https://www.npmjs.com/package/@minguyen68/node-red-contrib-tapo-local)
[![GitHub last commit](https://img.shields.io/github/last-commit/minhtuannguyen/node-red-contrib-tapo-local.svg?style=flat-square)](https://github.com/minhtuannguyen/node-red-contrib-tapo-local)

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
| **Privacy** | |
| `get-lens-mask` | Read current lens mask state — `msg.payload.result.lens_mask.lens_mask_info.enabled` is `"on"` or `"off"` |
| `privacy-on` | Cover the lens (privacy mode on) |
| `privacy-off` | Uncover the lens |
| **Alarm** | |
| `alarm-on` | Enable alarm on detected events (sound + light) |
| `alarm-off` | Disable alarm on detected events |
| `alarm-trigger` | Immediately sound siren + light (manual trigger) |
| `alarm-stop` | Stop a manually triggered alarm |
| **Motion & AI detection** | |
| `motion-on` | Enable motion detection |
| `motion-off` | Disable motion detection |
| `person-on` | Enable AI person detection |
| `person-off` | Disable AI person detection |
| `pet-on` | Enable pet detection |
| `pet-off` | Disable pet detection |
| `vehicle-on` | Enable vehicle detection |
| `vehicle-off` | Disable vehicle detection |
| `package-on` | Enable package delivery detection |
| `package-off` | Disable package delivery detection |
| `linecross-on` | Enable line crossing detection |
| `linecross-off` | Disable line crossing detection |
| `tamper-on` | Enable camera tamper detection |
| `tamper-off` | Disable camera tamper detection |
| `tracking-on` | Enable auto-tracking (pan/tilt follows subject) |
| `tracking-off` | Disable auto-tracking |
| **Sound detection** | |
| `baby-cry-on` | Enable baby cry detection |
| `baby-cry-off` | Disable baby cry detection |
| `glass-break-on` | Enable glass break detection |
| `glass-break-off` | Disable glass break detection |
| `bark-on` | Enable dog bark detection |
| `bark-off` | Disable dog bark detection |
| `meow-on` | Enable cat meow detection |
| `meow-off` | Disable cat meow detection |
| **Camera** | |
| `led-on` | Turn the status LED on |
| `led-off` | Turn the status LED off |
| `night-vision-on` | Night vision always-on (IR active) |
| `night-vision-off` | Night vision off (always day mode) |
| `night-vision-auto` | Night vision auto-switch |
| `flip-on` | Flip image vertically — for ceiling-mount installs |
| `flip-off` | Disable vertical flip |
| `record-audio-on` | Enable microphone recording |
| `record-audio-off` | Disable microphone recording |
| `circular-recording-on` | Enable circular (loop) SD recording — oldest footage overwritten when full |
| `circular-recording-off` | Disable circular recording |
| **System** | |
| `reboot` | Reboot the camera |
| **Monitor** | |
| `get-device-info` | Device info — `msg.payload.result.device_info.basic_info` has model, firmware, MAC |
| `get-sd-card` | SD card status — `msg.payload.result.harddisk_manage.hd_info` has status, total/free space |
| `get-detections` | Poll recent detection events — see below |

**Output `msg.payload`:**

```json
{ "command": "privacy-on", "result": {} }
```

---

### Polling detection events (`get-detections`)

Set `msg.command = 'get-detections'` and optionally `msg.minutes = 10` (default 5) before triggering the node.
`msg.payload.events` will be an array of detection objects from the camera's local event log:

```json
{ "command": "get-detections", "events": [
  { "start_time": 1747300000, "end_time": 1747300010, "cls_type": "person", ... },
  { "start_time": 1747299900, "end_time": 1747299905, "cls_type": "baby_cry", ... }
]}
```

**Detection types reported by C225:** `motion`, `person`, `vehicle`, `pet`, `baby_cry`, `glass_break`, and others depending on firmware.

> **Requires:** SD card inserted + local recording enabled in the Tapo app. If not present the node returns an empty events array.

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

## `tapo-onvif-events` — live event subscription

Subscribes to ONVIF WS-PullPoint events from the camera — **no `onvif` npm library**, implemented directly via raw HTTP SOAP calls.

### Node settings

| Field | Description |
|---|---|
| Device | Select a `tapo-device` config node |
| ONVIF port | Camera's ONVIF port (default **2020** for Tapo cameras) |
| Action | Fixed action, or leave blank to use `msg.action` at runtime |
| Poll hold | How long the camera holds each `PullMessages` request before returning empty (default **5 s**) |
| Motion timeout | Silence duration before emitting `detected:false` — must be longer than the camera's batch interval (~14 s on C225). Default **30 s** |

### Input

| `msg.action` | Description |
|---|---|
| `"start"` | Subscribe and begin delivering events |
| `"stop"` | Send ONVIF `Unsubscribe` to camera and halt all requests |

### Output `msg.payload`

```json
{
  "topic":    "RuleEngine/PeopleDetector/People",
  "payload": {
    "detected": true,
    "time":     "2026-05-18T12:03:01Z",
    "property": "Initialized",
    "source":   { "Rule": "MyPeopleDetectorRule" },
    "data":     { "IsMotion": "true" }
  }
}
```

`detected: false` is emitted after `motionTimeout` seconds of camera silence (watchdog).

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
