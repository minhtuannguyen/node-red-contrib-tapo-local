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
| **System** | |
| `reboot` | Reboot the camera |
| **Monitor** | |
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

### Why not the `onvif` npm library?

The Tapo C225 has a very limited HTTP server. The `onvif` library's pull loop keeps running even after `removeListener()` is called, and when it hits an `ECONNRESET` (e.g. during privacy mode) it fires ~89 rapid-fire reconnect attempts starting at 10 ms intervals. This overwhelms the camera's embedded HTTP stack and causes it to freeze — responding to `ping` but refusing all HTTP connections — until the firmware recovers (30–60 s).

This node replaces that with full control: zero requests while stopped, proper ONVIF `Unsubscribe` on stop, and exponential back-off (3 s → 6 s → … → 2 min max) that is harmless.

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

### Tapo C225 quirks

The C225 does **not** send standard `Changed` events. Instead it broadcasts `Initialized` events in batches roughly every **14 s** while motion/person is present. The node handles this with:

- A **300 ms debounce** per topic to coalesce one batch into a single output message.
- A **watchdog timer** (configurable, default 30 s) that fires `detected:false` when the camera goes silent. The watchdog is reset on the **first event of each batch** to eliminate the race condition where watchdog and next batch arrive at the same millisecond.

### Always-on vs start/stop

| | Always-on (never stop) | Start/stop (stop on privacy ON) |
|---|---|---|
| Requests while privacy ON | 1 per 5 s (empty PullMessages) | Zero |
| If camera refuses ONVIF during privacy | Back-off: 3 s → max 2 min between retries | Zero |
| Flow complexity | Simple — single "start" on deploy | Need to sequence stop→privacy-on and privacy-off→start |
| Risk | Minimal — our back-off is safe | Timing errors in sequencing can still cause flashes |

**Recommendation: use always-on.** The C225 accepts ONVIF connections even during privacy mode (it just returns empty events). Our back-off is well-behaved and will never freeze the camera. Only switch to start/stop if you confirm the camera returns `ECONNRESET` during privacy mode (meaning it fully shuts down its ONVIF HTTP server then).

If you do use start/stop, add a **1–2 s delay** between stopping ONVIF and sending the privacy command to give the camera time to process the `Unsubscribe` before new Tapo HTTPS connections arrive:

```
privacy ON  → [stop → tapo-onvif-events] ──1s delay──► [privacy-on  → tapo-local]
privacy OFF → [privacy-off → tapo-local] ──1s delay──► [start → tapo-onvif-events]
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
