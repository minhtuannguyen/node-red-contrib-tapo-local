# node-red-contrib-tapo-local
[![npm](https://img.shields.io/npm/v/@minguyen68/node-red-contrib-tapo-local.svg?style=flat-square)](https://www.npmjs.com/package/@minguyen68/node-red-contrib-tapo-local)
[![npm](https://img.shields.io/npm/dt/@minguyen68/node-red-contrib-tapo-local.svg?style=flat-square)](https://www.npmjs.com/package/@minguyen68/node-red-contrib-tapo-local)
[![GitHub last commit](https://img.shields.io/github/last-commit/minhtuannguyen/node-red-contrib-tapo-local.svg?style=flat-square)](https://github.com/minhtuannguyen/node-red-contrib-tapo-local)

Node-RED node for **local** control of Tapo C225 cameras — no cloud required

> **Tested with:** Tapo C225 (firmware 1.2.x). May work with other Tapo cameras that use the same local HTTPS API.

---

## Reliability and HomeKit

- Use the **same DHCP-reserved IP address** in every HTTPS, ONVIF and PTZ config for a camera. Hostname case, surrounding spaces and a trailing dot are normalized, but a hostname and its IP are not automatically recognized as the same camera.
- HTTPS commands are serialized per camera, paced at least one second apart, and limited to three active/queued commands. Each command pauses ONVIF polling (aborting an in-flight pull); polling resumes half a second after it finishes. A cold session needs two login requests before its command. `QUEUE_FULL` is backpressure, not a reason to increase the queue or automatically reboot the camera.
- PTZ commands have a separate bounded, paced queue. New movement replaces waiting movement; non-Stop commands expire after three seconds, including time spent waiting for a connection. A Stop bypasses backoff and cooldowns only within about 6.5 seconds after a move that may have reached the camera, and only once; any other Stop obeys cooldowns and pacing.
- Continuous movement requests a **five-second camera-side timeout**. Verify timeout support on your C225 firmware before relying on it; automated tests do not establish hardware support. A timeout rejection is reported without retrying the movement without its safety timeout. Send Stop when releasing a button, and a new movement command to continue beyond five seconds.
- Matching ONVIF event nodes share one poller and subscription per camera. Each node can start/stop its own output independently. Credentials, port, poll hold and motion timeout must match; conflicting configurations are rejected.
- Closing/redeploying a node cancels its queued work and aborts active requests when no other caller needs them. An expired production control lease destroys its tracked requests and blocks new work until its owner confirms cleanup. If that acknowledgement is lost, it recovers after 30 seconds, but only once all tracked requests have closed.
- Network failures use exponential backoff. Event polling and PTZ share ONVIF endpoint health; HTTPS health is separate. Invalid PTZ arguments do not block event polling; authorization, overload and server failures still trigger cooldowns. Reboot and valid Retry-After cooldowns apply to both. Recovery requires occasional probes, not continuous retries.
- Node-RED startup has a three-second quiet period; explicit reboot commands are refused for the first 60 seconds. Cooldowns and possible subscription expiry are recorded atomically in `tapo-local-state.json` under Node-RED's user directory. **Keep that directory persistent in Docker.** The file contains deadlines and failure counts, not passwords or session keys. File-access failures are logged and protection falls back to memory.
- After an unclean restart or a lost subscription response, polling may wait for the possible subscription to expire rather than allocate another one. The requested lifetime is 120 seconds with default settings, up to 390 seconds with the longest poll hold.
- Completed setter results are not used to suppress later commands: HomeKit or another controller may have changed the setting. Identical queued/in-flight requests can still share work.

Treat HomeKit button presses as triggers. Filter retained/initial accessory-state messages and feedback loops in the flow; the plugin cannot tell a replayed HomePod state update from an intentional command. It does not reboot cameras automatically. These protections cannot control requests sent by HomePod, other bridges or other Node-RED processes, nor prove the cause of a camera firmware restart.


---

## Nodes

### `tapo-device` (config node — for `tapo-c225`)

Registers a camera for the **tapo-c225** command node (Tapo local HTTPS API).

| Field    | Description |
|----------|-------------|
| Name     | Optional display label |
| IP       | Camera's local IP address, e.g. `192.168.1.100` |
| Username | `admin` |
| Password | The password you set when you **first added the camera to the Tapo app** — your TP-Link cloud/device password. |

---

### `tapo-onvif-device` (config node — for `tapo-onvif-events`)

Registers a camera for the **tapo-onvif-events** node (ONVIF event subscription).

| Field    | Description |
|----------|-------------|
| Name     | Optional display label |
| IP       | Camera's local IP address, e.g. `192.168.1.100` |
| Username | The username set in the Camera Account |
| Password | The password set in **Tapo app → Settings → Advanced → Camera Account** — a separate local account, not your TP-Link cloud password. |

> These two config nodes require **different credentials**. You need both if you use `tapo-c225` and `tapo-onvif-events` on the same camera.

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

Concurrent queries for the same credentials and time window share work. Successful samples are reused for five seconds; accepted camera errors such as unavailable event history return an empty array and defer another query for 30 seconds. Detection results are snapshots, not a live motion feed.

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
| Poll hold | How long the camera holds each `PullMessages` request before returning empty (default **25 s**) |
| Motion timeout | Silence duration before emitting `detected:false` — must be longer than the camera's batch interval (~14 s on C225). Default **30 s** |

### Input

| `msg.action` | Description |
|---|---|
| `"start"` | Subscribe and begin delivering events |
| `"stop"` | Stop this node's output; when the final subscriber stops, attempt a coordinated Unsubscribe and halt polling |

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
