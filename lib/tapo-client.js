'use strict';

/**
 * Tapo local HTTPS API client — zero npm deps.
 *
 * Auth protocol: challenge-response ("encrypt_type": "3")
 *   1. Send cnonce → camera returns nonce + device_confirm
 *   2. Verify device_confirm = SHA256(cnonce + hashedPw + nonce) + nonce + cnonce
 *   3. Send digest_passwd → receive stok + start_seq
 *   4. Derive AES-128-CBC keys (lsk, ivb) from session material
 *   5. Encrypt each command with multipleRequest wrapper, sign with Tapo_tag
 *
 * To add a new command: append an entry to COMMANDS.
 */

const https  = require('https');
const crypto = require('crypto');

// One keep-alive agent per session so auth + commands share the same TCP connection.
function makeAgent() {
    return new https.Agent({
        rejectUnauthorized: false,
        keepAlive:          true,
        maxSockets:         1,
        ALPNProtocols:      ['http/1.1'],
    });
}

const REQUEST_TIMEOUT_MS = 12000; // 12 s — abort if camera stops responding

function post(agent, ip, path, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req  = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent,
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
            timeout: REQUEST_TIMEOUT_MS,
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(new Error('Bad JSON from camera: ' + s.slice(0, 200))); } });
        });
        req.on('timeout', () => { req.destroy(new Error('Request timed out after ' + REQUEST_TIMEOUT_MS + 'ms')); });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

function postRaw(agent, ip, path, bodyStr, headers) {
    return new Promise((resolve, reject) => {
        const buf = Buffer.from(bodyStr, 'utf8');
        const req = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent, headers,
            timeout: REQUEST_TIMEOUT_MS,
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(new Error('Bad JSON from camera: ' + s.slice(0, 200))); } });
        });
        req.on('timeout', () => { req.destroy(new Error('Request timed out after ' + REQUEST_TIMEOUT_MS + 'ms')); });
        req.on('error', reject);
        req.write(buf);
        req.end();
    });
}

/**
 * Authenticate and return a { sendCmd } session.
 * sendCmd(apiCmd) sends an encrypted API command and returns the decoded result.
 */
async function authenticate(ip, username, password) {
    const sha256U = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex').toUpperCase();
    const md5U    = s => crypto.createHash('md5').update(s, 'utf8').digest('hex').toUpperCase();
    const agent   = makeAgent();

    const cnonce = crypto.randomBytes(8).toString('hex').toUpperCase();

    // Step 1: probe
    const r1 = await post(agent, ip, '/', { method: 'login', params: { cnonce, encrypt_type: '3', username } });
    if (r1?.result?.data?.code === -40404) {
        throw Object.assign(new Error(`Account locked — wait ${r1.result.data.sec_left ?? 0}s`), { code: 'LOCKED' });
    }
    if (r1?.error_code !== -40413) throw new Error('Auth probe failed: ' + JSON.stringify(r1));

    const { nonce, device_confirm: devConfirm } = r1.result.data;

    // Step 2: verify device_confirm — accepts both SHA256 and MD5 password hashes
    let hashedPw = null;
    for (const h of [sha256U(password), md5U(password)]) {
        if (sha256U(cnonce + h + nonce) + nonce + cnonce === devConfirm) { hashedPw = h; break; }
    }
    if (!hashedPw) throw new Error('Wrong password — device_confirm mismatch');

    // Step 3: authenticate → stok + start_seq
    const r2 = await post(agent, ip, '/', {
        method: 'login',
        params: { cnonce, encrypt_type: '3', digest_passwd: sha256U(hashedPw + cnonce + nonce) + cnonce + nonce, username },
    });
    if (r2?.result?.data?.code === -40404) {
        throw Object.assign(new Error(`Account locked — wait ${r2.result.data.sec_left ?? 0}s`), { code: 'LOCKED' });
    }
    if (!r2?.result?.stok) throw new Error('Auth failed: ' + JSON.stringify(r2));

    const stok      = r2.result.stok;
    let   seq       = r2.result.start_seq ?? 1;

    // Step 4: derive AES-128-CBC keys
    const hashedKey = sha256U(cnonce + hashedPw + nonce);
    const tok16     = t => crypto.createHash('sha256').update(t + cnonce + nonce + hashedKey, 'utf8').digest().slice(0, 16);
    const lsk       = tok16('lsk');
    const ivb       = tok16('ivb');

    // Tag step1 is constant per session
    const tagStep1 = sha256U(hashedPw + cnonce);

    // Camera validates Tapo_tag against a spaced-JSON body (matching Python's json.dumps).
    const pyJson = o => JSON.stringify(o).replace(/:/g, ': ').replace(/,/g, ', ');

    // Step 5: send encrypted commands
    async function sendCmd(apiCmd) {
        // Strip meta fields before sending to camera
        const { _acceptErrors = [], _acceptNetworkErrors = false, _direct = false, ...cmd } = apiCmd;
        // _direct: true → send command as-is (pytapo's performRequest path, used for method:'set'/'do')
        // _direct: false → wrap in multipleRequest (pytapo's executeFunction path)
        const payload = _direct ? cmd : { method: 'multipleRequest', params: { requests: [cmd] } };
        const cipher  = crypto.createCipheriv('aes-128-cbc', lsk, ivb);
        const encReq  = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]).toString('base64');
        const bodyStr = pyJson({ method: 'securePassthrough', params: { request: encReq } });
        const curSeq  = seq++;
        const buf     = Buffer.from(bodyStr, 'utf8');
        const tag     = crypto.createHash('sha256')
            .update(tagStep1 + bodyStr + String(curSeq), 'utf8').digest('hex').toUpperCase();

        let r;
        try {
            r = await postRaw(agent, ip, `/stok=${stok}/ds`, bodyStr, {
                'User-Agent':      'Tapo CameraClient Android',
                'Accept-Encoding': 'gzip, deflate',
                'Accept':          'application/json',
                'Connection':      'keep-alive',
                'Host':            `${ip}:443`,
                'Referer':         `https://${ip}:443`,
                'requestByApp':    'true',
                'Content-Type':    'application/json; charset=UTF-8',
                'Content-Length':  buf.length,
                'Seq':             String(curSeq),
                'Tapo_tag':        tag,
            });
        } catch (err) {
            if (_acceptNetworkErrors) return {};
            throw err;
        }

        if (r.error_code !== 0) throw new Error('securePassthrough error ' + r.error_code);
        // Direct commands (method:'set'/'do') return {error_code:0} with no encrypted body
        if (!r.result?.response) return {};
        const decipher = crypto.createDecipheriv('aes-128-cbc', lsk, ivb);
        const inner    = JSON.parse(
            Buffer.concat([decipher.update(Buffer.from(r.result.response, 'base64')), decipher.final()]).toString()
        );
        if (_direct) {
            // Direct commands return {error_code, result} — no responses array
            if (inner.error_code !== 0 && !_acceptErrors.includes(inner.error_code)) {
                throw new Error('command error: ' + JSON.stringify(inner));
            }
            return inner.result ?? {};
        }
        if (inner.error_code !== 0) throw new Error('command error ' + inner.error_code);
        const resp0 = inner.result?.responses?.[0];
        if (resp0?.error_code !== 0 && !_acceptErrors.includes(resp0?.error_code)) {
            throw new Error('command error: ' + JSON.stringify(resp0));
        }
        return resp0?.result ?? {};
    }

    return { sendCmd, agent };
}

// ─── Per-device session cache + serial command queue ──────────────────────────
// Two tapo-local nodes triggered simultaneously (e.g. privacy + alarm) both call
// authenticate() at the same time. The camera only handles one auth handshake at
// a time — the second attempt collides on the nonce → -40413 INVALID_NONCE.
// Solution: serialize ALL commands per device and reuse the cached session.
const SESSION_TTL_MS = 10 * 60 * 1000; // 10 min — well within typical stok lifetime
const _sessions      = new Map();       // `${ip}|${user}` → { sendCmd, agent, expiresAt }
const _queues        = new Map();       // `${ip}|${user}` → Promise (last running op)

// ── ONVIF coordination registry ────────────────────────────────────────────────
// If a tapo-onvif-events node is watching this IP, it registers here.
//   privacy-on  → await reg.stop()  before the command (clean Unsubscribe first)
//   privacy-off → reg.start()       after  the command (ONVIF resumes automatically)
// Only privacy commands trigger coordination; all others run at full speed.
const _onvifRegistry = new Map(); // ip → { stop: async fn, start: fn }

function registerOnvifCallbacks(ip, callbacks) { _onvifRegistry.set(ip, callbacks); }
function unregisterOnvifCallbacks(ip)          { _onvifRegistry.delete(ip); }

async function executeOnDevice(ip, username, password, apiCmd) {
    const key    = `${ip}|${username}`;

    // Wait for the previous command on this device to finish before starting ours.
    // This prevents concurrent auth handshakes and seq-counter races.
    const prevOp = (_queues.get(key) ?? Promise.resolve()).catch(() => {});

    const thisOp = prevOp.then(async () => {
        // ── Privacy-mode coordination with the ONVIF event node ───────────────
        // privacy-on:  stop ONVIF first (clean Unsubscribe + RST) so the C225
        //              connection slot is free before we open the HTTPS session.
        // privacy-off: start ONVIF after the command so it resumes automatically.
        // All other commands run without coordination — no added latency.
        const reg          = _onvifRegistry.get(ip);
        const isPrivacyCmd = apiCmd.method === 'setLensMaskConfig';
        const privacyOn    = isPrivacyCmd &&
            apiCmd.params?.lens_mask?.lens_mask_info?.enabled === 'on';
        if (reg && privacyOn) {
            await reg.stop();
            // The C225 closes idle HTTPS keep-alive sockets while ONVIF holds the
            // single TCP slot.  After doStop() the slot is free but the cached agent
            // still holds a dead TLS socket → ERR_SSL_WRONG_VERSION_NUMBER on reuse.
            // Destroy it now so the next block always opens a fresh TLS handshake.
            const stale = _sessions.get(key);
            if (stale) { stale.agent.destroy(); _sessions.delete(key); }
        }

        // Reuse cached session or create a new one
        let cached = _sessions.get(key);
        if (!cached || Date.now() >= cached.expiresAt) {
            if (cached) cached.agent.destroy();  // free keep-alive sockets from old session
            const { sendCmd, agent } = await authenticate(ip, username, password);
            cached = { sendCmd, agent, expiresAt: Date.now() + SESSION_TTL_MS };
            _sessions.set(key, cached);
        }

        let succeeded = false;
        try {
            const result = await cached.sendCmd(apiCmd);
            succeeded = true;
            return result;
        } catch (err) {
            // Stok expired mid-session (-40401) — clear cache and retry once
            if (/securePassthrough error -40401/.test(err.message)) {
                cached.agent.destroy();  // free sockets from expired session
                _sessions.delete(key);
                const { sendCmd, agent } = await authenticate(ip, username, password);
                _sessions.set(key, { sendCmd, agent, expiresAt: Date.now() + SESSION_TTL_MS });
                const result = await sendCmd(apiCmd);
                succeeded = true;
                return result;
            }
            // Timeout or network error — destroy the cached session so the next
            // command gets a fresh connection instead of reusing a dead socket.
            if (/timed out|ECONNRESET|ECONNREFUSED|ETIMEDOUT|socket hang up/.test(err.message)) {
                cached.agent.destroy();
                _sessions.delete(key);
            }
            throw err;
        } finally {
            // privacy-off succeeded → restart ONVIF automatically.
            const privacyOff = isPrivacyCmd &&
                apiCmd.params?.lens_mask?.lens_mask_info?.enabled === 'off';
            if (reg && privacyOff && succeeded) reg.start();
        }
    });

    // Store as the queue tail (swallow errors so the queue never gets permanently stuck)
    _queues.set(key, thisOp.catch(() => {}));
    return thisOp;
}

// Add new commands here — no other changes needed.
// _direct:false (default) → wrapped in multipleRequest (pytapo's executeFunction path)
// _direct:true            → sent as-is (pytapo's performRequest path, used for method:'set'/'do')
const COMMANDS = {
    // ── Privacy (lens mask) ────────────────────────────────────────────────────
    'get-lens-mask': { method: 'getLensMaskConfig', params: { lens_mask: { name: ['lens_mask_info'] } } },
    'privacy-on':    { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'on'  } } } },
    'privacy-off':   { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'off' } } } },

    // ── Alarm — configure auto-trigger on detected events ─────────────────────
    'alarm-on':      { _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'on',  light_type: '0', alarm_mode: ['sound', 'light'] } } },
    'alarm-off':     { _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'off', light_type: '0', alarm_mode: ['sound', 'light'] } } },
    // Immediately start/stop the alarm siren+light regardless of detection events
    'alarm-trigger': { _direct: true, method: 'do',  msg_alarm: { manual_msg_alarm: { action: 'start' } } },
    'alarm-stop':    { _direct: true, method: 'do',  msg_alarm: { manual_msg_alarm: { action: 'stop'  } } },

    // ── LED status light ───────────────────────────────────────────────────────
    'led-on':  { method: 'setLedStatus', params: { led: { config: { enabled: 'on'  } } } },
    'led-off': { method: 'setLedStatus', params: { led: { config: { enabled: 'off' } } } },

    // ── Motion detection ───────────────────────────────────────────────────────
    'motion-on':  { method: 'setDetectionConfig', params: { motion_detection: { motion_det: { enabled: 'on'  } } } },
    'motion-off': { method: 'setDetectionConfig', params: { motion_detection: { motion_det: { enabled: 'off' } } } },

    // ── Person (AI) detection ──────────────────────────────────────────────────
    'person-on':  { method: 'setPersonDetectionConfig', params: { people_detection: { detection: { enabled: 'on'  } } } },
    'person-off': { method: 'setPersonDetectionConfig', params: { people_detection: { detection: { enabled: 'off' } } } },

    // ── Baby cry detection (sound) ─────────────────────────────────────────────
    'baby-cry-on':  { method: 'setBCDConfig', params: { sound_detection: { bcd: { enabled: 'on'  } } } },
    'baby-cry-off': { method: 'setBCDConfig', params: { sound_detection: { bcd: { enabled: 'off' } } } },

    // ── Glass break detection ──────────────────────────────────────────────────
    'glass-break-on':  { method: 'setGlassDetectionConfig', params: { glass_detection: { detection: { enabled: 'on'  } } } },
    'glass-break-off': { method: 'setGlassDetectionConfig', params: { glass_detection: { detection: { enabled: 'off' } } } },
    // ── Pet detection ────────────────────────────────────────────────────────────
    'pet-on':  { method: 'setPetDetectionConfig', params: { pet_detection: { detection: { enabled: 'on'  } } } },
    'pet-off': { method: 'setPetDetectionConfig', params: { pet_detection: { detection: { enabled: 'off' } } } },

    // ── Vehicle detection ────────────────────────────────────────────────────────
    'vehicle-on':  { method: 'setVehicleDetectionConfig', params: { vehicle_detection: { detection: { enabled: 'on'  } } } },
    'vehicle-off': { method: 'setVehicleDetectionConfig', params: { vehicle_detection: { detection: { enabled: 'off' } } } },

    // ── Dog bark detection ───────────────────────────────────────────────────────
    'bark-on':  { method: 'setBarkDetectionConfig', params: { bark_detection: { detection: { enabled: 'on'  } } } },
    'bark-off': { method: 'setBarkDetectionConfig', params: { bark_detection: { detection: { enabled: 'off' } } } },

    // ── Cat meow detection ───────────────────────────────────────────────────────
    'meow-on':  { method: 'setMeowDetectionConfig', params: { meow_detection: { detection: { enabled: 'on'  } } } },
    'meow-off': { method: 'setMeowDetectionConfig', params: { meow_detection: { detection: { enabled: 'off' } } } },

    // ── Line crossing detection ──────────────────────────────────────────────────
    'linecross-on':  { method: 'setLinecrossingDetectionConfig', params: { linecrossing_detection: { detection: { enabled: 'on'  } } } },
    'linecross-off': { method: 'setLinecrossingDetectionConfig', params: { linecrossing_detection: { detection: { enabled: 'off' } } } },

    // ── Camera tamper detection ──────────────────────────────────────────────────
    // Note: uses 'tamper_det' key (not 'detection') — matches pytapo setTamperDetection
    'tamper-on':  { method: 'setTamperDetectionConfig', params: { tamper_detection: { tamper_det: { enabled: 'on'  } } } },
    'tamper-off': { method: 'setTamperDetectionConfig', params: { tamper_detection: { tamper_det: { enabled: 'off' } } } },

    // ── Auto-tracking (pan/tilt follows detected subject) ──────────────────────
    'tracking-on':  { method: 'setTargetTrackConfig', params: { target_track: { target_track_info: { enabled: 'on'  } } } },
    'tracking-off': { method: 'setTargetTrackConfig', params: { target_track: { target_track_info: { enabled: 'off' } } } },

    // ── Night vision / infrared mode ───────────────────────────────────────────
    'night-vision-on':   { method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'on'   } } } }, // always IR
    'night-vision-off':  { method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'off'  } } } }, // always day
    'night-vision-auto': { method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'auto' } } } }, // auto-switch

    // ── Image orientation ──────────────────────────────────────────────────────
    // flip-on mirrors vertically — useful for ceiling-mount installs.
    // pytapo: setImageFlipVertical → setLdc with flip_type 'center'/'off'
    'flip-on':  { method: 'setLdc', params: { image: { switch: { flip_type: 'center' } } } },
    'flip-off': { method: 'setLdc', params: { image: { switch: { flip_type: 'off'    } } } },

    // ── Audio recording ─────────────────────────────────────────────────────────
    'record-audio-on':  { method: 'setRecordAudio', params: { audio_config: { record_audio: { enabled: 'on'  } } } },
    'record-audio-off': { method: 'setRecordAudio', params: { audio_config: { record_audio: { enabled: 'off' } } } },

    // ── SD card loop (circular) recording ──────────────────────────────────────
    'circular-recording-on':  { method: 'setCircularRecordingConfig', params: { harddisk_manage: { harddisk: { loop: 'on'  } } } },
    'circular-recording-off': { method: 'setCircularRecordingConfig', params: { harddisk_manage: { harddisk: { loop: 'off' } } } },

    // ── System ─────────────────────────────────────────────────────────────────
    // params from pytapo: method=rebootDevice, params={system:{reboot:'null'}} (string 'null', not JSON null)
    'reboot': { method: 'rebootDevice', params: { system: { reboot: 'null' } }, _acceptNetworkErrors: true },

    // ── Status / info queries ───────────────────────────────────────────────────
    // Returns device_info.basic_info: model, hw_version, sw_version, mac, etc.
    'get-device-info': { method: 'getDeviceInfo', params: { device_info: { name: ['basic_info'] } } },
    // Returns harddisk_manage.hd_info[]: status, total_space, free_space, etc.
    'get-sd-card':     { method: 'getSdCardStatus', params: { harddisk_manage: { table: ['hd_info'] } } },
};

// ─── Poll detection events ──────────────────────────────────────────────────
// Uses the camera's searchDetectionList API (same as pytapo getEvents()).
// Returns raw detection objects; each has start_time / end_time (Unix seconds)
// and a detection type field (e.g. cls_type: 'person', 'motion', 'baby_cry', etc.).
// Note: the camera must have an SD card with local recording enabled for the
// event log to be populated; results vary by firmware.
async function getDetections(ip, username, password, minutes) {
    const now   = Math.floor(Date.now() / 1000);
    const start = now - ((minutes ?? 5) * 60);
    const apiCmd = {
        method: 'searchDetectionList',
        params: {
            playback: {
                search_detection_list: {
                    start_index: 0,
                    channel:     0,
                    start_time:  start,
                    end_time:    now + 30,  // small future buffer for clock skew
                    end_index:   99,
                },
            },
        },
        // Accept camera errors for "no results", "not supported", or "no SD card" gracefully
        _acceptErrors: [-64303, -40105, -71114],
    };
    const result = await executeOnDevice(ip, username, password, apiCmd);
    return result?.playback?.search_detection_list ?? [];
}

module.exports = { authenticate, executeOnDevice, COMMANDS, getDetections, registerOnvifCallbacks, unregisterOnvifCallbacks };
