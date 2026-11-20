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
const zlib   = require('zlib');
const { performance } = require('perf_hooks');
const monotonicNow = () => performance.now();
const protection = require('./device-state')();
const normalizeHost = value => String(value).trim().toLowerCase().replace(/\.$/, '');

// Module-level hash helpers — defined once, not re-created on every authenticate() call.
const sha256U = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex').toUpperCase();
const md5U    = s => crypto.createHash('md5').update(s, 'utf8').digest('hex').toUpperCase();
// Camera validates Tapo_tag against a spaced-JSON body (matching Python's json.dumps).
// Single-pass replace: colon → ": ", comma → ", "
const pyJson  = o => JSON.stringify(o).replace(/:|,/g, m => m === ':' ? ': ' : ', ');

// Tunable limits (exported as _limits so tests can shorten them).
const LIMITS = {
    requestMs:            12000,  // per HTTP request; hard deadline is requestMs + 3 s
    opMaxMs:              30000,  // whole operation: logins + command + retry
    queueDepth:           3,      // external commands queued or running per camera
    cmdMaxAgeMs:          30000,  // waited longer than this → stale (e.g. pressed during an outage)
    minGapMs:             1000,   // max ~1 command/s per camera, however fast it answers
    repeatWindowMs:       0,      // completed results may be stale when another controller changes the camera
    retryGapMs:           1000,   // pause before the single retry
    onvifStopMs:          5000,
    onvifPauseMs:         3000,
    onvifFailCooldownMs:  10000,  // after an unconfirmed ONVIF stop/pause, fail fast for this long
    leaseWaitMs:          15000,
    leaseHoldMs:          30000,  // safety cap on a control lease
    maxLeases:            4,
    maxQueuedJobs:        32,
    leaseGraceMs:         300,    // after a lease expires, time for its owner to tear down before the queue is freed
    leaseRecoveryMs:      30000,
    startupRebootGuardMs: 60000,
    startupQuietMs:      3000,
    ptzGapMs:            1000,
    ptzMaxAgeMs:         3000,
    httpsResumeMs:       500,   // ONVIF polling resumes this long after an HTTPS operation releases its pause
    detectionPollMs:     5000,
    detectionErrorMs:    30000,
};
// Idle keep-alive sockets are closed after this so they don't hold one of the camera's few connection slots.
const IDLE_SOCKET_MS     = 10000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_RETRY_AFTER_MS = 5 * 60 * 1000;

const errCode = (message, code) => Object.assign(new Error(message), { code });

// Errors where the request may never have reached the camera, or no reply came back.
const TRANSPORT_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'ECONNABORTED', 'ETIMEDOUT', 'EHOSTUNREACH', 'EHOSTDOWN', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE']);
// Connection never established — the request definitely was not delivered.
const NOT_SENT_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'EHOSTDOWN', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN']);
const RESET_CODES     = new Set(['ECONNRESET', 'EPIPE']);
const SSL_ERR_RE      = /ERR_SSL_WRONG_VERSION_NUMBER|ssl3_get_record|wrong version number|packet length too long|EPROTO/i;
const isSslError      = err => SSL_ERR_RE.test(err.code || '') || SSL_ERR_RE.test(err.message);

// Minimal cancellation token (AbortController needs Node 15+).
function makeAbort() {
    const s = {
        aborted: false, reason: null, fns: new Set(),
        abort(reason) {
            if (s.aborted) return;
            s.aborted = true;
            s.reason = reason;
            for (const listener of [...s.fns]) safeCall(() => listener(reason));
        },
        on(f) { if (s.aborted) { safeCall(() => f(s.reason)); return () => {}; } s.fns.add(f); return () => s.fns.delete(f); },
    };
    return s;
}

function parseRetryAfter(v) {
    if (!v) return 0;
    const secs = Number(v);
    const ms   = Number.isFinite(secs) ? secs * 1000 : Date.parse(v) - Date.now();
    return Number.isFinite(ms) ? Math.min(Math.max(ms, 0), MAX_RETRY_AFTER_MS) : 0;
}

// One keep-alive agent per session so auth + commands share the same TCP connection.
function makeAgent() {
    return new https.Agent({
        rejectUnauthorized: false,
        keepAlive:          true,
        maxSockets:         1,
        timeout:            IDLE_SOCKET_MS,
        ALPNProtocols:      ['http/1.1'],
    });
}

function post(agent, ip, path, body, abort) {
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    return postRaw(agent, ip, path, data, { 'Content-Type': 'application/json', 'Content-Length': data.length }, abort);
}

// body must be a Buffer — callers pre-compute it to avoid double encoding.
// Settles exactly once; the deadline and `abort` reject explicitly (not just destroy the
// request) so a stalled decode or a finished request can't leave the queue occupied.
function postRaw(agent, ip, path, body, headers, abort) {
    return new Promise((resolve, reject) => {
        if (abort?.aborted) return reject(abort.reason);
        let settled = false, deadline = null, off = null, req = null;
        const finish = (fn, v) => {
            if (settled) return;
            settled = true;
            clearTimeout(deadline);
            if (off) off();
            fn(v);
        };
        const ok        = v => finish(resolve, v);
        const fail      = e => { finish(reject, e); if (req) req.destroy(); };
        const timeoutEr = () => errCode('Request timed out after ' + LIMITS.requestMs + 'ms', 'ETIMEDOUT');
        req = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent, headers,
            timeout: LIMITS.requestMs,
        }, res => {
            const status = res.statusCode;
            // Overload / server errors are never valid Tapo replies, even with a JSON body.
            if (status === 429 || status >= 500) {
                return fail(Object.assign(errCode(`HTTP ${status} from camera`, 'HTTP_STATUS'),
                    { httpStatus: status, retryAfterMs: parseRetryAfter(res.headers['retry-after']) }));
            }
            const chunks = [];
            let size = 0;
            res.on('data', c => {
                size += c.length;
                if (size > MAX_RESPONSE_BYTES) return fail(errCode('Response from camera too large', 'BAD_RESPONSE'));
                chunks.push(c);
            });
            res.on('error', fail);
            // Socket closed mid-response (camera reset / agent destroyed): 'end' never fires.
            res.on('close', () => { if (!res.complete) fail(errCode('Connection closed before response completed', 'ECONNRESET')); });
            res.on('end', () => {
                const raw = Buffer.concat(chunks);
                const enc = String(res.headers['content-encoding'] || '').toLowerCase();
                const parse = buf => {
                    const text = buf.toString();
                    let json;
                    try { json = JSON.parse(text); } catch (_) { /* handled below */ }
                    // Tapo replies always carry a numeric error_code — including 4xx login probes.
                    if (json && typeof json.error_code === 'number') return ok(json);
                    if (status < 200 || status >= 300) return fail(Object.assign(errCode(`HTTP ${status} from camera`, 'HTTP_STATUS'), { httpStatus: status }));
                    fail(errCode('Malformed reply from camera: ' + text.slice(0, 200), 'BAD_RESPONSE'));
                };
                if (enc !== 'gzip' && enc !== 'deflate') return parse(raw);
                const decode = enc === 'gzip' ? zlib.gunzip : zlib.inflate;
                decode(raw, { maxOutputLength: MAX_RESPONSE_BYTES }, (e, out) =>
                    e ? fail(errCode('Cannot decode camera reply: ' + e.message, 'BAD_RESPONSE')) : parse(out));
            });
        });
        // Socket 'timeout' only catches idle gaps; this caps the total time (e.g. a trickling response).
        deadline = setTimeout(() => fail(timeoutEr()), LIMITS.requestMs + 3000);
        req.on('timeout', () => fail(timeoutEr()));
        req.on('error', fail);
        if (abort) off = abort.on(reason => fail(reason instanceof Error ? reason : errCode('Operation aborted', 'ETIMEDOUT')));
        if (abort?.trackRequest) abort.trackRequest(req);
        if (settled) return;
        req.write(body);
        req.end();
    });
}

/**
 * Authenticate and return a { sendCmd } session.
 * sendCmd(apiCmd) sends an encrypted API command and returns the decoded result.
 */
async function openSession(ip, username, password, abort) {
    const agent  = makeAgent();
    try {
        return await _authenticate(ip, username, password, agent, abort);
    } catch (err) {
        // Any failure between agent creation and return would otherwise leak the
        // HTTPS agent (with keep-alive sockets) until GC eventually collects it.
        // On an offline camera this happens on EVERY retry — a slow but real
        // memory leak.  Destroy the agent now so sockets are closed immediately.
        agent.destroy();
        throw err;
    }
}

async function _authenticate(ip, username, password, agent, abort) {

    const cnonce = crypto.randomBytes(8).toString('hex').toUpperCase();

    // Step 1: probe
    const r1 = await post(agent, ip, '/', { method: 'login', params: { cnonce, encrypt_type: '3', username } }, abort);
    // Camera returns locked status either as {result:{data:{code:-40404}}} or {data:{code:-40404},error_code:-40401}
    const r1Data = r1?.result?.data ?? r1?.data;
    if (r1Data?.code === -40404 || r1?.error_code === -40401) {
        throw Object.assign(new Error(`Account locked — wait ${r1Data?.sec_left ?? 0}s`), { code: 'LOCKED', secLeft: r1Data?.sec_left });
    }
    if (r1?.error_code !== -40413) throw errCode('Auth probe failed: ' + JSON.stringify(r1), 'BAD_RESPONSE');

    const { nonce, device_confirm: devConfirm } = r1.result?.data ?? {};
    if (!nonce || !devConfirm) throw errCode('Auth probe failed: ' + JSON.stringify(r1), 'BAD_RESPONSE');

    // Step 2: verify device_confirm — accepts both SHA256 and MD5 password hashes
    let hashedPw = null;
    for (const h of [sha256U(password), md5U(password)]) {
        if (sha256U(cnonce + h + nonce) + nonce + cnonce === devConfirm) { hashedPw = h; break; }
    }
    if (!hashedPw) throw errCode('Wrong password — device_confirm mismatch', 'BAD_PASSWORD');

    // Step 3: authenticate → stok + start_seq
    const r2 = await post(agent, ip, '/', {
        method: 'login',
        params: { cnonce, encrypt_type: '3', digest_passwd: sha256U(hashedPw + cnonce + nonce) + cnonce + nonce, username },
    }, abort);
    const r2Data = r2?.result?.data ?? r2?.data;
    if (r2Data?.code === -40404 || r2?.error_code === -40401) {
        throw Object.assign(new Error(`Account locked — wait ${r2Data?.sec_left ?? 0}s`), { code: 'LOCKED', secLeft: r2Data?.sec_left });
    }
    if (!r2?.result?.stok) throw Object.assign(new Error('Auth failed: ' + JSON.stringify(r2)), { code: 'AUTH' });

    const stok      = r2.result.stok;
    let   seq       = r2.result.start_seq ?? 1;

    // Step 4: derive AES-128-CBC keys
    const hashedKey = sha256U(cnonce + hashedPw + nonce);
    const tok16     = t => crypto.createHash('sha256').update(t + cnonce + nonce + hashedKey, 'utf8').digest().slice(0, 16);
    const lsk       = tok16('lsk');
    const ivb       = tok16('ivb');

    // Tag step1 is constant per session
    const tagStep1 = sha256U(hashedPw + cnonce);

    // Pre-built headers object — static fields set once per session, only 3 dynamic
    // fields mutated per command. Safe because commands are serialized by the queue.
    const _cmdHeaders = {
        'User-Agent':      'Tapo CameraClient Android',
        'Accept-Encoding': 'identity',
        'Accept':          'application/json',
        'Connection':      'keep-alive',
        'Host':            `${ip}:443`,
        'Referer':         `https://${ip}:443`,
        'requestByApp':    'true',
        'Content-Type':    'application/json; charset=UTF-8',
        'Content-Length':  0,
        'Seq':             '0',
        'Tapo_tag':        '',
    };

    // Step 5: send encrypted commands
    async function sendCmd(apiCmd, abort) {
        // Strip meta fields (any key starting with '_') before sending to camera
        const { _acceptErrors = [], _acceptNetworkErrors = false, _direct = false } = apiCmd;
        const cmd = {};
        for (const k of Object.keys(apiCmd)) if (k[0] !== '_') cmd[k] = apiCmd[k];
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
            _cmdHeaders['Content-Length'] = buf.length;
            _cmdHeaders['Seq']            = String(curSeq);
            _cmdHeaders['Tapo_tag']       = tag;
            r = await postRaw(agent, ip, `/stok=${stok}/ds`, buf, _cmdHeaders, abort);
        } catch (err) {
            // Reboot drops the connection before replying — delivery is likely but unconfirmed.
            if (_acceptNetworkErrors && TRANSPORT_CODES.has(err.code) && !NOT_SENT_CODES.has(err.code)) {
                return { confirmed: false, note: 'No reply (expected if the camera is rebooting): ' + err.message };
            }
            throw err;
        }

        if (r.error_code === -40401) throw errCode('securePassthrough error -40401 (session expired)', 'STOK_EXPIRED');
        if (r.error_code !== 0) throw Object.assign(errCode('securePassthrough error ' + r.error_code, 'PASSTHROUGH'), { deviceCode: r.error_code });
        if (!r.result?.response) {
            // Only direct (set/do) commands may succeed without an encrypted body.
            if (_direct) return {};
            throw errCode('Camera reply has no encrypted response', 'BAD_RESPONSE');
        }
        let inner;
        try {
            const decipher = crypto.createDecipheriv('aes-128-cbc', lsk, ivb);
            inner = JSON.parse(
                Buffer.concat([decipher.update(Buffer.from(r.result.response, 'base64')), decipher.final()]).toString()
            );
        } catch (e) {
            throw errCode('Cannot decrypt camera response: ' + e.message, 'BAD_RESPONSE');
        }
        if (typeof inner?.error_code !== 'number') throw errCode('Decrypted reply has no error_code', 'BAD_RESPONSE');
        if (_direct) {
            // Direct commands return {error_code, result} — no responses array
            if (inner.error_code !== 0 && !_acceptErrors.includes(inner.error_code)) {
                throw Object.assign(errCode('command error: ' + JSON.stringify(inner), 'CMD'), { deviceCode: inner.error_code });
            }
            return inner.result ?? {};
        }
        if (inner.error_code !== 0) throw Object.assign(errCode('command error ' + inner.error_code, 'CMD'), { deviceCode: inner.error_code });
        const resp0 = inner.result?.responses?.[0];
        if (typeof resp0?.error_code !== 'number') throw errCode('Decrypted reply has no command response', 'BAD_RESPONSE');
        if (resp0.error_code !== 0 && !_acceptErrors.includes(resp0.error_code)) {
            throw Object.assign(errCode('command error: ' + JSON.stringify(resp0), 'CMD'), { deviceCode: resp0.error_code });
        }
        return resp0.result ?? {};
    }

    return { sendCmd, agent };
}

// ─── Per-device session cache + serial command queue ──────────────────────────
// Every HTTPS command to one camera IP runs one at a time — whatever the
// username — so auth handshakes never collide (-40413 INVALID_NONCE) and this
// process never opens parallel control connections to the camera.
const SESSION_TTL_MS    = 10 * 60 * 1000; // 10 min — well within typical stok lifetime
const _sessions         = new Map();  // `${ip}|${user}` → { sendCmd, agent, expiresAt, cred }
const _queues           = new Map();  // ip → queue (see newQueue)
const _lastDone         = new Map();  // ip → time the last command finished
const _recent           = new Map();  // ip → Map(settingGroup → { sig, at, result }) of confirmed setters
const _unreleased       = new Map();
const _restored         = new Set();
const _subscriptionUntil = new Map();
const _onvifHealth       = new Map();
const _detectionSamples  = new Map();

// Circuit breakers — while blocked, commands fail fast without touching the camera.
//   transport (per camera):      network / protocol / overload failures, reboots
//   auth (per camera + user):    lockout, rejected credentials
const _transport            = new Map(); // ip → { failures, blockedUntil, reason, probeGranted }
const _auth                 = new Map(); // `${ip}|${user}` → { blockedUntil, reason, cred }
const BACKOFF_BASE_MS       = 5000;
const BACKOFF_MAX_MS        = 60000;
const AUTH_BLOCK_MS         = 60000;
const BAD_PASSWORD_BLOCK_MS = 30 * 60 * 1000;  // cleared immediately when the password changes
const LOCK_MARGIN_MS        = 10000;
const REBOOT_BLOCK_MS       = 45000;

const delay      = ms => new Promise(r => setTimeout(r, ms));
const sessionKey = (ip, user) => `${ip}|${user}`;
const credOf     = password => sha256U(String(password ?? ''));

function configureProtection(RED) {
    protection.configure(RED.settings?.userDir, message => RED.log?.warn(message));
}

function restoreTransport(ip) {
    const key = 'https:' + ip;
    if (_restored.has(key)) return;
    _restored.add(key);
    const saved = protection.get(key);
    const remaining = Math.min(MAX_RETRY_AFTER_MS, (saved?.until || 0) - Date.now());
    if (remaining > 0) _transport.set(ip, {
        failures: Math.max(0, Math.min(Number(saved.failures) || 0, 10)),
        blockedUntil: monotonicNow() + remaining,
        mandatoryUntil: monotonicNow() + Math.max(0, Math.min(remaining, (saved.mandatoryUntil || 0) - Date.now())),
        reason: typeof saved.reason === 'string' ? saved.reason : 'recovering', probeGranted: true,
    });
}

function saveTransport(ip) {
    const state = _transport.get(ip);
    protection.set('https:' + ip, state ? {
        until: Date.now() + Math.max(0, state.blockedUntil - monotonicNow()),
        mandatoryUntil: Date.now() + Math.max(0, state.mandatoryUntil - monotonicNow()),
        failures: state.failures, reason: state.reason,
    } : null);
}

function saveAuth(key) {
    const state = _auth.get(key);
    protection.set('auth:' + key, state ? {
        until: Date.now() + Math.max(0, Math.min(state.reason === 'account locked' ? 3600000 : AUTH_BLOCK_MS,
            state.blockedUntil - monotonicNow())), reason: state.reason,
    } : null);
}

function subscriptionDelayMs(ip) {
    if (!_subscriptionUntil.has(ip)) {
        const remaining = Math.max(0, Math.min(600000, (protection.get('subscription:' + ip)?.until || 0) - Date.now()));
        _subscriptionUntil.set(ip, monotonicNow() + remaining);
    }
    return Math.max(0, _subscriptionUntil.get(ip) - monotonicNow());
}

function reserveSubscription(ip, ms) {
    _subscriptionUntil.set(ip, monotonicNow() + ms);
    protection.set('subscription:' + ip, ms > 0 ? { until: Date.now() + ms } : null);
}

function dropSession(key, only) {
    const s = _sessions.get(key);
    if (s && (!only || s === only)) { s.agent.destroy(); _sessions.delete(key); }
}

function dropDeviceSessions(ip) {
    for (const key of _sessions.keys()) if (key.startsWith(ip + '|')) dropSession(key);
}

const blockedErr = (ip, reason, until) =>
    errCode(`Device ${ip} ${reason} — request not sent, retry in ${Math.ceil((until - monotonicNow()) / 1000)}s`, 'BACKOFF');

function assertAvailable(ip, authKey, cred) {
    restoreTransport(ip);
    const savedKey = 'auth:' + authKey;
    if (!_restored.has(savedKey)) {
        _restored.add(savedKey);
        const saved = protection.get(savedKey);
        const remaining = Math.min(3600000, (saved?.until || 0) - Date.now());
        if (remaining > 0) _auth.set(authKey, { blockedUntil: monotonicNow() + remaining,
            reason: saved.reason || 'login cooling down', cred: null });
    }
    if (_unreleased.get(ip)?.size) throw errCode('Previous control owner has not confirmed cleanup - request not sent', 'ONVIF_PAUSE');
    const now = monotonicNow();
    const t   = _transport.get(ip);
    if (t && now < t.blockedUntil) throw blockedErr(ip, t.reason, t.blockedUntil);
    const a   = _auth.get(authKey);
    if (!a) return;
    if (a.cred && a.cred !== cred) { _auth.delete(authKey); saveAuth(authKey); return; }  // credentials changed
    if (now < a.blockedUntil) throw blockedErr(ip, a.reason, a.blockedUntil);
}

function controlDelayMs(ip) {
    ip = normalizeHost(ip);
    restoreTransport(ip);
    return Math.max(0, (_transport.get(ip)?.mandatoryUntil || 0) - monotonicNow(),
        _loadedAt + LIMITS.startupQuietMs - monotonicNow());
}

function onvifDelayMs(ip) {
    ip = normalizeHost(ip);
    const key = 'onvif:' + ip;
    if (!_restored.has(key)) {
        _restored.add(key);
        const saved = protection.get(key);
        const remaining = Math.min(MAX_RETRY_AFTER_MS, (saved?.until || 0) - Date.now());
        if (remaining > 0) _onvifHealth.set(ip, { blockedUntil: monotonicNow() + remaining,
            failures: Math.max(0, Math.min(Number(saved.failures) || 0, 10)) });
    }
    return Math.max(0, (_onvifHealth.get(ip)?.blockedUntil || 0) - monotonicNow());
}

function noteOnvifFailure(ip, error) {
    ip = normalizeHost(ip);
    onvifDelayMs(ip);
    const failures = (_onvifHealth.get(ip)?.failures || 0) + 1;
    const authFailure = /NotAuthorized|Unauthorized|authentication|HTTP 401|HTTP 403/i.test(error.message);
    const ms = Math.max(authFailure ? AUTH_BLOCK_MS : Math.min(3000 * 2 ** Math.min(failures - 1, 10), BACKOFF_MAX_MS),
        error.retryAfterMs || 0, onvifDelayMs(ip));
    _onvifHealth.set(ip, { failures, blockedUntil: monotonicNow() + ms });
    protection.set('onvif:' + ip, { until: Date.now() + ms, failures });
    if (error.retryAfterMs > 0) blockTransport(ip, ms, 'overloaded', false, true);
}

function noteOnvifSuccess(ip) {
    ip = normalizeHost(ip);
    _onvifHealth.delete(ip);
    protection.set('onvif:' + ip, null);
}

// `mandatory` cooldowns (Retry-After, reboot) are never shortened by a later block and are
// not eligible for an early ONVIF probe.
function blockTransport(ip, ms, reason, countFailure, mandatory = false) {
    restoreTransport(ip);
    const t = _transport.get(ip) || { failures: 0, blockedUntil: 0, mandatoryUntil: 0, reason: '', probeGranted: false };
    if (countFailure) t.failures++;
    let until = monotonicNow() + ms;
    if (t.mandatoryUntil > until) { until = t.mandatoryUntil; reason = t.reason; }
    else if (mandatory) t.mandatoryUntil = until;
    t.blockedUntil = until;
    t.reason       = reason;
    _transport.set(ip, t);
    saveTransport(ip);
}

function recordFailure(ip, authKey, cred, err) {
    const now = monotonicNow();
    switch (err.code) {
        case 'BACKOFF':
        case 'EXPIRED':
        case 'ONVIF_PAUSE':
        case 'CANCELLED':
            return;
        case 'CMD':
            _transport.delete(ip);  // the camera answered properly — the endpoint is healthy
            saveTransport(ip);
            return;
        case 'LOCKED':
            _auth.set(authKey, { blockedUntil: now + Math.max((Number(err.secLeft) || 0) * 1000 + LOCK_MARGIN_MS, 60000), reason: 'account locked', cred: null });
            saveAuth(authKey);
            return;
        case 'BAD_PASSWORD':
            _auth.set(authKey, { blockedUntil: now + BAD_PASSWORD_BLOCK_MS, reason: 'wrong password (fix credentials and redeploy)', cred });
            saveAuth(authKey);
            return;
        case 'AUTH':
            _auth.set(authKey, { blockedUntil: now + AUTH_BLOCK_MS, reason: 'login rejected', cred });
            saveAuth(authKey);
            return;
        default: {
            // Transport, protocol, malformed or overload failure.
            const failures   = (_transport.get(ip)?.failures ?? 0) + 1;
            const backoff    = Math.min(BACKOFF_BASE_MS * 2 ** Math.min(failures - 1, 10), BACKOFF_MAX_MS);
            const retryAfter = err.retryAfterMs || 0;
            const overloaded = err.httpStatus === 429 || err.httpStatus === 503 || retryAfter > 0;
            blockTransport(ip, Math.max(backoff, retryAfter), overloaded ? 'overloaded' : 'unreachable', true, retryAfter > 0);
        }
    }
}

// Called by the ONVIF node when the camera answers ONVIF.  That doesn't prove the
// HTTPS endpoint works, so it only grants ONE early probe per failure streak, and
// never during a mandatory (Retry-After / reboot) cooldown.
function noteDeviceReachable(ip) {
    ip = normalizeHost(ip);
    restoreTransport(ip);
    const now = monotonicNow();
    const t   = _transport.get(ip);
    if (t && t.reason === 'unreachable' && !t.probeGranted && now < t.blockedUntil && now >= t.mandatoryUntil) {
        t.probeGranted = true;
        t.blockedUntil = now;
    }
}

async function getSession(ip, username, password, cred, abort) {
    const key    = sessionKey(ip, username);
    const cached = _sessions.get(key);
    if (cached && cached.cred === cred && monotonicNow() < cached.expiresAt) return { session: cached, reused: true };
    dropDeviceSessions(ip);
    const { sendCmd, agent } = await openSession(ip, username, password, abort);
    const session = { sendCmd, agent, cred, expiresAt: monotonicNow() + SESSION_TTL_MS };
    _sessions.set(key, session);
    return { session, reused: false };
}

async function authenticate(ip, username, password, ownerSignal) {
    ip = normalizeHost(ip);
    if (ownerSignal?.aborted) throw cancelledErr();
    const authKey = sessionKey(ip, username);
    const cred = credOf(password);
    assertAvailable(ip, authKey, cred);
    const lease = await acquireLease(ip, { requireRelease: true, signal: ownerSignal,
        holdMs: LIMITS.opMaxMs, stillWanted: () => !ownerSignal?.aborted });
    if (!lease) throw ownerSignal?.aborted ? cancelledErr() : errCode('Camera control busy - authentication not sent', 'ONVIF_PAUSE');
    const abort = makeAbort();
    abort.trackRequest = lease.trackRequest;
    const offLease = lease.signal.on(reason => abort.abort(reason));
    const offOwner = ownerSignal?.on(() => abort.abort(cancelledErr()));
    let resume = null;
    try {
        assertAvailable(ip, authKey, cred);
        resume = await interruptOnvifForPtz(ip, LIMITS.httpsResumeMs);
        const gap = (_lastDone.get(ip) ?? -LIMITS.minGapMs) + LIMITS.minGapMs - monotonicNow();
        if (gap > 0) await delay(gap);
        if (abort.aborted) throw abort.reason;
        const { session } = await getSession(ip, username, password, cred, abort);
        if (abort.aborted) { dropSession(authKey, session); throw abort.reason; }
        return { agent: session.agent,
            sendCmd: (apiCmd, signal) => executeOnDevice(ip, username, password, apiCmd, { signal }) };
    } catch (error) {
        recordFailure(ip, authKey, cred, error);
        throw error;
    } finally {
        if (resume) resume();
        offLease();
        if (offOwner) offOwner();
        _lastDone.set(ip, monotonicNow());
        lease.release();
    }
}

// One login (if needed) + one command.  Any failure other than a command-level
// rejection leaves the session unusable, so it is dropped on every attempt.
// err.afterSend is set when the command may have reached the camera.
async function attempt(ip, job, abort) {
    if (abort.aborted) throw abort.reason;
    if (monotonicNow() > job.enqueuedAt + LIMITS.cmdMaxAgeMs) throw expiredErr();
    const { session, reused } = await getSession(ip, job.username, job.password, job.cred, abort);
    try {
        if (abort.aborted) throw abort.reason;
        if (monotonicNow() > job.enqueuedAt + LIMITS.cmdMaxAgeMs) throw expiredErr();
        return await session.sendCmd(job.apiCmd, abort);
    } catch (err) {
        if (err.code !== 'CMD') dropSession(sessionKey(ip, job.username), session);
        err.reusedSession = reused;
        err.afterSend     = !NOT_SENT_CODES.has(err.code);
        throw err;
    }
}

// A lost reply does not mean the command didn't run — only getters/setters are replayed.
function shouldRetry(err, kind) {
    if (err.code === 'STOK_EXPIRED') return true;  // rejected before execution
    if (kind === 'action') return false;
    return isSslError(err) || (err.reusedSession === true && RESET_CODES.has(err.code));
}

function safeCall(fn) {
    try { Promise.resolve(fn()).catch(() => {}); } catch (_) { /* a callback must never break the queue */ }
}

function once(fn) {
    let called = false;
    return () => { if (called || typeof fn !== 'function') return; called = true; return fn(); };
}

function startRegs(regs, privacyKnownOff) {
    for (const r of regs) safeCall(() => r.start(privacyKnownOff));
}

const _onvifGen    = new Map();  // ip → counter bumped by every stop, so late cleanup can tell it is obsolete
const _onvifFail   = new Map();  // ip → time until which ONVIF coordination fails fast
const isRegistered = (ip, r) => !!_onvifRegistry.get(ip)?.has(r);
const onvifCoordinationBlocked = ip => monotonicNow() < (_onvifFail.get(ip) || 0);

// Resolves with the pollers that were running and are now confirmed stopped.
// Throws (command not sent) if any poller fails to confirm within the deadline.
async function stopOnvif(ip) {
    const regs = [...(_onvifRegistry.get(ip) || [])];
    if (!regs.length) return [];
    if (onvifCoordinationBlocked(ip)) throw errCode('ONVIF coordination failed recently — command not sent', 'ONVIF_PAUSE');
    const gen = (_onvifGen.get(ip) || 0) + 1;
    _onvifGen.set(ip, gen);
    const stops = regs.map(r => Promise.resolve().then(() => r.stop()));
    let timer;
    const settled = await Promise.race([
        Promise.allSettled(stops),
        new Promise(r => { timer = setTimeout(() => r(null), LIMITS.onvifStopMs); }),
    ]);
    clearTimeout(timer);
    if (settled && settled.every(s => s.status === 'fulfilled')) {
        return regs.filter((_, i) => settled[i].value);
    }
    _onvifFail.set(ip, monotonicNow() + LIMITS.onvifFailCooldownMs);
    // The command won't be sent: undo stops that complete later, unless a newer stop or an unregister made that obsolete.
    stops.forEach((p, i) => p.then(wasRunning => {
        if (wasRunning && _onvifGen.get(ip) === gen && isRegistered(ip, regs[i])) startRegs([regs[i]], false);
    }, () => {}));
    throw errCode('ONVIF poller did not confirm stop — command not sent', 'ONVIF_PAUSE');
}

async function runOp(ip, job) {
    const { username, cred, apiCmd, kind } = job;
    const authKey = sessionKey(ip, username);
    // An earlier op in this queue may have just found the camera down.
    assertAvailable(ip, authKey, cred);

    // privacy-on:  stop ONVIF first so the C225 connection slot is free.
    // privacy-off: start ONVIF after the command succeeds.
    const lensState = apiCmd.method === 'setLensMaskConfig'
        ? apiCmd.params?.lens_mask?.lens_mask_info?.enabled : undefined;
    let paused = [];
    let resume = null;

    // Whole-operation deadline: aborting also destroys the in-flight request.
    const abort = job.abort = makeAbort();
    const timer = setTimeout(() => abort.abort(errCode(`Operation exceeded ${LIMITS.opMaxMs}ms`, 'ETIMEDOUT')), LIMITS.opMaxMs);

    let result, retryFailure = null;
    try {
        if (lensState === 'on' || apiCmd.method === 'rebootDevice') {
            paused = await stopOnvif(ip);
            // The cached TLS socket may have been dropped while ONVIF held the slot.
            dropDeviceSessions(ip);
        } else {
            // Pollers hold a long-lived connection; keep it away from the camera while HTTPS is in use.
            resume = await interruptOnvifForPtz(ip, LIMITS.httpsResumeMs);
        }
        try {
            result = await attempt(ip, job, abort);
        } catch (err) {
            // Single retry budget for the whole operation (max 2 logins, 2 sends).
            if (!shouldRetry(err, kind)) throw err;
            retryFailure = err;
            await delay(LIMITS.retryGapMs);
            if (abort.aborted) throw abort.reason;
            result = await attempt(ip, job, abort);
        }
    } catch (err) {
        recordFailure(ip, authKey, cred, err.code === 'EXPIRED' && retryFailure ? retryFailure : err);
        // A reboot that may have been delivered must be treated as a reboot in progress.
        if (apiCmd.method === 'rebootDevice' && err.afterSend) {
            dropDeviceSessions(ip);
            blockTransport(ip, REBOOT_BLOCK_MS, 'rebooting (outcome unconfirmed)', false, true);
        }
        // privacy-on didn't happen — resume ONVIF (its own privacy guard re-checks state).
        startRegs(paused.filter(r => isRegistered(ip, r)), false);
        throw err;
    } finally {
        clearTimeout(timer);
        if (resume) resume();
    }
    _transport.delete(ip);
    _auth.delete(authKey);
    saveTransport(ip);
    saveAuth(authKey);

    if (result?.confirmed === false && apiCmd.method !== 'rebootDevice') {
        dropDeviceSessions(ip);
        blockTransport(ip, BACKOFF_BASE_MS, 'unreachable (outcome unconfirmed)', true);
    }

    if (apiCmd.method === 'rebootDevice') {
        // Old stok dies with the reboot; don't contact the camera while it boots.
        dropDeviceSessions(ip);
        blockTransport(ip, REBOOT_BLOCK_MS, 'rebooting', false, true);
        startRegs(paused.filter(r => isRegistered(ip, r)), false);
    }
    if (lensState === 'off') startRegs([...(_onvifRegistry.get(ip) || [])], true);
    return result;
}

// ── ONVIF coordination registry ────────────────────────────────────────────────
// Every tapo-onvif-events node watching an IP registers here; all of them are
// coordinated (privacy on/off, PTZ interrupt), not just the latest.
const _onvifRegistry = new Map(); // ip → Set<{ stop, start, interrupt }>

function registerOnvifCallbacks(ip, callbacks) {
    ip = normalizeHost(ip);
    if (!_onvifRegistry.has(ip)) _onvifRegistry.set(ip, new Set());
    _onvifRegistry.get(ip).add(callbacks);
}
function unregisterOnvifCallbacks(ip, callbacks) {
    ip = normalizeHost(ip);
    const regs = _onvifRegistry.get(ip);
    if (!regs) return;
    regs.delete(callbacks);
    if (!regs.size) _onvifRegistry.delete(ip);
}

// Complete-state setters declare _coalesce:true; other setters stay separate and invalidate cached state.
// 'getter': read-only → identical requests are shared; retry-safe.
// 'action': anything else (do, reboot, unknown methods) → never merged, skipped or replayed.
// Commands may declare `_kind` explicitly; otherwise unknown methods default to 'action'.
const settingPaths = obj => Object.keys(obj || {})
    .filter(k => k[0] !== '_' && k !== 'method').sort()
    .map(k => k + '.' + Object.keys(obj[k] || {}).sort().join('+')).join(',');

function classify(apiCmd) {
    const m    = apiCmd.method;
    const kind = apiCmd._kind || (/^(get|search)/.test(m) ? 'getter' : KNOWN_SETTERS.has(m) ? 'setter' : 'action');
    if (kind !== 'setter' || apiCmd._coalesce !== true) return { kind, group: null };
    return { kind, group: `${m}:${settingPaths(m === 'set' ? apiCmd : apiCmd.params)}` };
}

function deferred() {
    let resolve, reject;
    const promise = new Promise((a, b) => { resolve = a; reject = b; });
    return { promise, resolve, reject };
}

// Node-RED (re)start forgets all cooldowns; refuse reboots briefly to break restart/reboot loops.
const _loadedAt = monotonicNow();

// Queue entry lifecycle: waiting (replaceable, `entries` + `waiting`) → running → done.
// `live` counts external entries not yet done; capacity is checked against it, and it is
// decremented BEFORE the caller's promise settles so a caller that immediately submits the
// next command never sees a stale full queue.
function newQueue(ip) {
    const q = {
        tail: Promise.resolve(), jobs: 0, live: 0, internal: 0,
        waiting: new Map(), entries: new Set(), running: null,
        writeSeq: 0,    // bumped by every non-getter submission and lease; getters only share results from before it
        barrierSeq: 0,  // bumped by actions and leases; setters are only replaced within the same segment
    };
    _queues.set(ip, q);
    return q;
}

// Appends work to the camera's serial queue.
function enqueue(ip, q, work) {
    q.jobs++;
    const run = q.tail.then(work).catch(() => {});
    q.tail = run;
    run.then(() => {
        if (--q.jobs === 0 && _queues.get(ip) === q) _queues.delete(ip);
    });
    return run;
}

function finishEntry(q, entry, settle) {
    if (q.running === entry) q.running = null;
    if (!entry.done) {
        entry.done = true;
        q.live--;
        q.entries.delete(entry);
        if (q.waiting.get(entry.group) === entry) q.waiting.delete(entry.group);
    }
    settle();
}

const expiredErr = () => errCode(`Command older than ${LIMITS.cmdMaxAgeMs / 1000}s — dropped as stale`, 'EXPIRED');
const cancelledErr = () => errCode('Command owner stopped - request cancelled', 'CANCELLED');

function watchEntry(q, entry, signal) {
    const owner = entry.owner;
    owner.interests = (owner.interests || 0) + 1;
    return new Promise((resolve, reject) => {
        let off = null, settled = false;
        const finish = (fn, value) => {
            if (settled) return;
            settled = true;
            if (off) off();
            owner.interests--;
            fn(value);
        };
        owner.promise.then(value => finish(resolve, value), err => finish(reject, err));
        if (signal) off = signal.on(() => {
            finish(reject, cancelledErr());
            if (entry.owner !== owner || owner.interests || entry.done) return;
            if (q.running === entry) entry.abort?.abort(cancelledErr());
            else finishEntry(q, entry, () => owner.reject(cancelledErr()));
        });
    });
}

// Retire waiting entries that went stale so they stop consuming capacity.
function purgeExpired(q) {
    const now = monotonicNow();
    for (const e of [...q.entries]) {
        if (now - e.enqueuedAt > LIMITS.cmdMaxAgeMs) finishEntry(q, e, () => e.owner.reject(expiredErr()));
    }
}

async function executeOnDevice(ip, username, password, apiCmdIn, { signal } = {}) {
    ip = normalizeHost(ip);
    if (signal?.aborted) throw cancelledErr();
    // Snapshot: later mutation by the caller must not change what is classified or sent.
    const apiCmd  = JSON.parse(JSON.stringify(apiCmdIn));
    const authKey = sessionKey(ip, username);
    const cred    = credOf(password);
    if (apiCmd.method === 'rebootDevice' && monotonicNow() - _loadedAt < LIMITS.startupRebootGuardMs) {
        throw errCode(`Reboot refused within ${LIMITS.startupRebootGuardMs / 1000}s of Node-RED start`, 'STARTUP_GUARD');
    }
    assertAvailable(ip, authKey, cred);

    const { kind, group: settingGroup } = classify(apiCmd);
    const cmdSig = JSON.stringify(apiCmd);
    const sig    = `${authKey}|${cred}|${cmdSig}`;
    // Setters share one group per physical setting (any user); getters only share an identical request.
    const group  = kind === 'setter' ? settingGroup : kind === 'getter' ? sig : null;
    let   q      = _queues.get(ip);
    if (q) purgeExpired(q);

    if (q && group) {
        const waiting = q.waiting.get(group);
        if (kind === 'getter') {
            // Sharing is only valid if no write was submitted after that read.
            if (waiting && waiting.writeSeq === q.writeSeq) return watchEntry(q, waiting, signal);
            if (!waiting && q.running?.group === group && !q.running.abort?.aborted && q.running.writeSeq === q.writeSeq) return watchEntry(q, q.running, signal);
        } else if (waiting) {
            // Only replace within the same segment: an action or lease in between may depend on the earlier state.
            if (waiting.barrierSeq === q.barrierSeq) {
                if (waiting.sig === sig) return watchEntry(q, waiting, signal);
                // Newer desired state takes over the waiting slot — no extra capacity needed.
                waiting.owner.resolve({ superseded: true });
                Object.assign(waiting, { sig, cmdSig, apiCmd, username, password, cred, authKey, enqueuedAt: monotonicNow(), owner: deferred() });
                waiting.writeSeq = ++q.writeSeq;
                return watchEntry(q, waiting, signal);
            }
        } else if (q.running?.group === group) {
            if (!q.running.abort?.aborted && q.running.sig === sig && q.running.barrierSeq === q.barrierSeq) return watchEntry(q, q.running, signal);
        } else {
            const recent = _recent.get(ip)?.get(group);
            if (recent && recent.sig === sig && monotonicNow() - recent.at < LIMITS.repeatWindowMs) return recent.result;
        }
    }

    // Reject immediately if too many commands are already queued.
    if (q && q.live >= LIMITS.queueDepth) {
        throw errCode(`Device ${ip} queue full (${q.live} pending) — camera may be offline`, 'QUEUE_FULL');
    }
    if (q && q.jobs >= LIMITS.maxQueuedJobs) throw errCode('Device queue draining cancelled work - request not sent', 'QUEUE_FULL');
    q = q || newQueue(ip);

    if (kind !== 'getter') q.writeSeq++;
    if (kind === 'action' || (kind === 'setter' && !group)) {
        q.barrierSeq++;
        _recent.delete(ip);
    }
    const entry = {
        kind, group, sig, cmdSig, apiCmd, username, password, cred, authKey,
        enqueuedAt: monotonicNow(), owner: deferred(), done: false, writeSeq: q.writeSeq, barrierSeq: q.barrierSeq,
    };
    q.live++;
    q.entries.add(entry);
    if (group) q.waiting.set(group, entry);
    enqueue(ip, q, () => dispatch(ip, q, entry));
    return watchEntry(q, entry, signal);
}

async function dispatch(ip, q, entry) {
    // The rate-limit wait happens while the entry is still replaceable or expirable.
    for (;;) {
        if (entry.done) return;
        const now = monotonicNow();
        const remaining = entry.enqueuedAt + LIMITS.cmdMaxAgeMs - now;
        if (remaining < 0) return finishEntry(q, entry, () => entry.owner.reject(expiredErr()));
        const gap = (_lastDone.get(ip) ?? (_loadedAt + LIMITS.startupQuietMs - LIMITS.minGapMs)) + LIMITS.minGapMs - now;
        if (gap <= 0) break;
        await delay(Math.min(gap, remaining + 1));
    }
    if (monotonicNow() - entry.enqueuedAt > LIMITS.cmdMaxAgeMs) {
        return finishEntry(q, entry, () => entry.owner.reject(expiredErr()));
    }

    // From here the command is committed: no more replacement.
    q.entries.delete(entry);
    if (q.waiting.get(entry.group) === entry) q.waiting.delete(entry.group);
    q.running = entry;

    if (entry.kind === 'setter' && entry.group) {
        const recent = _recent.get(ip)?.get(entry.group);
        if (recent && recent.sig === entry.sig && monotonicNow() - recent.at < LIMITS.repeatWindowMs) {
            return finishEntry(q, entry, () => entry.owner.resolve(recent.result));
        }
        // The camera's state is unknown from dispatch until a confirmed reply.
        _recent.get(ip)?.delete(entry.group);
    }
    if (entry.apiCmd.method === 'rebootDevice') _recent.delete(ip);

    let outcome;
    try {
        outcome = { ok: true, value: await runOp(ip, entry) };
    } catch (err) {
        outcome = { ok: false, err };
    }
    if (outcome.ok && outcome.value?.confirmed !== false && entry.kind === 'setter' && entry.group && entry.barrierSeq === q.barrierSeq) {
        if (!_recent.has(ip)) _recent.set(ip, new Map());
        _recent.get(ip).set(entry.group, { sig: entry.sig, at: monotonicNow(), result: outcome.value });
    }
    _lastDone.set(ip, monotonicNow());
    finishEntry(q, entry, () => outcome.ok ? entry.owner.resolve(outcome.value) : entry.owner.reject(outcome.err));
}

// Short exclusive hold on the camera's HTTPS queue for a connection hand-off (ONVIF connect,
// PTZ command).  Resolves { release, signal, trackRequest } or null within waitMs.
// When holdMs runs out, `signal` fires so the owner can abort its network work; the queue is
// only freed leaseGraceMs later. Network owners must trackRequest(req) before writing.
// Unacknowledged expiry recovers after leaseRecoveryMs only once tracked requests close.
// With dropSessions the cached HTTPS sessions are closed first.
function acquireLease(ip, { dropSessions = false, waitMs = LIMITS.leaseWaitMs, holdMs = LIMITS.leaseHoldMs, stillWanted, emergency = false, requireRelease = false, signal: ownerSignal, onvif = false } = {}) {
    ip = normalizeHost(ip);
    if (ownerSignal?.aborted) return Promise.resolve(null);
    if (_unreleased.get(ip)?.size) return Promise.resolve(null);
    if (!emergency && controlDelayMs(ip) > 0) return Promise.resolve(null);
    if (onvif && !emergency && onvifDelayMs(ip) > 0) return Promise.resolve(null);
    let q = _queues.get(ip);
    if (q && (q.internal >= LIMITS.maxLeases || q.jobs >= LIMITS.maxQueuedJobs)) return Promise.resolve(null);
    q = q || newQueue(ip);
    q.internal++;
    // The owner may change camera state and may separate setters on either side of it.
    q.writeSeq++;
    q.barrierSeq++;
    _recent.delete(ip);
    return new Promise(resolve => {
        let abandoned = false, off = null;
        const retire = once(() => { q.internal--; });
        const cancel = () => {
            abandoned = true;
            clearTimeout(timer);
            if (off) off();
            retire();
            resolve(null);
        };
        const timer = setTimeout(cancel, waitMs);
        if (ownerSignal) off = ownerSignal.on(cancel);
        enqueue(ip, q, async () => {
            try {
                if (abandoned) return;  // nobody is waiting any more — don't hold or close anything
                clearTimeout(timer);
                if (off) off();
                if (stillWanted && !stillWanted()) { resolve(null); return; }
                if (_unreleased.get(ip)?.size) { resolve(null); return; }
                if (!emergency && controlDelayMs(ip) > 0) { resolve(null); return; }
                if (onvif && !emergency && onvifDelayMs(ip) > 0) { resolve(null); return; }
                if (dropSessions) dropDeviceSessions(ip);
                const freed  = deferred();
                const signal = makeAbort();
                const pending = _unreleased.get(ip) || new Set();
                const requests = new Map();
                let recovery = null, recoveryDue = false, released = false;
                const release = once(() => {
                    released = true;
                    clearTimeout(hold);
                    clearTimeout(recovery);
                    for (const detach of requests.values()) detach();
                    requests.clear();
                    pending.delete(signal);
                    if (!pending.size) _unreleased.delete(ip);
                    freed.resolve();
                });
                const trackRequest = req => {
                    if (released || signal.aborted) { req.destroy(signal.reason || cancelledErr()); return; }
                    if (req.closed || requests.has(req)) return;
                    const onClose = () => {
                        requests.delete(req);
                        if (recoveryDue && !requests.size) release();
                    };
                    requests.set(req, () => req.removeListener('close', onClose));
                    req.once('close', onClose);
                };
                const hold   = setTimeout(() => {
                    if (requireRelease) {
                        pending.add(signal);
                        _unreleased.set(ip, pending);
                        recovery = setTimeout(() => {
                            recoveryDue = true;
                            if (!requests.size) release();
                        }, LIMITS.leaseRecoveryMs);
                    }
                    setTimeout(freed.resolve, LIMITS.leaseGraceMs);
                    signal.abort(errCode('Control lease expired', 'ETIMEDOUT'));
                    for (const req of requests.keys()) req.destroy(signal.reason);
                }, holdMs);
                resolve({ signal, release, trackRequest });
                await freed.promise;
            } catch (_) {
                resolve(null);
            } finally {
                retire();
            }
        });
    });
}

// Add new commands here — no other changes needed.
// _direct:false (default) → wrapped in multipleRequest (pytapo's executeFunction path)
// _direct:true            → sent as-is (pytapo's performRequest path, used for method:'set'/'do')
const COMMANDS = {
    // ── Privacy (lens mask) ────────────────────────────────────────────────────
    'get-lens-mask': { method: 'getLensMaskConfig', params: { lens_mask: { name: ['lens_mask_info'] } } },
    'privacy-on':    { _coalesce: true, method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'on'  } } } },
    'privacy-off':   { _coalesce: true, method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'off' } } } },

    // ── Alarm — configure auto-trigger on detected events ─────────────────────
    'alarm-on':      { _coalesce: true, _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'on',  light_type: '0', alarm_mode: ['sound', 'light'] } } },
    'alarm-off':     { _coalesce: true, _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'off', light_type: '0', alarm_mode: ['sound', 'light'] } } },
    // Immediately start/stop the alarm siren+light regardless of detection events
    'alarm-trigger': { _direct: true, method: 'do',  msg_alarm: { manual_msg_alarm: { action: 'start' } } },
    'alarm-stop':    { _direct: true, method: 'do',  msg_alarm: { manual_msg_alarm: { action: 'stop'  } } },

    // ── LED status light ───────────────────────────────────────────────────────
    'led-on':  { _coalesce: true, method: 'setLedStatus', params: { led: { config: { enabled: 'on'  } } } },
    'led-off': { _coalesce: true, method: 'setLedStatus', params: { led: { config: { enabled: 'off' } } } },

    // ── Motion detection ───────────────────────────────────────────────────────
    'motion-on':  { _coalesce: true, method: 'setDetectionConfig', params: { motion_detection: { motion_det: { enabled: 'on'  } } } },
    'motion-off': { _coalesce: true, method: 'setDetectionConfig', params: { motion_detection: { motion_det: { enabled: 'off' } } } },

    // ── Person (AI) detection ──────────────────────────────────────────────────
    'person-on':  { _coalesce: true, method: 'setPersonDetectionConfig', params: { people_detection: { detection: { enabled: 'on'  } } } },
    'person-off': { _coalesce: true, method: 'setPersonDetectionConfig', params: { people_detection: { detection: { enabled: 'off' } } } },

    // ── Baby cry detection (sound) ─────────────────────────────────────────────
    'baby-cry-on':  { _coalesce: true, method: 'setBCDConfig', params: { sound_detection: { bcd: { enabled: 'on'  } } } },
    'baby-cry-off': { _coalesce: true, method: 'setBCDConfig', params: { sound_detection: { bcd: { enabled: 'off' } } } },

    // ── Glass break detection ──────────────────────────────────────────────────
    'glass-break-on':  { _coalesce: true, method: 'setGlassDetectionConfig', params: { glass_detection: { detection: { enabled: 'on'  } } } },
    'glass-break-off': { _coalesce: true, method: 'setGlassDetectionConfig', params: { glass_detection: { detection: { enabled: 'off' } } } },
    // ── Pet detection ────────────────────────────────────────────────────────────
    'pet-on':  { _coalesce: true, method: 'setPetDetectionConfig', params: { pet_detection: { detection: { enabled: 'on'  } } } },
    'pet-off': { _coalesce: true, method: 'setPetDetectionConfig', params: { pet_detection: { detection: { enabled: 'off' } } } },

    // ── Vehicle detection ────────────────────────────────────────────────────────
    'vehicle-on':  { _coalesce: true, method: 'setVehicleDetectionConfig', params: { vehicle_detection: { detection: { enabled: 'on'  } } } },
    'vehicle-off': { _coalesce: true, method: 'setVehicleDetectionConfig', params: { vehicle_detection: { detection: { enabled: 'off' } } } },

    // ── Dog bark detection ───────────────────────────────────────────────────────
    'bark-on':  { _coalesce: true, method: 'setBarkDetectionConfig', params: { bark_detection: { detection: { enabled: 'on'  } } } },
    'bark-off': { _coalesce: true, method: 'setBarkDetectionConfig', params: { bark_detection: { detection: { enabled: 'off' } } } },

    // ── Cat meow detection ───────────────────────────────────────────────────────
    'meow-on':  { _coalesce: true, method: 'setMeowDetectionConfig', params: { meow_detection: { detection: { enabled: 'on'  } } } },
    'meow-off': { _coalesce: true, method: 'setMeowDetectionConfig', params: { meow_detection: { detection: { enabled: 'off' } } } },

    // ── Line crossing detection ──────────────────────────────────────────────────
    'linecross-on':  { _coalesce: true, method: 'setLinecrossingDetectionConfig', params: { linecrossing_detection: { detection: { enabled: 'on'  } } } },
    'linecross-off': { _coalesce: true, method: 'setLinecrossingDetectionConfig', params: { linecrossing_detection: { detection: { enabled: 'off' } } } },

    // ── Camera tamper detection ──────────────────────────────────────────────────
    // Note: uses 'tamper_det' key (not 'detection') — matches pytapo setTamperDetection
    'tamper-on':  { _coalesce: true, method: 'setTamperDetectionConfig', params: { tamper_detection: { tamper_det: { enabled: 'on'  } } } },
    'tamper-off': { _coalesce: true, method: 'setTamperDetectionConfig', params: { tamper_detection: { tamper_det: { enabled: 'off' } } } },

    // ── Auto-tracking (pan/tilt follows detected subject) ──────────────────────
    'tracking-on':  { _coalesce: true, method: 'setTargetTrackConfig', params: { target_track: { target_track_info: { enabled: 'on'  } } } },
    'tracking-off': { _coalesce: true, method: 'setTargetTrackConfig', params: { target_track: { target_track_info: { enabled: 'off' } } } },

    // ── Night vision / infrared mode ───────────────────────────────────────────
    'night-vision-on':   { _coalesce: true, method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'on'   } } } }, // always IR
    'night-vision-off':  { _coalesce: true, method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'off'  } } } }, // always day
    'night-vision-auto': { _coalesce: true, method: 'setLightFrequencyInfo', params: { image: { common: { inf_type: 'auto' } } } }, // auto-switch

    // ── Image orientation ──────────────────────────────────────────────────────
    // flip-on mirrors vertically — useful for ceiling-mount installs.
    // pytapo: setImageFlipVertical → setLdc with flip_type 'center'/'off'
    'flip-on':  { _coalesce: true, method: 'setLdc', params: { image: { switch: { flip_type: 'center' } } } },
    'flip-off': { _coalesce: true, method: 'setLdc', params: { image: { switch: { flip_type: 'off'    } } } },

    // ── Audio recording ─────────────────────────────────────────────────────────
    'record-audio-on':  { _coalesce: true, method: 'setRecordAudio', params: { audio_config: { record_audio: { enabled: 'on'  } } } },
    'record-audio-off': { _coalesce: true, method: 'setRecordAudio', params: { audio_config: { record_audio: { enabled: 'off' } } } },

    // ── SD card loop (circular) recording ──────────────────────────────────────
    'circular-recording-on':  { _coalesce: true, method: 'setCircularRecordingConfig', params: { harddisk_manage: { harddisk: { loop: 'on'  } } } },
    'circular-recording-off': { _coalesce: true, method: 'setCircularRecordingConfig', params: { harddisk_manage: { harddisk: { loop: 'off' } } } },

    // ── System ─────────────────────────────────────────────────────────────────
    // params from pytapo: method=rebootDevice, params={system:{reboot:'null'}} (string 'null', not JSON null)
    'reboot': { method: 'rebootDevice', params: { system: { reboot: 'null' } }, _acceptNetworkErrors: true },

    // ── Status / info queries ───────────────────────────────────────────────────
    // Returns device_info.basic_info: model, hw_version, sw_version, mac, etc.
    'get-device-info': { method: 'getDeviceInfo', params: { device_info: { name: ['basic_info'] } } },
    // Returns harddisk_manage.hd_info[]: status, total_space, free_space, etc.
    'get-sd-card':     { method: 'getSdCardStatus', params: { harddisk_manage: { table: ['hd_info'] } } },
};

// Only catalogue methods named set* are settings; a new non-set method must declare `_kind` or it is an action.
const KNOWN_SETTERS = new Set(Object.values(COMMANDS).map(c => c.method).filter(m => /^set/.test(m)));

// ─── Poll detection events ──────────────────────────────────────────────────
// Uses the camera's searchDetectionList API (same as pytapo getEvents()).
// Returns raw detection objects; each has start_time / end_time (Unix seconds)
// and a detection type field (e.g. cls_type: 'person', 'motion', 'baby_cry', etc.).
// Note: the camera must have an SD card with local recording enabled for the
// event log to be populated; results vary by firmware.
// Static parts of the detection search command — hoisted to avoid per-call object allocation.
const _DETECT_ACCEPT_ERRORS = Object.freeze([-64303, -40105, -71114]);

async function getDetections(ip, username, password, minutes, options) {
    ip = normalizeHost(ip);
    if (options?.signal?.aborted) throw cancelledErr();
    minutes = Number.isFinite(minutes) && minutes > 0 ? Math.min(minutes, 1440) : 5;
    const key = `${sessionKey(ip, username)}|${credOf(password)}|${minutes}`;
    const cached = _detectionSamples.get(key);
    if (cached && monotonicNow() < cached.until) return JSON.parse(JSON.stringify(cached.events));
    const sample = cached && !cached.done ? cached : { done: false };
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
    };
    sample.apiCmd = sample.apiCmd || apiCmd;
    sample.waiters = (sample.waiters || 0) + 1;
    _detectionSamples.delete(key);
    _detectionSamples.set(key, sample);
    while (_detectionSamples.size > 64) _detectionSamples.delete(_detectionSamples.keys().next().value);
    try {
        const result = await executeOnDevice(ip, username, password, sample.apiCmd, options);
        sample.events = result?.playback?.search_detection_list ?? [];
        sample.until = monotonicNow() + LIMITS.detectionPollMs;
    } catch (error) {
        if (!_DETECT_ACCEPT_ERRORS.includes(error.deviceCode)) {
            if (_detectionSamples.get(key) === sample && sample.waiters === 1) _detectionSamples.delete(key);
            throw error;
        }
        sample.events = [];
        sample.until = monotonicNow() + LIMITS.detectionErrorMs;
    } finally {
        sample.waiters--;
    }
    sample.done = true;
    return JSON.parse(JSON.stringify(sample.events));
}

// Called by tapo-ptz before sending a PTZ SOAP command: pauses every ONVIF poller
// for this camera (aborting its in-flight PullMessages).
// Returns release(), idempotent, which releases every acquired pause.
// Throws (PTZ must not be sent) if any poller fails to confirm its pause in time.
async function interruptOnvifForPtz(ip, graceMs) {
    ip = normalizeHost(ip);
    const regs = [...(_onvifRegistry.get(ip) || [])].filter(r => r.interrupt);
    if (!regs.length) return once(() => {});
    if (onvifCoordinationBlocked(ip)) throw errCode('ONVIF coordination failed recently — request not sent', 'ONVIF_PAUSE');
    const releases = [];
    let   gaveUp   = false;
    const releaseAll = () => { for (const f of releases.splice(0)) safeCall(f); };
    const pauses = regs.map(r => Promise.resolve().then(() => r.interrupt(graceMs)).then(release => {
        const f = once(release);
        if (gaveUp) safeCall(f); else releases.push(f);
    }));
    let timer;
    const ok = await Promise.race([
        Promise.allSettled(pauses).then(rs => rs.every(s => s.status === 'fulfilled')),
        new Promise(r => { timer = setTimeout(() => r(false), LIMITS.onvifPauseMs); }),
    ]);
    clearTimeout(timer);
    if (!ok) {
        gaveUp = true;
        releaseAll();
        _onvifFail.set(ip, monotonicNow() + LIMITS.onvifFailCooldownMs);
        throw errCode('ONVIF poller did not confirm pause — request not sent', 'ONVIF_PAUSE');
    }
    return once(releaseAll);
}

module.exports = {
    authenticate, executeOnDevice, COMMANDS, getDetections,
    registerOnvifCallbacks, unregisterOnvifCallbacks, interruptOnvifForPtz,
    acquireLease, noteDeviceReachable, controlDelayMs,
    configureProtection, subscriptionDelayMs, reserveSubscription,
    onvifDelayMs, noteOnvifFailure, noteOnvifSuccess, parseRetryAfter,
    normalizeHost,
    makeAbort,
    _limits: LIMITS,  // test hook
};
