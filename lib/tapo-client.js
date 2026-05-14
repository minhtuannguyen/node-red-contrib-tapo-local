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

function post(agent, ip, path, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req  = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent,
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(new Error('Bad JSON from camera: ' + s.slice(0, 200))); } });
        });
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
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(new Error('Bad JSON from camera: ' + s.slice(0, 200))); } });
        });
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
        // Strip meta fields (e.g. _acceptErrors) before sending to camera
        const { _acceptErrors = [], _acceptNetworkErrors = false, ...cmd } = apiCmd;
        const wrapped = { method: 'multipleRequest', params: { requests: [cmd] } };
        const cipher  = crypto.createCipheriv('aes-128-cbc', lsk, ivb);
        const encReq  = Buffer.concat([cipher.update(JSON.stringify(wrapped), 'utf8'), cipher.final()]).toString('base64');
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
        const decipher = crypto.createDecipheriv('aes-128-cbc', lsk, ivb);
        const inner    = JSON.parse(
            Buffer.concat([decipher.update(Buffer.from(r.result.response, 'base64')), decipher.final()]).toString()
        );
        if (inner.error_code !== 0) throw new Error('command error ' + inner.error_code);
        const resp0 = inner.result?.responses?.[0];
        if (resp0?.error_code !== 0 && !_acceptErrors.includes(resp0?.error_code)) {
            throw new Error('command error: ' + JSON.stringify(resp0));
        }
        return resp0?.result ?? {};
    }

    return { sendCmd };
}

// Add new commands here — no other changes needed.
const COMMANDS = {
    'privacy-on':  { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'on'  } } } },
    'privacy-off': { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'off' } } } },
    // params from pytapo: method=rebootDevice, params={system:{reboot:'null'}} (string 'null', not JSON null)
    'reboot':      { method: 'rebootDevice', params: { system: { reboot: 'null' } }, _acceptNetworkErrors: true },
};

module.exports = { authenticate, COMMANDS };
