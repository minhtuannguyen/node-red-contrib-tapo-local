#!/usr/bin/env node
/**
 * Tapo C225 local control — zero npm deps
 * Usage: node tapo_privacy.js <ip> <username> <password> <command>
 *   username: admin
 *   password: camera account password (Tapo app → Settings → Advanced → Camera Account)
 */
'use strict';

const https  = require('https');
const crypto = require('crypto');

const COMMANDS = {
    'privacy-on':  { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'on'  } } } },
    'privacy-off': { method: 'setLensMaskConfig', params: { lens_mask: { lens_mask_info: { enabled: 'off' } } } },
    // _direct: pytapo sends alarm via method:'set' directly (not wrapped in multipleRequest)
    'alarm-on':   { _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'on',  light_type: '0', alarm_mode: ['sound', 'light'] } } },
    'alarm-off':  { _direct: true, method: 'set', msg_alarm: { chn1_msg_alarm_info: { alarm_type: '0', enabled: 'off', light_type: '0', alarm_mode: ['sound', 'light'] } } },
    // params from pytapo: method=rebootDevice, params={system:{reboot:'null'}} (string 'null', not JSON null)
    'reboot':      { method: 'rebootDevice', params: { system: { reboot: 'null' } }, _acceptNetworkErrors: true },
};

const [,, ip, username, password, command] = process.argv;

if (!ip || !username || !password || !COMMANDS[command]) {
    console.error(`Usage: node tapo_privacy.js <ip> <username> <password> <command>`);
    console.error(`Commands: ${Object.keys(COMMANDS).join(', ')}`);
    process.exit(1);
}

const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true, maxSockets: 1, ALPNProtocols: ['http/1.1'] });

function post(path, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req  = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent,
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(e); } });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

function postRaw(path, bodyStr, headers) {
    return new Promise((resolve, reject) => {
        const buf = Buffer.from(bodyStr, 'utf8');
        const req = https.request({
            hostname: ip, port: 443, path, method: 'POST', agent, headers,
        }, res => {
            let s = '';
            res.on('data', c => s += c);
            res.on('end', () => { try { resolve(JSON.parse(s)); } catch(e) { reject(e); } });
        });
        req.on('error', reject);
        req.write(buf);
        req.end();
    });
}

async function main() {
    const sha256U = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex').toUpperCase();
    const md5U    = s => crypto.createHash('md5').update(s, 'utf8').digest('hex').toUpperCase();
    const cnonce  = crypto.randomBytes(8).toString('hex').toUpperCase();

    // ── 1. Probe: receive nonce + device_confirm ───────────────────────────────
    const r1 = await post('/', { method: 'login', params: { cnonce, encrypt_type: '3', username } });
    if (r1?.result?.data?.code === -40404) {
        console.error(`Account locked — wait ${r1.result.data.sec_left ?? 0}s before retrying`);
        process.exit(1);
    }
    if (r1?.error_code !== -40413) throw new Error('Unexpected probe response: ' + JSON.stringify(r1));

    const { nonce, device_confirm: devConfirm } = r1.result.data;

    // ── 2. Verify device_confirm (accepts SHA256 or MD5 password hash) ─────────
    let hashedPw = null;
    for (const h of [sha256U(password), md5U(password)]) {
        if (sha256U(cnonce + h + nonce) + nonce + cnonce === devConfirm) { hashedPw = h; break; }
    }
    if (!hashedPw) { console.error('Wrong password — device_confirm mismatch'); process.exit(1); }

    // ── 3. Send digest_passwd → receive stok + start_seq ──────────────────────
    const r2 = await post('/', {
        method: 'login',
        params: { cnonce, encrypt_type: '3', digest_passwd: sha256U(hashedPw + cnonce + nonce) + cnonce + nonce, username },
    });
    if (r2?.result?.data?.code === -40404) {
        console.error(`Account locked — wait ${r2.result.data.sec_left ?? 0}s before retrying`);
        process.exit(1);
    }
    if (!r2?.result?.stok) throw new Error('Auth failed: ' + JSON.stringify(r2));

    const stok = r2.result.stok;
    const seq  = r2.result.start_seq ?? 1;

    // ── 4. Derive AES-128-CBC keys ─────────────────────────────────────────────
    const hashedKey = sha256U(cnonce + hashedPw + nonce);
    const tok16     = t => crypto.createHash('sha256').update(t + cnonce + nonce + hashedKey, 'utf8').digest().slice(0, 16);
    const lsk       = tok16('lsk');
    const ivb       = tok16('ivb');

    // ── 5. Encrypt and send command via securePassthrough ──────────────────────
    // _direct commands (e.g. alarm) use method:'set'/'do' sent as-is (pytapo's performRequest path).
    // All other commands are wrapped in multipleRequest (pytapo's executeFunction path).
    const { _acceptErrors = [], _acceptNetworkErrors = false, _direct = false, ...apiCmd } = COMMANDS[command];
    const payload = _direct ? apiCmd : { method: 'multipleRequest', params: { requests: [apiCmd] } };
    const cipher  = crypto.createCipheriv('aes-128-cbc', lsk, ivb);
    const encReq  = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]).toString('base64');
    const bodyStr = JSON.stringify({ method: 'securePassthrough', params: { request: encReq } })
        .replace(/:/g, ': ').replace(/,/g, ', ');
    const tag = crypto.createHash('sha256')
        .update(sha256U(hashedPw + cnonce) + bodyStr + String(seq), 'utf8').digest('hex').toUpperCase();
    const buf = Buffer.from(bodyStr, 'utf8');

    let r3;
    try {
        r3 = await postRaw(`/stok=${stok}/ds`, bodyStr, {
            'User-Agent':      'Tapo CameraClient Android',
            'Accept-Encoding': 'gzip, deflate',
            'Accept':          'application/json',
            'Connection':      'keep-alive',
            'Host':            `${ip}:443`,
            'Referer':         `https://${ip}:443`,
            'requestByApp':    'true',
            'Content-Type':    'application/json; charset=UTF-8',
            'Content-Length':  buf.length,
            'Seq':             String(seq),
            'Tapo_tag':        tag,
        });
    } catch (err) {
        if (_acceptNetworkErrors) { console.log(`OK: ${command}`); return; }
        throw err;
    }

    if (r3.error_code !== 0) throw new Error('securePassthrough failed: ' + JSON.stringify(r3));
    // Direct commands (method:'set'/'do') return {error_code:0} with no encrypted body
    if (!r3.result?.response) { console.log(`OK: ${command}`); return; }
    const decipher = crypto.createDecipheriv('aes-128-cbc', lsk, ivb);
    const inner    = JSON.parse(
        Buffer.concat([decipher.update(Buffer.from(r3.result.response, 'base64')), decipher.final()]).toString()
    );
    if (_direct) {
        // Direct commands return {error_code, result} — no responses array
        if (inner.error_code !== 0 && !_acceptErrors.includes(inner.error_code)) {
            throw new Error('command error: ' + JSON.stringify(inner));
        }
    } else {
        if (inner.error_code !== 0) throw new Error('command failed: ' + JSON.stringify(inner));
        const resp0 = inner.result?.responses?.[0];
        if (resp0?.error_code !== 0 && !_acceptErrors.includes(resp0?.error_code)) {
            throw new Error('command error: ' + JSON.stringify(resp0));
        }
    }

    console.log(`OK: ${command}`);
}

main().catch(e => { console.error(e.message); process.exit(1); });
