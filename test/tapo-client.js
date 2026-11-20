'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { EventEmitter } = require('events');
const { performance } = require('perf_hooks');

const clientPath = require.resolve('../lib/tapo-client');
const originalRequest = https.request;
const password = 'test-password';
const digest = value => crypto.createHash('sha256').update(value, 'utf8').digest('hex').toUpperCase();
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const tests = [];

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

async function withWallClock(test) {
    const originalNow = Date.now;
    let offset = 0;
    Date.now = () => originalNow() + offset;
    try {
        await test(value => { offset = value; });
    } finally {
        Date.now = originalNow;
    }
}

function fixture() {
    const camera = {
        requests: [], commands: [], sessions: new Map(), setting: 'off',
        onCommand: async () => ({}), onLogin: async () => {},
    };
    let pending;
    let sessionNumber = 0;

    async function handle(options, body) {
        camera.requests.push(body.method);
        if (body.method === 'login') {
            await camera.onLogin(body);
            const { cnonce, digest_passwd: digestPassword } = body.params;
            if (!digestPassword) {
                const nonce = crypto.randomBytes(8).toString('hex').toUpperCase();
                pending = { cnonce, nonce };
                return { body: { error_code: -40413, result: { data: {
                    nonce, device_confirm: digest(cnonce + digest(password) + nonce) + nonce + cnonce,
                } } } };
            }
            const hashedKey = digest(pending.cnonce + digest(password) + pending.nonce);
            const key = token => crypto.createHash('sha256')
                .update(token + pending.cnonce + pending.nonce + hashedKey).digest().slice(0, 16);
            const stok = 'session-' + ++sessionNumber;
            camera.sessions.set(stok, { key: key('lsk'), iv: key('ivb') });
            return { body: { error_code: 0, result: { stok, start_seq: 1 } } };
        }

        const stok = /stok=([^/]+)/.exec(options.path)[1];
        const session = camera.sessions.get(stok);
        const decipher = crypto.createDecipheriv('aes-128-cbc', session.key, session.iv);
        const payload = JSON.parse(Buffer.concat([
            decipher.update(Buffer.from(body.params.request, 'base64')), decipher.final(),
        ]).toString());
        const direct = payload.method !== 'multipleRequest';
        const command = direct ? payload : payload.params.requests[0];
        camera.commands.push(command.method);
        const reply = await camera.onCommand(command);
        if (reply.raw) return { body: reply.raw, status: reply.status, headers: reply.headers };
        if (command.method === 'setLedStatus') camera.setting = command.params.led.config.enabled;
        if (command.method === 'changeState') camera.setting = 'off';
        const result = { enabled: camera.setting };
        const inner = direct ? { error_code: 0, result }
            : { error_code: 0, result: { responses: [{ error_code: 0, result }] } };
        const cipher = crypto.createCipheriv('aes-128-cbc', session.key, session.iv);
        const response = Buffer.concat([cipher.update(JSON.stringify(inner)), cipher.final()]).toString('base64');
        return { body: { error_code: 0, result: { response } } };
    }

    https.request = (options, callback) => {
        const request = new EventEmitter();
        const chunks = [];
        let destroyed = false;
        request.write = chunk => chunks.push(Buffer.from(chunk));
        request.destroy = error => {
            if (destroyed) return;
            destroyed = true;
            if (error) request.emit('error', error);
        };
        request.end = () => {
            Promise.resolve().then(() => handle(options, JSON.parse(Buffer.concat(chunks).toString())))
                .then(reply => {
                    if (destroyed) return;
                    const response = new EventEmitter();
                    response.statusCode = reply.status || 200;
                    response.headers = reply.headers || {};
                    response.complete = true;
                    callback(response);
                    response.emit('data', Buffer.from(JSON.stringify(reply.body)));
                    response.emit('end');
                    response.emit('close');
                }).catch(error => request.emit('error', error));
        };
        return request;
    };

    delete require.cache[clientPath];
    const client = require(clientPath);
    Object.assign(client._limits, { minGapMs: 0, leaseGraceMs: 10, opMaxMs: 2000 });
    const ip = 'mock-camera';
    const send = command => client.executeOnDevice(ip, 'test-user', password, command);
    return { client, camera, ip, send };
}

async function eventFixture({ tls = false, expired = false } = {}) {
    const base = fixture();
    const originalHttpRequest = http.request;
    const cameraRequest = https.request;
    const ready = deferred();
    const leaseReady = deferred();
    const acquire = base.client.acquireLease;
    let expiredLease = null;
    if (expired) {
        expiredLease = await acquire(base.ip, { holdMs: 20 });
        const expiredSignal = deferred();
        const off = expiredLease.signal.on(expiredSignal.resolve);
        await expiredSignal.promise;
        off();
    }
    base.client.acquireLease = async (ip, options) => {
        const lease = expiredLease || await acquire(ip, { ...options, holdMs: tls ? 450 : 50 });
        leaseReady.resolve(lease);
        return lease;
    };

    function soapRequest(options, callback) {
        const request = new EventEmitter();
        const socket = new EventEmitter();
        socket.connecting = true;
        socket.encrypted = options.port === 443;
        request.socket = socket;
        request.destroyed = false;
        request.writes = 0;
        request.write = () => { request.writes++; };
        request.destroy = error => {
            if (request.destroyed) return;
            request.destroyed = true;
            socket.destroyed = true;
            process.nextTick(() => {
                if (error) request.emit('error', error);
                request.emit('close');
            });
        };
        request.end = () => {
            request.emit('socket', socket);
            if (tls && !socket.encrypted) {
                socket.connecting = false;
                socket.emit('connect');
                const response = new EventEmitter();
                response.statusCode = 200;
                response.complete = true;
                callback(response);
                response.emit('data', Buffer.from('<Events><XAddr>https://mock-camera/events</XAddr></Events>'));
                response.emit('end');
                request.emit('close');
            }
        };
        if (!tls || socket.encrypted) ready.resolve(request);
        return request;
    }
    http.request = soapRequest;
    https.request = (options, callback) => options.headers['Content-Type'].startsWith('application/soap+xml')
        ? soapRequest(options, callback) : cameraRequest(options, callback);
    const types = {};
    const device = { ip: base.ip, username: 'test-user', credentials: { password } };
    const RED = { nodes: {
        createNode(node) {
            const emitter = new EventEmitter();
            node.on = emitter.on.bind(emitter);
            node.emit = emitter.emit.bind(emitter);
            node.status = () => {};
            node.warn = () => {};
            node.error = () => {};
            node.send = () => {};
        },
        getNode: () => device,
        registerType: (name, constructor) => { types[name] = constructor; },
    } };
    const eventPath = require.resolve('../nodes/tapo-onvif-events');
    delete require.cache[eventPath];
    require(eventPath)(RED);
    const node = new types['tapo-onvif-events']({ device: 'test-device', autoStart: !tls });
    if (tls) node.emit('input', { action: 'start' }, () => {}, () => {});
    return { ...base, request: ready.promise, lease: leaseReady.promise,
        async close() {
            try { await new Promise(resolve => node.emit('close', false, resolve)); }
            finally {
                http.request = originalHttpRequest;
                https.request = cameraRequest;
                delete require.cache[eventPath];
            }
        },
    };
}

tests.push(['all catalogue setters explicitly declare complete-state coalescing', async () => {
    const { client } = fixture();
    for (const [name, command] of Object.entries(client.COMMANDS)) {
        if (command.method.startsWith('set')) assert.strictEqual(command._coalesce, true, name);
    }
}]);

tests.push(['event handoff expiry destroys pending connection before queued HTTPS proceeds', async () => {
    const events = await eventFixture();
    try {
        const request = await events.request;
        const lease = await events.lease;
        assert.strictEqual(request.destroyed, false);
        events.camera.onCommand = async () => { assert.strictEqual(request.destroyed, true); return {}; };
        await events.send(events.client.COMMANDS['get-device-info']);
        assert.strictEqual(lease.signal.aborted, true);
        assert.strictEqual(request.socket.destroyed, true);
        assert.strictEqual(lease.signal.fns.size, 0);
    } finally { await events.close(); }
}]);

tests.push(['TLS handoff stays protected after TCP connect until secureConnect', async () => {
    const events = await eventFixture({ tls: true });
    try {
        const request = await events.request;
        const lease = await events.lease;
        request.socket.connecting = false;
        request.socket.emit('connect');
        let completed = false;
        const queued = events.send(events.client.COMMANDS['get-device-info']).then(() => { completed = true; });
        await delay(20);
        assert.strictEqual(completed, false);
        request.socket.emit('secureConnect');
        await queued;
        assert.strictEqual(lease.signal.fns.size, 0);
        assert.strictEqual(lease.signal.aborted, false);
        assert.strictEqual(request.destroyed, false);
    } finally { await events.close(); }
}]);

tests.push(['already-expired event handoff cancels immediately without SOAP writes', async () => {
    const events = await eventFixture({ expired: true });
    try {
        const request = await events.request;
        const lease = await events.lease;
        await delay(10);
        assert.strictEqual(request.destroyed, true);
        assert.strictEqual(request.writes, 0);
        assert.strictEqual(lease.signal.fns.size, 0);
        await events.send(events.client.COMMANDS['get-device-info']);
    } finally { await events.close(); }
}]);

tests.push(['throwing cancellation listeners do not block delivery or queue progress', async () => {
    const { client, ip } = fixture();
    const lease = await client.acquireLease(ip, { holdMs: 20 });
    let delivered = 0;
    lease.signal.on(() => { throw new Error('listener failure'); });
    lease.signal.on(() => { delivered++; });
    lease.signal.on(async () => { throw new Error('async listener failure'); });
    const next = await client.acquireLease(ip, { waitMs: 500 });
    assert(next, 'Expired lease must free the queue');
    next.release();
    assert.strictEqual(delivered, 1);
    assert.strictEqual(lease.signal.reason.code, 'ETIMEDOUT');
    assert.doesNotThrow(() => lease.signal.on(() => { throw new Error('late listener failure'); }));
}]);

for (const barrier of ['action', 'lease']) {
    for (const running of [true, false]) {
        tests.push([`identical setters execute across ${barrier} with ${running ? 'running' : 'cached'} first setter`, async () => {
            const { client, camera, ip, send } = fixture();
            const started = deferred();
            const finish = deferred();
            camera.onCommand = async command => {
                if ((running && command.method === 'setLedStatus' && camera.commands.length === 1)
                    || (!running && command.method === 'changeState')) {
                    started.resolve();
                    await finish.promise;
                }
                return {};
            };
            const first = send(client.COMMANDS['led-on']);
            if (running) await started.promise;
            else await first;
            const middle = barrier === 'action' ? send({ method: 'changeState' }) : client.acquireLease(ip);
            if (!running && barrier === 'action') await started.promise;
            const last = send(client.COMMANDS['led-on']);
            finish.resolve();
            await first;
            const owner = await middle;
            if (barrier === 'lease') {
                assert(owner);
                camera.setting = 'off';
                owner.release();
            }
            await last;
            assert.deepStrictEqual(camera.commands, barrier === 'action'
                ? ['setLedStatus', 'changeState', 'setLedStatus'] : ['setLedStatus', 'setLedStatus']);
            assert.strictEqual(camera.setting, 'on');
        }]);
    }
}

tests.push(['identical setters still share running and recent results without a barrier', async () => {
    const { client, camera, send } = fixture();
    const started = deferred();
    const finish = deferred();
    camera.onCommand = async () => { started.resolve(); await finish.promise; return {}; };
    const first = send(client.COMMANDS['led-on']);
    await started.promise;
    const second = send(client.COMMANDS['led-on']);
    finish.resolve();
    await Promise.all([first, second]);
    await send(client.COMMANDS['led-on']);
    assert.deepStrictEqual(camera.commands, ['setLedStatus']);
}]);

for (const status of [429, 503]) {
    for (const header of [undefined, 'invalid', '0']) {
        tests.push([`HTTP ${status} with Retry-After ${String(header)} cannot be shortened by ONVIF`, async () => {
            const { client, camera, ip, send } = fixture();
            camera.onCommand = async () => ({ status, headers: header === undefined ? {} : { 'retry-after': header }, raw: { error_code: 0 } });
            await assert.rejects(send(client.COMMANDS['get-device-info']), error => error.httpStatus === status);
            const before = camera.requests.length;
            client.noteDeviceReachable(ip);
            await assert.rejects(send(client.COMMANDS['get-device-info']), error => error.code === 'BACKOFF' && /overloaded/.test(error.message));
            assert.strictEqual(camera.requests.length, before);
        }]);
    }
}

tests.push(['expiry during ONVIF stop prevents both login and command traffic', async () => {
    const { client, camera, ip, send } = fixture();
    client._limits.cmdMaxAgeMs = 40;
    const callbacks = { stop: async () => { await delay(80); return true; }, start: () => {} };
    client.registerOnvifCallbacks(ip, callbacks);
    try {
        await assert.rejects(send(client.COMMANDS['privacy-on']), error => error.code === 'EXPIRED');
        assert.deepStrictEqual(camera.requests, []);
    } finally {
        client.unregisterOnvifCallbacks(ip, callbacks);
    }
}]);

tests.push(['independent custom partial setters in the same section are both retained', async () => {
    const { client, camera, ip, send } = fixture();
    const state = {};
    camera.onCommand = async command => { Object.assign(state, command.params.motion_detection.motion_det); return {}; };
    const lease = await client.acquireLease(ip);
    const first = send({ method: 'setDetectionConfig', params: { motion_detection: { motion_det: { enabled: 'on' } } } });
    const second = send({ method: 'setDetectionConfig', params: { motion_detection: { motion_det: { sensitivity: 70 } } } });
    lease.release();
    const results = await Promise.all([first, second]);
    assert(results.every(result => !result.superseded));
    assert.deepStrictEqual(camera.commands, ['setDetectionConfig', 'setDetectionConfig']);
    assert.deepStrictEqual(state, { enabled: 'on', sensitivity: 70 });
}]);

tests.push(['unmarked custom setter is a barrier for catalogue setter sharing and caching', async () => {
    const { client, camera, send } = fixture();
    const started = deferred();
    const finish = deferred();
    camera.onCommand = async command => {
        if (command.method === 'setLedStatus' && camera.commands.length === 1) { started.resolve(); await finish.promise; }
        return {};
    };
    const first = send(client.COMMANDS['led-on']);
    await started.promise;
    const custom = send({ method: 'setLedStatus', params: { led: { config: { enabled: 'off' } } } });
    const last = send(client.COMMANDS['led-on']);
    finish.resolve();
    await Promise.all([first, custom, last]);
    assert.deepStrictEqual(camera.commands, ['setLedStatus', 'setLedStatus', 'setLedStatus']);
    assert.strictEqual(camera.setting, 'on');
}]);

tests.push(['cancellation during ONVIF stop prevents login traffic', async () => {
    const { client, camera, ip, send } = fixture();
    client._limits.opMaxMs = 40;
    const callbacks = { stop: async () => { await delay(80); return true; }, start: () => {} };
    client.registerOnvifCallbacks(ip, callbacks);
    try {
        await assert.rejects(send(client.COMMANDS['privacy-on']), error => error.code === 'ETIMEDOUT');
        assert.deepStrictEqual(camera.requests, []);
    } finally {
        client.unregisterOnvifCallbacks(ip, callbacks);
    }
}]);

tests.push(['expiry during retry delay prevents reauthentication', async () => {
    const { client, camera, send } = fixture();
    client._limits.cmdMaxAgeMs = 40;
    client._limits.retryGapMs = 80;
    camera.onCommand = async () => ({ raw: { error_code: -40401 } });
    await assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'EXPIRED');
    assert.deepStrictEqual(camera.requests, ['login', 'login', 'securePassthrough']);
}]);

tests.push(['expiry after a cached-session reset preserves transport backoff', async () => {
    const { client, camera, ip, send } = fixture();
    await send(client.COMMANDS['get-device-info']);
    client._limits.cmdMaxAgeMs = 100;
    client._limits.retryGapMs = 80;
    camera.onCommand = async () => { throw Object.assign(new Error('socket reset'), { code: 'ECONNRESET' }); };
    const lease = await client.acquireLease(ip);
    const stale = assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'EXPIRED');
    await delay(60);
    lease.release();
    await stale;
    const before = camera.requests.length;
    await assert.rejects(send(client.COMMANDS['get-device-info']), error => error.code === 'BACKOFF');
    assert.strictEqual(camera.requests.length, before);
    assert.deepStrictEqual(camera.commands, ['getDeviceInfo', 'setLedStatus']);
}]);

for (const offset of [-3600000, 3600000]) {
    tests.push([`wall-clock jump ${offset}ms cannot lengthen or skip pacing`, async () => withWallClock(async shift => {
        const { client, send } = fixture();
        await send(client.COMMANDS['get-device-info']);
        client._limits.minGapMs = 80;
        shift(offset);
        const started = performance.now();
        await send(client.COMMANDS['led-on']);
        const elapsed = performance.now() - started;
        assert(elapsed >= 60 && elapsed < 500, 'Pacing must remain near its configured duration: ' + elapsed);
    })]);
}

tests.push(['backward clock jump cannot keep expired waiters occupying queue capacity', async () => withWallClock(async shift => {
    const { client, camera, ip, send } = fixture();
    client._limits.cmdMaxAgeMs = 40;
    const lease = await client.acquireLease(ip);
    const expired = ['get-device-info', 'get-sd-card', 'get-lens-mask']
        .map(name => assert.rejects(send(client.COMMANDS[name]), error => error.code === 'EXPIRED'));
    shift(-3600000);
    await delay(80);
    const fresh = send(client.COMMANDS['led-on']);
    lease.release();
    await Promise.all([...expired, fresh]);
    assert.deepStrictEqual(camera.commands, ['setLedStatus']);
})]);

tests.push(['expired commands do not wait for the full pacing gap', async () => withWallClock(async shift => {
    const { client, camera, send } = fixture();
    await send(client.COMMANDS['get-device-info']);
    client._limits.minGapMs = 1000;
    client._limits.cmdMaxAgeMs = 40;
    shift(-3600000);
    const started = performance.now();
    await assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'EXPIRED');
    assert(performance.now() - started < 500);
    assert.deepStrictEqual(camera.commands, ['getDeviceInfo']);
})]);

tests.push(['backward clock jump cannot extend recent-setter suppression', async () => withWallClock(async shift => {
    const { client, camera, send } = fixture();
    client._limits.repeatWindowMs = 20;
    await send(client.COMMANDS['led-on']);
    shift(-3600000);
    await delay(50);
    await send(client.COMMANDS['led-on']);
    assert.deepStrictEqual(camera.commands, ['setLedStatus', 'setLedStatus']);
})]);

tests.push(['forward clock jump cannot expire a healthy cached session', async () => withWallClock(async shift => {
    const { client, camera, send } = fixture();
    await send(client.COMMANDS['get-device-info']);
    shift(3600000);
    await send(client.COMMANDS['get-device-info']);
    assert.deepStrictEqual(camera.requests, ['login', 'login', 'securePassthrough', 'securePassthrough']);
})]);

tests.push(['startup reboot guard ignores forward and backward clock jumps', async () => withWallClock(async shift => {
    const { client, send } = fixture();
    client._limits.startupRebootGuardMs = 40;
    shift(3600000);
    await assert.rejects(send(client.COMMANDS.reboot), error => error.code === 'STARTUP_GUARD');
    await delay(60);
    shift(-3600000);
    await send(client.COMMANDS.reboot);
})]);

tests.push(['HTTP-date Retry-After becomes a duration unaffected by later clock jumps', async () => withWallClock(async shift => {
    const { client, camera, ip, send } = fixture();
    camera.onCommand = async () => ({ status: 503, raw: { error_code: 0 },
        headers: { 'retry-after': new Date(Date.now() + 60000).toUTCString() } });
    await assert.rejects(send(client.COMMANDS['get-device-info']), error => error.retryAfterMs >= 58000 && error.retryAfterMs <= 60000);
    const before = camera.requests.length;
    for (const offset of [3600000, -3600000]) {
        shift(offset);
        client.noteDeviceReachable(ip);
        await assert.rejects(send(client.COMMANDS['get-device-info']), error => error.code === 'BACKOFF' && /retry in (59|60)s/.test(error.message));
    }
    assert.strictEqual(camera.requests.length, before);
})]);

tests.push(['expiry during authentication survives a backward clock jump', async () => withWallClock(async shift => {
    const { client, camera, send } = fixture();
    client._limits.cmdMaxAgeMs = 40;
    camera.onLogin = async body => {
        if (!body.params.digest_passwd) { shift(-3600000); await delay(80); }
    };
    await assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'EXPIRED');
    assert.deepStrictEqual(camera.requests, ['login', 'login']);
    assert.deepStrictEqual(camera.commands, []);
})]);

(async () => {
    let failures = 0;
    try {
        for (const [name, test] of tests) {
            try {
                await test();
                console.log('PASS ' + name);
            } catch (error) {
                failures++;
                console.error('FAIL ' + name, error);
            }
        }
    } finally {
        https.request = originalRequest;
        delete require.cache[clientPath];
    }
    console.log(`${tests.length - failures} passed, ${failures} failed`);
    process.exitCode = failures ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });