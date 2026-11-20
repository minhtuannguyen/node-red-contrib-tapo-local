'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
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

async function withMonotonicClock(test) {
    const descriptor = Object.getOwnPropertyDescriptor(performance, 'now');
    const originalNow = performance.now.bind(performance);
    let offset = 0;
    Object.defineProperty(performance, 'now', { configurable: true, value: () => originalNow() + offset });
    try {
        await test(value => { offset = value; });
    } finally {
        if (descriptor) Object.defineProperty(performance, 'now', descriptor);
        else delete performance.now;
    }
}

function fixture() {
    const camera = {
        requests: [], commands: [], sessions: new Map(), setting: 'off', privacy: 'off',
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
        if (command.method === 'setLensMaskConfig') camera.privacy = command.params.lens_mask.lens_mask_info.enabled;
        const result = command.method === 'getLensMaskConfig'
            ? { lens_mask: { lens_mask_info: { enabled: camera.privacy } } } : { enabled: camera.setting };
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
    Object.assign(client._limits, { minGapMs: 0, leaseGraceMs: 10, opMaxMs: 2000, startupQuietMs: 0 });
    const ip = 'mock-camera';
    const send = command => client.executeOnDevice(ip, 'test-user', password, command);
    return { client, camera, ip, send };
}

const HOLD = Symbol('connected, no reply yet');
const ONVIF_DEFAULTS = {
    GetCapabilities: '<Capabilities><Events><XAddr>http://mock-camera:2020/events</XAddr></Events></Capabilities>',
    CreatePullPointSubscription: '<SubscriptionReference><Address>http://mock-camera:2020/sub/1</Address></SubscriptionReference>',
    PullMessages: HOLD,
    Renew: '<RenewResponse/>',
    Unsubscribe: '<UnsubscribeResponse/>',
    ContinuousMove: '<ContinuousMoveResponse/>',
    Stop: '<StopResponse/>',
};

async function waitFor(predicate, ms = 3000) {
    const end = performance.now() + ms;
    while (!predicate()) {
        if (performance.now() > end) throw new Error('Timed out waiting for condition');
        await delay(10);
    }
}

// Real event node against scripted ONVIF requests.  `script[op](request)` returns XML, { status, body },
// HOLD (connected, no reply) or undefined (still connecting); unlisted operations use ONVIF_DEFAULTS.
async function eventFixture({ script = {}, leases = 'real', leaseHoldMs, autoStart = false, privacy = 'off', eventConfig = {}, beforeNode, onvifDevice } = {}) {
    const base = fixture();
    base.camera.privacy = privacy;
    const originalHttpRequest = http.request;
    const cameraRequest = https.request;
    const created = [];
    const seen = [];
    const leaseLog = [];
    const statuses = [];
    const warns = [];
    const messages = [];
    const realAcquire = base.client.acquireLease;
    let acquireCalls = 0;
    let expiredLease = null;
    if (leases === 'expired') {
        expiredLease = await realAcquire(base.ip, { holdMs: 20 });
        const expiredSignal = deferred();
        const off = expiredLease.signal.on(expiredSignal.resolve);
        await expiredSignal.promise;
        off();
    }
    base.client.acquireLease = async (ip, options) => {
        acquireCalls++;
        if (leases === 'null') return null;
        const lease = expiredLease || await realAcquire(ip, leaseHoldMs ? { ...options, holdMs: leaseHoldMs } : options);
        if (lease) leaseLog.push(lease);
        return lease;
    };

    function soapRequest(options, callback) {
        const request = new EventEmitter();
        const socket = new EventEmitter();
        socket.connecting = true;
        socket.encrypted = options.port === 443;
        Object.assign(request, { socket, destroyed: false, writes: 0, body: '', op: null });
        request.write = chunk => { request.writes++; request.body += chunk; };
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
            request.op = (/<(?:\w+:)?(GetCapabilities|CreatePullPointSubscription|PullMessages|Renew|Unsubscribe|ContinuousMove|Stop)\b/.exec(request.body) || [])[1];
            seen.push(request);
            const reply = request.op in script ? script[request.op](request) : ONVIF_DEFAULTS[request.op];
            if (reply === undefined) return;
            socket.connecting = false;
            socket.emit(socket.encrypted ? 'secureConnect' : 'connect');
            if (reply === HOLD) return;
            setImmediate(() => {
                if (request.destroyed) return;
                const response = new EventEmitter();
                response.statusCode = reply.status || 200;
                response.headers = {};
                response.complete = true;
                callback(response);
                response.emit('data', Buffer.from(typeof reply === 'string' ? reply : reply.body || ''));
                response.emit('end');
                request.emit('close');
            });
        };
        created.push(request);
        return request;
    }
    http.request = soapRequest;
    https.request = (options, callback) => options.headers['Content-Type'].startsWith('application/soap+xml')
        ? soapRequest(options, callback) : cameraRequest(options, callback);
    const types = {};
    const device = { ip: base.ip, username: 'test-user', credentials: { password } };
    const eventDevice = onvifDevice ? { ip: base.ip, ...onvifDevice } : device;
    const RED = { nodes: {
        createNode(node) {
            const emitter = new EventEmitter();
            node.on = emitter.on.bind(emitter);
            node.emit = emitter.emit.bind(emitter);
            node.status = status => statuses.push(status.text);
            node.warn = message => warns.push(String(message));
            node.error = () => {};
            node.send = message => messages.push(message);
        },
        getNode: id => id === 'test-https-device' || !onvifDevice ? device : eventDevice,
        registerType: (name, constructor) => { types[name] = constructor; },
    } };
    const eventPath = require.resolve('../nodes/tapo-onvif-events');
    delete require.cache[eventPath];
    require(eventPath)(RED);
    if (beforeNode) await beforeNode(base);
    const node = new types['tapo-onvif-events']({ device: 'test-device', autoStart, ...eventConfig });
    const eventNodes = [node];
    const input = action => node.emit('input', { action }, () => {}, () => {});
    const ops = () => seen.map(request => request.op);
    const ptzPath = require.resolve('../nodes/tapo-ptz');
    const ptzNodes = [];
    const controlNodes = [];
    function createPtz() {
        if (!types['tapo-ptz']) {
            delete require.cache[ptzPath];
            require(ptzPath)(RED);
        }
        const ptz = new types['tapo-ptz']({ device: 'test-device' });
        ptzNodes.push(ptz);
        const messages = [];
        return {
            messages,
            send: action => new Promise(resolve => ptz.emit('input', { action }, message => messages.push(message), resolve)),
            close: () => ptz.emit('close'),
        };
    }
    return { ...base, node, input, created, seen, ops, leaseLog, statuses, warns, messages, realAcquire,
        createControl() {
            const controlPath = require.resolve('../nodes/tapo-local');
            delete require.cache[controlPath];
            require(controlPath)(RED);
            const control = new types['tapo-local']({ device: 'test-device' });
            controlNodes.push(control);
            return {
                send: command => new Promise(resolve => control.emit('input', { command }, message => messages.push(message), resolve)),
                close: () => control.emit('close'),
            };
        },
        createEvents(config = {}) {
            const added = new types['tapo-onvif-events']({ device: 'test-device', autoStart: true, ...config });
            eventNodes.push(added);
            return added;
        },
        createPtz,
        acquireCalls: () => acquireCalls,
        async close() {
            try {
                for (const ptz of ptzNodes) ptz.emit('close');
                for (const control of controlNodes) control.emit('close');
                for (const eventNode of eventNodes) await new Promise(resolve => eventNode.emit('close', false, resolve));
            }
            finally {
                http.request = originalHttpRequest;
                https.request = cameraRequest;
                delete require.cache[eventPath];
                delete require.cache[ptzPath];
            }
        },
    };
}

tests.push(['event handoff is released when a request fails before tracking', async () => {
    const events = await eventFixture({ script: {
        GetCapabilities: () => '<Events><XAddr>http://[</XAddr></Events>',
    } });
    try {
        events.input('start');
        await waitFor(() => events.warns.some(message => /Bad ONVIF URL/.test(message)));
        const lease = await events.realAcquire(events.ip, { waitMs: 100 });
        assert(lease, 'a failed request must not leave the camera quarantined');
        lease.release();
        assert(events.leaseLog.every(entry => !entry.signal.aborted), 'handoff must release before expiry');
    } finally { await events.close(); }
}]);

tests.push(['lease predicate exceptions settle without wedging the caller', async () => {
    const { client, ip } = fixture();
    const result = await Promise.race([
        client.acquireLease(ip, { stillWanted: () => { throw new Error('owner removed'); } }),
        delay(100).then(() => 'unsettled'),
    ]);
    assert.strictEqual(result, null);
    const lease = await client.acquireLease(ip, { waitMs: 100 });
    assert(lease);
    lease.release();
}]);

tests.push(['timed-out lease waiters free admission capacity immediately', async () => {
    const { client, ip } = fixture();
    client._limits.maxLeases = 2;
    const blocker = await client.acquireLease(ip);
    try {
        assert.strictEqual(await client.acquireLease(ip, { waitMs: 10 }), null);
        const pending = client.acquireLease(ip, { waitMs: 100 });
        blocker.release();
        const lease = await pending;
        assert(lease, 'an abandoned waiter must not occupy a lease slot');
        lease.release();
    } finally { blocker.release(); }
}]);

tests.push(['cancelled queue owners send no traffic and free capacity', async () => {
    const { client, camera, ip, send } = fixture();
    const lease = await client.acquireLease(ip);
    const signal = client.makeAbort();
    const pending = client.executeOnDevice(ip, 'test-user', password, client.COMMANDS['led-on'], { signal });
    const rejected = assert.rejects(pending, error => error.code === 'CANCELLED');
    signal.abort();
    await rejected;
    const next = send(client.COMMANDS['get-device-info']);
    lease.release();
    await next;
    assert.deepStrictEqual(camera.commands, ['getDeviceInfo']);
}]);

tests.push(['cancelling one shared read preserves the other live owner', async () => {
    const { client, camera, ip, send } = fixture();
    const lease = await client.acquireLease(ip);
    const signal = client.makeAbort();
    const first = client.executeOnDevice(ip, 'test-user', password, client.COMMANDS['get-device-info'], { signal });
    const second = send(client.COMMANDS['get-device-info']);
    const rejected = assert.rejects(first, error => error.code === 'CANCELLED');
    signal.abort();
    lease.release();
    await Promise.all([rejected, second]);
    assert.deepStrictEqual(camera.commands, ['getDeviceInfo']);
}]);

tests.push(['unconfirmed setters are not cached as successful repeats', async () => {
    const { client, camera, send } = fixture();
    camera.onCommand = async () => { throw Object.assign(new Error('lost reply'), { code: 'ECONNRESET' }); };
    const command = { ...client.COMMANDS['led-on'], _acceptNetworkErrors: true };
    assert.strictEqual((await send(command)).confirmed, false);
    await assert.rejects(send(command), error => error.code === 'BACKOFF');
    assert.deepStrictEqual(camera.commands, ['setLedStatus']);
}]);

tests.push(['multiple event nodes share one subscription and stop independently', async () => {
    const events = await eventFixture({ autoStart: true });
    try {
        const second = events.createEvents();
        await waitFor(() => events.ops().includes('PullMessages'));
        await new Promise(resolve => second.emit('input', { action: 'stop' }, null, resolve));
        assert.strictEqual(events.ops().filter(op => op === 'CreatePullPointSubscription').length, 1);
        assert(!events.ops().includes('Unsubscribe'), 'stopping one subscriber must not stop another');
        await new Promise(resolve => events.node.emit('input', { action: 'stop' }, null, resolve));
        assert.strictEqual(events.ops().filter(op => op === 'Unsubscribe').length, 1);
    } finally { await events.close(); }
}]);

tests.push(['PTZ flood replaces waiting moves without replaying the backlog', async () => {
    let firstMove;
    const events = await eventFixture({ script: { ContinuousMove: request => {
        if (!firstMove) { firstMove = request; return HOLD; }
        return ONVIF_DEFAULTS.ContinuousMove;
    } } });
    events.client._limits.ptzGapMs = 10;
    const ptz = events.createPtz();
    const running = ptz.send('continuousMove');
    try {
        await waitFor(() => firstMove);
        const flood = Array.from({ length: 200 }, () => ptz.send('continuousMove'));
        firstMove.destroy(new Error('cancel test move'));
        await Promise.all([running, ...flood]);
        assert.strictEqual(events.ops().filter(op => op === 'ContinuousMove').length, 2);
        assert(/<tptz:Timeout>PT5S<\/tptz:Timeout>/.test(firstMove.body));
    } finally { await events.close(); }
}]);

tests.push(['PTZ Stop bypasses movement pacing', async () => {
    const events = await eventFixture();
    const ptz = events.createPtz();
    try {
        events.client._limits.ptzGapMs = 2000;
        await ptz.send('continuousMove');
        const started = performance.now();
        await ptz.send('stop');
        assert(performance.now() - started < 500);
        assert(events.ops().includes('Stop'));
    } finally { await events.close(); }
}]);

for (const reason of ['Invalid preset token', 'Unsupported timeout argument']) {
    tests.push([`PTZ command fault (${reason}) does not trigger a device cooldown`, async () => {
        let moves = 0;
        const events = await eventFixture({ script: { ContinuousMove: () => ++moves === 1
            ? `<s:Fault><s:Reason>${reason}</s:Reason></s:Fault>` : ONVIF_DEFAULTS.ContinuousMove } });
        const ptz = events.createPtz();
        events.client._limits.ptzGapMs = 0;
        try {
            assert((await ptz.send('continuousMove')) instanceof Error);
            assert.strictEqual(moves, 1, 'a rejected move must not be replayed automatically');
            assert.strictEqual(events.client.onvifDelayMs(events.ip), 0);
            assert.strictEqual(await ptz.send('continuousMove'), undefined);
            assert.strictEqual(moves, 2);
        } finally { await events.close(); }
    }]);
}

for (const reply of [
    { status: 401 }, { status: 403 }, { status: 429 }, { status: 500 }, { status: 503 },
    '<s:Fault><s:Subcode>ter:NotAuthorized</s:Subcode></s:Fault>',
]) {
    tests.push([`PTZ health failure (${reply.status || 'NotAuthorized'}) still triggers a cooldown`, async () => {
        const events = await eventFixture({ script: { ContinuousMove: () => reply } });
        const ptz = events.createPtz();
        try {
            assert((await ptz.send('continuousMove')) instanceof Error);
            assert(events.client.onvifDelayMs(events.ip) > 0);
            const sent = events.seen.length;
            assert((await ptz.send('continuousMove')) instanceof Error);
            assert.strictEqual(events.seen.length, sent, 'cooldown must prevent another camera request');
        } finally { await events.close(); }
    }]);
}

tests.push(['reboot cooldown blocks ordinary ONVIF leases', async () => {
    const { client, ip, send } = fixture();
    client._limits.startupRebootGuardMs = 0;
    await send(client.COMMANDS.reboot);
    assert(client.controlDelayMs(ip) > 40000);
    assert.strictEqual(await client.acquireLease(ip), null);
}]);

tests.push(['expired production leases quarantine unacknowledged owners', async () => {
    const { client, ip, send, camera } = fixture();
    const lease = await client.acquireLease(ip, { holdMs: 10, requireRelease: true });
    await delay(40);
    try {
        assert.strictEqual(await client.acquireLease(ip, { waitMs: 50 }), null);
        await assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'ONVIF_PAUSE');
        assert.deepStrictEqual(camera.requests, []);
    } finally { lease.release(); }
    await send(client.COMMANDS['led-on']);
    assert.deepStrictEqual(camera.commands, ['setLedStatus']);
}]);

tests.push(['abandoned idle leases recover without an owner acknowledgement', async () => {
    const { client, ip, send } = fixture();
    client._limits.leaseRecoveryMs = 30;
    const abandoned = await client.acquireLease(ip, { holdMs: 10, requireRelease: true });
    await delay(80);
    const next = await client.acquireLease(ip, { requireRelease: true, holdMs: 200 });
    assert(next, 'an abandoned idle owner must not block control permanently');
    abandoned.release();
    next.release();
    await send(client.COMMANDS['led-on']);
}]);

tests.push(['lease recovery waits for socket close and rejects late requests', async () => {
    const { client, ip, send, camera } = fixture();
    client._limits.leaseRecoveryMs = 20;
    const lease = await client.acquireLease(ip, { holdMs: 10, requireRelease: true });
    const request = new EventEmitter();
    let destroyed = false;
    request.destroy = () => { destroyed = true; };
    lease.trackRequest(request);
    try {
        await delay(70);
        assert(destroyed, 'expired leases must destroy tracked requests');
        assert.strictEqual(await client.acquireLease(ip), null);
        await assert.rejects(send(client.COMMANDS['led-on']), error => error.code === 'ONVIF_PAUSE');
        assert.deepStrictEqual(camera.requests, []);
        request.emit('close');
        assert.strictEqual(request.listenerCount('close'), 0);
        await send(client.COMMANDS['led-on']);
        let lateDestroyed = false;
        lease.trackRequest({ destroy: () => { lateDestroyed = true; } });
        assert(lateDestroyed, 'an expired owner cannot open another connection');
    } finally { lease.release(); }
}]);

tests.push(['reboot and subscription protection survive a fresh client instance', async () => {
    const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tapo-state-'));
    try {
        const first = fixture();
        first.client.configureProtection({ settings: { userDir } });
        first.client._limits.startupRebootGuardMs = 0;
        first.client.reserveSubscription(first.ip, 120000);
        await first.send(first.client.COMMANDS.reboot);
        first.client.noteOnvifFailure(first.ip, new Error('ECONNREFUSED'));
        const second = fixture();
        second.client.configureProtection({ settings: { userDir } });
        await assert.rejects(second.send(second.client.COMMANDS['led-on']), error => error.code === 'BACKOFF');
        assert.strictEqual(await second.client.acquireLease(second.ip), null);
        assert(second.client.subscriptionDelayMs(second.ip) > 119000);
        assert(second.client.onvifDelayMs(second.ip) > 2000);
        assert.deepStrictEqual(second.camera.requests, []);
        const saved = fs.readFileSync(path.join(userDir, 'tapo-local-state.json'), 'utf8');
        assert(!saved.includes(password));
        assert(!saved.includes(digest(password)));
    } finally { fs.rmSync(userDir, { recursive: true, force: true }); }
}]);

tests.push(['privacy-on cancels a poller lease queued behind its own command', async () => {
    const events = await eventFixture();
    events.client._limits.onvifStopMs = 1200;
    const blocker = await events.realAcquire(events.ip);
    const privacy = events.send(events.client.COMMANDS['privacy-on']);
    try {
        events.input('start');
        await waitFor(() => events.acquireCalls() === 1);
        blocker.release();
        await privacy;
        assert.deepStrictEqual(events.camera.commands, ['setLensMaskConfig']);
        assert.deepStrictEqual(events.ops(), []);
    } finally { blocker.release(); await privacy.catch(() => {}); await events.close(); }
}]);

tests.push(['ONVIF backoff prevents both event and PTZ probes without blocking healthy HTTPS', async () => {
    const events = await eventFixture();
    try {
        events.client.noteOnvifFailure(events.ip, new Error('ECONNREFUSED'));
        events.input('start');
        const ptz = events.createPtz();
        const error = await ptz.send('continuousMove');
        assert(error instanceof Error);
        await events.send(events.client.COMMANDS['get-device-info']);
        await delay(50);
        assert.deepStrictEqual(events.ops(), []);
        assert.deepStrictEqual(events.camera.commands, ['getDeviceInfo']);
    } finally { await events.close(); }
}]);

tests.push(['hostname spelling variants share the same camera queue', async () => {
    const { client, camera, ip } = fixture();
    const blocker = await client.acquireLease(ip);
    const pending = client.executeOnDevice(' MOCK-CAMERA. ', 'test-user', password, client.COMMANDS['led-on']);
    await delay(20);
    assert.deepStrictEqual(camera.requests, []);
    blocker.release();
    await pending;
    assert.deepStrictEqual(camera.commands, ['setLedStatus']);
}]);

tests.push(['PTZ commands expire while waiting for the HTTPS lease', async () => {
    const events = await eventFixture();
    events.client._limits.ptzMaxAgeMs = 40;
    const blocker = await events.realAcquire(events.ip);
    const ptz = events.createPtz();
    try {
        const error = await ptz.send('continuousMove');
        assert(error instanceof Error);
        assert.deepStrictEqual(events.ops(), []);
    } finally { blocker.release(); await events.close(); }
}]);

tests.push(['repeated PTZ Stops remain paced', async () => {
    const events = await eventFixture();
    events.client._limits.ptzGapMs = 80;
    const ptz = events.createPtz();
    try {
        await ptz.send('stop');
        const started = performance.now();
        await ptz.send('stop');
        assert(performance.now() - started >= 60);
        assert.strictEqual(events.ops().filter(op => op === 'Stop').length, 2);
    } finally { await events.close(); }
}]);

tests.push(['public authenticated senders obey the shared queue and circuit breaker', async () => {
    const { client, camera, ip, send } = fixture();
    const session = await client.authenticate(ip, 'test-user', password);
    try {
        const blocker = await client.acquireLease(ip);
        const pending = session.sendCmd(client.COMMANDS['led-on']);
        await delay(20);
        assert.deepStrictEqual(camera.requests, ['login', 'login']);
        blocker.release();
        await pending;
        camera.onCommand = async () => ({ status: 503, raw: { error_code: 0 } });
        await assert.rejects(send(client.COMMANDS['get-device-info']));
        const before = camera.requests.length;
        await assert.rejects(session.sendCmd(client.COMMANDS['led-off']), error => error.code === 'BACKOFF');
        await assert.rejects(client.authenticate(ip, 'test-user', password), error => error.code === 'BACKOFF');
        assert.strictEqual(camera.requests.length, before);
    } finally { session.agent.destroy(); }
}]);

tests.push(['new callers do not inherit cancellation from an abandoned running read', async () => {
    const { client, camera, ip, send } = fixture();
    const started = deferred();
    const finish = deferred();
    camera.onCommand = async () => {
        if (camera.commands.length === 1) { started.resolve(); await finish.promise; }
        return {};
    };
    const signal = client.makeAbort();
    const first = client.executeOnDevice(ip, 'test-user', password, client.COMMANDS['get-device-info'], { signal });
    const cancelled = assert.rejects(first, error => error.code === 'CANCELLED');
    try {
        await started.promise;
        signal.abort();
        const second = send(client.COMMANDS['get-device-info']);
        await Promise.all([cancelled, second]);
        assert.deepStrictEqual(camera.commands, ['getDeviceInfo', 'getDeviceInfo']);
    } finally { finish.resolve(); }
}]);

tests.push(['closing a control node cancels queued commands and emits no output', async () => {
    const events = await eventFixture();
    const blocker = await events.realAcquire(events.ip);
    const control = events.createControl();
    try {
        const pending = control.send('led-on');
        control.close();
        blocker.release();
        await pending;
        assert.deepStrictEqual(events.camera.requests, []);
        assert.deepStrictEqual(events.messages, []);
    } finally { blocker.release(); await events.close(); }
}]);

tests.push(['changing camera usernames destroys the previous session agent', async () => {
    const { client, ip } = fixture();
    const first = await client.authenticate(ip, 'test-user', password);
    let destroyed = false;
    const originalDestroy = first.agent.destroy.bind(first.agent);
    first.agent.destroy = () => { destroyed = true; originalDestroy(); };
    const second = await client.authenticate(ip, 'other-user', password);
    assert(destroyed);
    second.agent.destroy();
}]);

tests.push(['all catalogue setters explicitly declare complete-state coalescing', async () => {
    const { client } = fixture();
    for (const [name, command] of Object.entries(client.COMMANDS)) {
        if (command.method.startsWith('set')) assert.strictEqual(command._coalesce, true, name);
    }
}]);

tests.push(['event handoff expiry destroys pending connection before queued HTTPS proceeds', async () => {
    const events = await eventFixture({ script: { GetCapabilities: () => undefined }, leaseHoldMs: 50 });
    try {
        events.input('start');
        await waitFor(() => events.created.length === 1);
        const request = events.created[0];
        const lease = events.leaseLog[0];
        assert.strictEqual(request.destroyed, false);
        events.camera.onCommand = async () => { assert.strictEqual(request.destroyed, true); return {}; };
        await events.send(events.client.COMMANDS['get-device-info']);
        assert.strictEqual(lease.signal.aborted, true);
        assert.strictEqual(request.socket.destroyed, true);
        assert.strictEqual(lease.signal.fns.size, 0);
    } finally { await events.close(); }
}]);

tests.push(['TLS handoff stays protected after TCP connect until secureConnect', async () => {
    const events = await eventFixture({
        leaseHoldMs: 2000,
        script: {
            GetCapabilities: () => '<Capabilities><Events><XAddr>https://mock-camera/events</XAddr></Events></Capabilities>',
            CreatePullPointSubscription: () => undefined,
        },
    });
    try {
        events.input('start');
        await waitFor(() => events.ops().includes('CreatePullPointSubscription'));
        const request = events.seen[events.seen.length - 1];
        const lease = events.leaseLog[events.leaseLog.length - 1];
        request.socket.connecting = false;
        request.socket.emit('connect');
        let completed = false;
        const queued = events.send(events.client.COMMANDS['get-device-info']).then(() => { completed = true; });
        await delay(30);
        assert.strictEqual(completed, false);
        request.socket.emit('secureConnect');
        await queued;
        assert.strictEqual(lease.signal.fns.size, 0);
        assert.strictEqual(lease.signal.aborted, false);
        assert.strictEqual(request.destroyed, true, 'the HTTPS command pauses the connected ONVIF request');
    } finally { await events.close(); }
}]);

tests.push(['already-expired event handoff cancels immediately without SOAP writes', async () => {
    const events = await eventFixture({ leases: 'expired' });
    try {
        events.input('start');
        await waitFor(() => events.created.length === 1);
        await delay(20);
        assert.strictEqual(events.created[0].destroyed, true);
        assert.strictEqual(events.created[0].writes, 0);
        await events.send(events.client.COMMANDS['get-device-info']);
    } finally { await events.close(); }
}]);

tests.push(['failed handoff sends no event traffic and defers the retry', async () => {
    const events = await eventFixture({ leases: 'null' });
    try {
        events.input('start');
        await waitFor(() => events.acquireCalls() === 1);
        await delay(300);
        assert.strictEqual(events.created.length, 0);
        assert.strictEqual(events.acquireCalls(), 1);
        assert(events.warns.some(message => /Hand-off failed/.test(message)));
    } finally { await events.close(); }
}]);

for (const phase of ['GetCapabilities', 'ContinuousMove']) {
    tests.push([`closing PTZ during ${phase} cancels the request and queued commands`, async () => {
        const events = await eventFixture({ script: { [phase]: () => HOLD } });
        const ptz = events.createPtz();
        const running = ptz.send('continuousMove');
        let queued;
        try {
            await waitFor(() => events.ops().includes(phase));
            const request = events.seen[events.seen.length - 1];
            queued = ptz.send('stop');
            ptz.close();
            assert.strictEqual(request.destroyed, true);
            await Promise.all([running, queued]);
            assert(!events.ops().includes('Stop'));
            assert.strictEqual(ptz.messages.length, 0);
            const lease = await events.realAcquire(events.ip, { waitMs: 200 });
            assert(lease, 'Closing PTZ must release its control lease');
            lease.release();
        } finally {
            for (const request of events.created) request.destroy(new Error('ECONNRESET'));
            await Promise.all([running, queued]);
            await events.close();
        }
    }]);
}

tests.push(['closing PTZ during lease acquisition prevents later SOAP traffic', async () => {
    const events = await eventFixture();
    const blocker = await events.realAcquire(events.ip);
    const ptz = events.createPtz();
    const running = ptz.send('continuousMove');
    try {
        await waitFor(() => events.acquireCalls() === 1);
        ptz.close();
        blocker.release();
        await running;
        assert.deepStrictEqual(events.ops(), []);
        assert.strictEqual(ptz.messages.length, 0);
    } finally {
        blocker.release();
        await running;
        await events.close();
    }
}]);

for (const [phase, script] of [
    ['discovery', { GetCapabilities: () => HOLD }],
    ['subscription creation', { CreatePullPointSubscription: () => HOLD }],
]) {
    tests.push([`PTZ interruption during ${phase} cancels the request and starts nothing new`, async () => {
        const events = await eventFixture({ script });
        let release;
        try {
            events.input('start');
            const op = phase === 'discovery' ? 'GetCapabilities' : 'CreatePullPointSubscription';
            await waitFor(() => events.ops().includes(op));
            const held = events.seen[events.seen.length - 1];
            release = await events.client.interruptOnvifForPtz(events.ip);
            assert.strictEqual(held.destroyed, true);
            const count = events.created.length;
            await delay(400);
            assert.strictEqual(events.created.length, count);
        } finally { if (release) release(); await events.close(); }
    }]);
}

tests.push(['PTZ interruption during renewal of a reused subscription, which also avoids a second Create', async () => {
    const events = await eventFixture({ script: { Renew: () => HOLD } });
    let release;
    try {
        events.input('start');
        await waitFor(() => events.ops().includes('PullMessages'));
        await events.send(events.client.COMMANDS['privacy-on']);
        await events.send(events.client.COMMANDS['privacy-off']);
        await waitFor(() => events.ops().includes('Renew'));
        const held = events.seen[events.seen.length - 1];
        release = await events.client.interruptOnvifForPtz(events.ip);
        assert.strictEqual(held.destroyed, true);
        const count = events.created.length;
        await delay(400);
        assert.strictEqual(events.created.length, count);
        assert.strictEqual(events.ops().filter(op => op === 'CreatePullPointSubscription').length, 1);
    } finally { if (release) release(); await events.close(); }
}]);

tests.push(['PTZ interruption during cleanup Unsubscribe cancels it', async () => {
    const events = await eventFixture({ script: { Unsubscribe: () => HOLD } });
    let release;
    try {
        events.input('start');
        await waitFor(() => events.ops().includes('PullMessages'));
        events.input('stop');
        await waitFor(() => events.ops().includes('Unsubscribe'));
        const held = events.seen[events.seen.length - 1];
        release = await events.client.interruptOnvifForPtz(events.ip);
        assert.strictEqual(held.destroyed, true);
    } finally { if (release) release(); await events.close(); }
}]);

tests.push(['PTZ arriving between ONVIF requests prevents the next one from starting', async () => {
    const events = await eventFixture();
    let release;
    try {
        events.camera.onCommand = async () => { await delay(200); return {}; };
        events.input('start');
        await waitFor(() => events.ops().includes('GetCapabilities') && events.camera.commands.length === 1);
        release = await events.client.interruptOnvifForPtz(events.ip);
        await delay(600);
        assert.deepStrictEqual(events.ops(), ['GetCapabilities']);
    } finally { if (release) release(); await events.close(); }
}]);

tests.push(['stopping while a handoff is queued leaves no lease holding HTTPS', async () => {
    const events = await eventFixture();
    try {
        const blocker = await events.realAcquire(events.ip);
        events.input('start');
        await waitFor(() => events.acquireCalls() === 1);
        events.input('stop');
        await delay(50);
        blocker.release();
        const started = performance.now();
        const next = await events.realAcquire(events.ip, { waitMs: 400 });
        assert(next && performance.now() - started < 300, 'a cancelled handoff must not hold the HTTPS queue');
        next.release();
        assert.strictEqual(events.created.length, 0);
    } finally { await events.close(); }
}]);

tests.push(['confirmed privacy-on at startup takes no lease and sends no ONVIF traffic', async () => {
    const events = await eventFixture({ autoStart: true, privacy: 'on' });
    try {
        await waitFor(() => events.statuses.includes('privacy — idle'));
        await delay(100);
        assert.strictEqual(events.acquireCalls(), 0);
        assert.strictEqual(events.created.length, 0);
    } finally { await events.close(); }
}]);

tests.push(['stopping startup cancels the queued privacy query', async () => {
    let blocker;
    const events = await eventFixture({ autoStart: true, beforeNode: async base => {
        blocker = await base.client.acquireLease(base.ip);
    } });
    try {
        await new Promise(resolve => events.node.emit('input', { action: 'stop' }, null, resolve));
        blocker.release();
        await delay(50);
        assert.deepStrictEqual(events.camera.requests, []);
        assert.deepStrictEqual(events.ops(), []);
    } finally { blocker.release(); await events.close(); }
}]);

tests.push(['SOAP transport settles real HTTP responses, tracking errors and overloads', async () => {
    const { soapPost } = require('../lib/onvif-soap');
    const server = http.createServer((request, response) => {
        request.resume();
        if (request.url === '/overload') {
            response.writeHead(503, { 'Retry-After': '120' });
            response.end('<Fault>busy</Fault>');
        } else response.end('<PullMessagesResponse/>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}`;
    try {
        assert.strictEqual(await soapPost(url + '/ok', '<Envelope/>', 1000), '<PullMessagesResponse/>');
        await assert.rejects(soapPost(url + '/overload', '<Envelope/>', 1000),
            error => error.httpStatus === 503 && error.retryAfterMs === 120000);
        await assert.rejects(soapPost(url + '/track-error', '<Envelope/>', 1000, () => { throw new Error('tracking failed'); }),
            /tracking failed/);
    } finally { await new Promise(resolve => server.close(resolve)); }
}]);

tests.push(['transient subscription SOAP faults retain the existing pull-point', async () => {
    let pulls = 0;
    const events = await eventFixture({ script: { PullMessages: () => (++pulls === 1
        ? '<s:Fault><s:Reason>temporarily busy</s:Reason></s:Fault>' : HOLD) } });
    try {
        events.input('start');
        await waitFor(() => pulls === 2, 9000);
        assert.strictEqual(events.ops().filter(op => op === 'CreatePullPointSubscription').length, 1);
        assert(events.ops().includes('Renew'));
    } finally { await events.close(); }
}]);

for (const [name, setup] of [
    ['missing lens-mask field', camera => { camera.privacy = undefined; }],
    ['unavailable HTTPS API', camera => { camera.onLogin = async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); }; }],
]) {
    tests.push([`unknown privacy (${name}) is not treated as off`, async () => {
        const events = await eventFixture();
        try {
            setup(events.camera);
            events.input('start');
            await waitFor(() => events.warns.some(message => /Privacy check failed/.test(message)));
            await delay(300);
            assert.deepStrictEqual(events.ops(), ['GetCapabilities']);
        } finally { await events.close(); }
    }]);
}

tests.push(['unknown periodic privacy recheck withholds pulls until confirmed off again', async () => withMonotonicClock(async shift => {
    const firstPull = deferred();
    let pulls = 0;
    const events = await eventFixture({ script: { PullMessages: () => {
        pulls++;
        if (pulls === 1) { firstPull.resolve(); return '<PullMessagesResponse/>'; }
        return HOLD;
    } } });
    try {
        events.input('start');
        await firstPull.promise;
        events.camera.privacy = undefined;
        shift(301000);
        await waitFor(() => events.camera.commands.filter(method => method === 'getLensMaskConfig').length >= 2);
        await delay(400);
        assert.strictEqual(pulls, 1, 'Unknown privacy must not reuse an old off result');
        assert(events.warns.some(message => /Privacy check failed/.test(message)));
        events.camera.privacy = 'off';
        await waitFor(() => pulls === 2, 8000);
    } finally { await events.close(); }
})]);

tests.push(['transient pull failure renews the existing subscription instead of creating another', async () => {
    let pulls = 0;
    const events = await eventFixture({ script: { PullMessages: () => (++pulls === 1 ? { status: 500, body: '' } : HOLD) } });
    try {
        events.input('start');
        await waitFor(() => pulls === 2, 12000);
        const ops = events.ops();
        assert.strictEqual(ops.filter(op => op === 'CreatePullPointSubscription').length, 1);
        assert.strictEqual(ops.filter(op => op === 'Renew').length, 1);
    } finally { await events.close(); }
}]);

for (const interrupted of [false, true]) {
    tests.push([`uncertain subscription creation after ${interrupted ? 'PTZ cancellation' : 'transport failure'} is not repeated before expiry`, async () => withMonotonicClock(async shift => {
        let creates = 0;
        const events = await eventFixture({ script: { CreatePullPointSubscription: request => {
            if (++creates > 1) return ONVIF_DEFAULTS.CreatePullPointSubscription;
            if (!interrupted) request.destroy(new Error('lost subscription response'));
            return HOLD;
        } } });
        let release;
        try {
            events.input('start');
            await waitFor(() => creates === 1);
            if (interrupted) {
                release = await events.client.interruptOnvifForPtz(events.ip);
                release();
                await delay(3300);
            } else {
                await waitFor(() => events.warns.some(message => /CreateSubscription failed/.test(message)));
            }
            events.input('stop');
            await waitFor(() => events.statuses[events.statuses.length - 1] === 'stopped');
            events.input('start');
            await delay(700);
            assert.strictEqual(creates, 1, 'Restarting must not allocate another possibly-live pull-point');
            events.input('stop');
            await waitFor(() => events.statuses[events.statuses.length - 1] === 'stopped');
            shift(121000);
            events.input('start');
            await waitFor(() => events.ops().includes('PullMessages'));
            assert.strictEqual(creates, 2, 'Creation should recover after the uncertain subscription expires');
        } finally { if (release) release(); await events.close(); }
    })]);
}

tests.push(['failed subscription unsubscribe retains the pull-point across restart', async () => {
    let unsubscribes = 0;
    const events = await eventFixture({ script: { Unsubscribe: () => {
        if (++unsubscribes === 1) return '<s:Fault><s:Reason>temporarily busy</s:Reason></s:Fault>';
        return ONVIF_DEFAULTS.Unsubscribe;
    } } });
    try {
        events.input('start');
        await waitFor(() => events.ops().includes('PullMessages'));
        events.input('stop');
        await waitFor(() => events.statuses[events.statuses.length - 1] === 'stopped');
        events.input('start');
        await waitFor(() => events.ops().filter(op => op === 'PullMessages').length === 2);
        assert.strictEqual(events.ops().filter(op => op === 'CreatePullPointSubscription').length, 1);
        assert(events.ops().includes('Renew'));
    } finally { await events.close(); }
}]);

tests.push(['backward wall-clock jump does not stretch the minimum pull interval', async () => withWallClock(async shift => {
    let pulls = 0;
    const events = await eventFixture({ script: { PullMessages: () => {
        if (++pulls === 1) shift(-3600000);
        return pulls < 3 ? '<PullMessagesResponse/>' : HOLD;
    } } });
    try {
        events.input('start');
        await waitFor(() => pulls >= 2, 4000);
    } finally { await events.close(); }
})]);

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

tests.push(['identical setters share running and opt-in recent results without a barrier', async () => {
    const { client, camera, send } = fixture();
    client._limits.repeatWindowMs = 3000;
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

tests.push(['completed setters are resent after an external controller changes the state', async () => {
    const { client, camera, send } = fixture();
    assert.strictEqual(client._limits.repeatWindowMs, 0);
    await send(client.COMMANDS['led-on']);
    camera.setting = 'off';
    await send(client.COMMANDS['led-on']);
    assert.deepStrictEqual(camera.commands, ['setLedStatus', 'setLedStatus']);
    assert.strictEqual(camera.setting, 'on');
}]);

tests.push(['detection polling shares concurrent and recent samples', async () => {
    const { client, camera, ip } = fixture();
    const poll = () => client.getDetections(ip, 'test-user', password, 5);
    await Promise.all(Array.from({ length: 20 }, poll));
    await poll();
    assert.deepStrictEqual(camera.commands, ['searchDetectionList']);
}]);

for (const source of ['external', 'command']) {
    tests.push([`${source} privacy clears active motion exactly once`, async () => withMonotonicClock(async shift => {
        let pulls = 0;
        const events = await eventFixture({ script: { PullMessages: () => {
            if (++pulls > 1) return HOLD;
            return '<PullMessagesResponse>' + ['Motion', 'Person'].map(topic =>
                `<NotificationMessage><Topic>${topic}</Topic>`
                + '<Message><tt:Message PropertyOperation="Changed"><Data>'
                + '<SimpleItem Name="Detected" Value="true"/>'
                + '</Data></tt:Message></Message></NotificationMessage>').join('') + '</PullMessagesResponse>';
        } } });
        try {
            events.input('start');
            await waitFor(() => events.messages.length === 2);
            if (source === 'external') {
                events.camera.privacy = 'on';
                shift(301000);
            } else await events.send(events.client.COMMANDS['privacy-on']);
            await waitFor(() => events.messages.length === 4);
            assert.deepStrictEqual(events.messages.map(message => message.payload.detected), [true, true, false, false]);
            assert.deepStrictEqual(events.messages.slice(2).map(message => message.payload.property), ['privacy', 'privacy']);
            assert.strictEqual(pulls, 1, 'privacy must stop event polling');
        } finally { await events.close(); }
    })]);
}

tests.push(['false Initialized events do not prolong an active motion watchdog', async () => {
    let pulls = 0;
    const events = await eventFixture({ eventConfig: { motionTimeout: 1 }, script: { PullMessages: () => {
        if (++pulls > 2) return HOLD;
        return '<PullMessagesResponse><NotificationMessage><Topic>Motion</Topic>'
            + '<Message><tt:Message PropertyOperation="Initialized"><Data>'
            + `<SimpleItem Name="IsMotion" Value="${pulls === 1}"/>`
            + '</Data></tt:Message></Message></NotificationMessage></PullMessagesResponse>';
    } } });
    try {
        events.input('start');
        await waitFor(() => events.messages.some(message => message.payload.detected), 3000);
        await waitFor(() => events.messages.some(message => message.payload.detected === false), 1800);
        assert.deepStrictEqual(events.messages.map(message => message.payload.detected), [true, false]);
    } finally { await events.close(); }
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

tests.push(['HTTPS commands pause the ONVIF pull and polling resumes afterwards', async () => {
    const events = await eventFixture({ autoStart: true });
    events.client._limits.httpsResumeMs = 50;
    try {
        await waitFor(() => events.ops().includes('PullMessages'));
        const pull = events.seen.find(request => request.op === 'PullMessages');
        let pausedAtCommand;
        events.camera.onCommand = async () => { pausedAtCommand = pull.destroyed; return {}; };
        await events.send(events.client.COMMANDS['led-on']);
        assert.strictEqual(pausedAtCommand, true);
        await waitFor(() => events.ops().filter(op => op === 'PullMessages').length >= 2);
    } finally { await events.close(); }
}]);

tests.push(['PTZ Stop without a recent move respects the reboot cooldown', async () => {
    const events = await eventFixture();
    try {
        events.client._limits.startupRebootGuardMs = 0;
        await events.send(events.client.COMMANDS.reboot);
        const ptz = events.createPtz();
        assert((await ptz.send('stop')) instanceof Error);
        assert.deepStrictEqual(events.ops(), []);
    } finally { await events.close(); }
}]);

tests.push(['PTZ Stop after a delivered move is sent once despite a cooldown', async () => {
    const events = await eventFixture();
    try {
        events.client._limits.startupRebootGuardMs = 0;
        events.client._limits.ptzGapMs = 10;
        const ptz = events.createPtz();
        await ptz.send('continuousMove');
        await events.send(events.client.COMMANDS.reboot);
        assert.strictEqual(await ptz.send('stop'), undefined);
        assert((await ptz.send('stop')) instanceof Error);
        assert.strictEqual(events.ops().filter(op => op === 'Stop').length, 1);
    } finally { await events.close(); }
}]);

tests.push(['an undelivered move does not open the urgent Stop window', async () => {
    const events = await eventFixture();
    try {
        events.client._limits.ptzMaxAgeMs = 40;
        const blocker = await events.realAcquire(events.ip);
        const ptz = events.createPtz();
        try { assert((await ptz.send('continuousMove')) instanceof Error); } finally { blocker.release(); }
        events.client._limits.startupRebootGuardMs = 0;
        await events.send(events.client.COMMANDS.reboot);
        assert((await ptz.send('stop')) instanceof Error);
        assert.deepStrictEqual(events.ops(), []);
    } finally { await events.close(); }
}]);

const separateAccounts = { username: 'onvif-user', credentials: { password: 'separate-onvif-password' } };

tests.push(['event privacy guard uses the configured HTTPS device credentials', async () => {
    const events = await eventFixture({ autoStart: true, onvifDevice: separateAccounts, eventConfig: { tapoDevice: 'test-https-device' } });
    try {
        await waitFor(() => events.ops().includes('CreatePullPointSubscription'));
        assert(!events.warns.some(message => /Privacy check failed/.test(message)));
    } finally { await events.close(); }
}]);

tests.push(['event privacy guard falls back to the ONVIF credentials without an HTTPS device', async () => {
    const events = await eventFixture({ autoStart: true, onvifDevice: separateAccounts });
    try {
        await waitFor(() => events.warns.some(message => /Privacy check failed/.test(message)));
        assert(!events.ops().includes('CreatePullPointSubscription'));
    } finally { await events.close(); }
}]);

(async () => {
    let failures = 0;
    const selected = tests.filter(([name]) => name.includes(process.env.TEST_FILTER || ''));
    assert(selected.length > 0, 'No tests matched TEST_FILTER');
    try {
        for (const [name, test] of selected) {
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
    console.log(`${selected.length - failures} passed, ${failures} failed`);
    process.exitCode = failures ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });