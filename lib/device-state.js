'use strict';

const fs = require('fs');
const path = require('path');

module.exports = function createDeviceState() {
    let file = null;
    let records = new Map();
    let warn = () => {};
    let warned = false;

    function report(error) {
        if (warned) return;
        warned = true;
        warn('Tapo restart protection could not access its state file: ' + error.message);
    }

    return {
        configure(userDir, onWarning = () => {}) {
            if (!userDir || file) return;
            file = path.join(userDir, 'tapo-local-state.json');
            warn = onWarning;
            try {
                if (fs.statSync(file).size > 256 * 1024) throw new Error('state file exceeds size limit');
                const data = JSON.parse(fs.readFileSync(file, 'utf8'));
                if (data.version !== 1 || !Array.isArray(data.records)) throw new Error('invalid state format');
                records = new Map(data.records.filter(entry => Array.isArray(entry) && typeof entry[0] === 'string'
                    && entry[1] && Number.isFinite(entry[1].until) && entry[1].until > Date.now()).slice(-256));
            } catch (error) {
                if (error.code !== 'ENOENT') report(error);
            }
        },
        get(key) { return records.get(key); },
        set(key, value) {
            const previous = records.get(key);
            if ((!previous && !value) || (previous && value && JSON.stringify(previous) === JSON.stringify(value))) return;
            records.delete(key);
            if (value) records.set(key, value);
            for (const [name, record] of records) if (record.until <= Date.now()) records.delete(name);
            while (records.size > 256) records.delete(records.keys().next().value);
            if (!file) return;
            try {
                const temporary = file + '.tmp';
                fs.writeFileSync(temporary, JSON.stringify({ version: 1, records: [...records] }), { mode: 0o600 });
                fs.chmodSync(temporary, 0o600);
                fs.renameSync(temporary, file);
            } catch (error) { report(error); }
        },
    };
};