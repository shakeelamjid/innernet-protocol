/* INNERNET Send: what this browser remembers. The device key cannot be exported; it stays in this
   browser's IndexedDB. The list of sent files (with their links and PINs) is kept so the sender can
   see what happened to them and take them back. */
(function () {
  'use strict';
  const C = window.InnernetSend;
  function db() {
    return new Promise(function (ok, bad) {
      const r = indexedDB.open('innernet-send', 1);
      r.onupgradeneeded = function () { r.result.createObjectStore('keys'); r.result.createObjectStore('sent'); };
      r.onsuccess = function () { ok(r.result); }; r.onerror = function () { bad(r.error); };
    });
  }
  function run(store, mode, fn) {
    return db().then(function (d) {
      return new Promise(function (ok, bad) {
        const t = d.transaction(store, mode); const q = fn(t.objectStore(store));
        t.oncomplete = function () { ok(q && q.result); }; t.onerror = function () { bad(t.error); };
      });
    });
  }
  async function deviceKey() {
    let pair = await run('keys', 'readonly', function (s) { return s.get('device'); });
    if (!pair) {
      pair = await C.newDeviceKey(false);
      await run('keys', 'readwrite', function (s) { return s.put(pair, 'device'); });
    }
    return pair;
  }
  const BASE = location.pathname.replace(/\/send(\/o\/[0-9a-f]+)?\/?$/, '');
  async function api(method, path, body, headers) {
    const h = Object.assign({ 'X-Innernet': '1' }, headers || {});
    let payload = body;
    if (body && !(body instanceof Uint8Array)) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    const r = await fetch(BASE + '/send/api' + path, { method: method, headers: h, body: payload, credentials: 'omit', cache: 'no-store' });
    if (!r.ok) {
      let why = 'The server answered ' + r.status + '.';
      try { const j = await r.json(); if (j && j.detail) why = String(j.detail); } catch (e) { /* not JSON */ }
      const err = new Error(why); err.status = r.status; throw err;
    }
    return r;
  }
  function size(n) { return n < 1024 ? n + ' B' : n < 1 << 20 ? (n / 1024).toFixed(0) + ' KB' : (n / (1 << 20)).toFixed(1) + ' MB'; }
  function when(ts) { return new Date(ts * 1000).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); }
  function left(ts) {
    const s = ts - Date.now() / 1000;
    if (s <= 0) return 'now';
    if (s < 3600) return Math.ceil(s / 60) + ' min';
    if (s < 2 * 86400) return Math.ceil(s / 3600) + ' hours';
    return Math.ceil(s / 86400) + ' days';
  }
  function rulesLine(r) {
    const bits = [r.max_opens === 1 ? 'Opens once' : r.max_opens ? 'Opens ' + r.max_opens + ' times' : 'Opens any number of times'];
    bits.push(r.fade ? 'Fading: half as likely to open each day, gone within ' + left(r.expires_at) : 'Expires in ' + left(r.expires_at));
    bits.push(r.forward ? 'May be passed on' : 'Not for passing on');
    return bits.join('. ') + '.';
  }
  window.InnernetSendStore = {
    BASE: BASE, api: api, deviceKey: deviceKey, size: size, when: when, left: left, rulesLine: rulesLine,
    sent: function () { return run('sent', 'readonly', function (s) { return s.getAll(); }); },
    remember: function (rec) { return run('sent', 'readwrite', function (s) { return s.put(rec, rec.id); }); },
    forget: function (id) { return run('sent', 'readwrite', function (s) { return s.delete(id); }); }
  };
})();
