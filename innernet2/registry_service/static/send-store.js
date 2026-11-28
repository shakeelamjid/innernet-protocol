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
  const BASE = location.pathname.replace(/\/send(\/(o|n)\/[a-z0-9-]+)?\/?$/, '');
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
  function size(n) { return n < 1024 ? n + ' B' : n < 1 << 20 ? (n / 1024).toFixed(0) + ' KB' : n < 1 << 30 ? (n / (1 << 20)).toFixed(1) + ' MB' : (n / (1 << 30)).toFixed(2) + ' GB'; }
  /* Upload sealed bytes with progress (fetch cannot report upload progress). */
  function put(path, bytes, headers, onProgress) {
    return new Promise(function (ok, bad) {
      const x = new XMLHttpRequest();
      x.open('PUT', BASE + '/send/api' + path);
      x.setRequestHeader('X-Innernet', '1');
      Object.keys(headers || {}).forEach(function (k) { x.setRequestHeader(k, headers[k]); });
      x.upload.onprogress = function (e) { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
      x.onload = function () {
        if (x.status >= 200 && x.status < 300) return ok();
        let why = 'The server answered ' + x.status + '.';
        try { const j = JSON.parse(x.responseText); if (j && j.detail) why = String(j.detail); } catch (e) { /* not JSON */ }
        const err = new Error(why); err.status = x.status; bad(err);
      };
      x.onerror = function () { bad(new Error('The connection dropped while storing.')); };
      x.send(bytes);
    });
  }
  function usdc(text) { return String(text).replace(/(\.\d\d\d*?)0+$/, '$1'); }
  /* The six steps, shown live. el: an <ol>; defs: [{title, text}]. Returns set(i, state, text, fraction). */
  function steps(el, bar, defs) {
    el.textContent = '';
    const rows = defs.map(function (d, i) {
      const li = document.createElement('li'); li.className = 'wait';
      const mk = document.createElement('span'); mk.className = 'six-n'; mk.textContent = String(i + 1);
      const body = document.createElement('div');
      const t = document.createElement('strong'); t.textContent = d.title;
      const tx = document.createElement('span'); tx.className = 'six-t'; tx.textContent = d.text || '';
      body.append(t, tx);
      let cells = null;
      if (d.cells) { cells = document.createElement('span'); cells.className = 'cells'; for (let c = 0; c < 24; c++) cells.append(document.createElement('i')); body.append(cells); }
      li.append(mk, body); el.append(li);
      return { li: li, tx: tx, cells: cells, frac: 0, state: 'wait' };
    });
    function paint() {
      let sum = 0;
      rows.forEach(function (r) { sum += r.state === 'done' ? 1 : r.state === 'run' ? r.frac : 0; });
      const pct = Math.round(100 * sum / rows.length);
      if (bar) { bar.style.setProperty('--p', pct + '%'); bar.setAttribute('aria-valuenow', pct); bar.dataset.pct = pct + '%'; }
    }
    return {
      set: function (i, state, text, frac) {
        const r = rows[i]; r.state = state; r.li.className = state;
        if (text != null) r.tx.textContent = text;
        r.frac = state === 'done' ? 1 : (frac || 0);
        if (r.cells) { const on = Math.round(24 * r.frac); Array.prototype.forEach.call(r.cells.children, function (c, k) { c.className = k < on ? 'on' : ''; }); }
        paint();
      },
      burn: function () { rows.forEach(function (r) { if (r.cells) Array.prototype.forEach.call(r.cells.children, function (c, k) { c.style.transitionDelay = (k * 40) + 'ms'; c.className = 'gone'; }); }); }
    };
  }
  function when(ts) {
    const d = new Date(ts * 1000), o = { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' };
    if (d.getFullYear() !== new Date().getFullYear()) o.year = 'numeric';
    return d.toLocaleString(undefined, o);
  }
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
  /* The sender's own box key for a send others add to: only this browser can open what they add. */
  async function boxKey(id, make) {
    let pair = await run('keys', 'readonly', function (s) { return s.get('box-' + id); });
    if (!pair && make) { pair = await C.newBoxKey(true); await run('keys', 'readwrite', function (s) { return s.put(pair, 'box-' + id); }); }
    return pair;
  }
  /* The box key travels inside the sender's sealed pack, so the sender key opens contributions on any device. */
  async function boxExport(id) {
    const pair = await boxKey(id, false);
    if (!pair || !pair.privateKey.extractable) return null;
    return { priv: C.b64u(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))), pub: C.b64u(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))) };
  }
  async function boxImport(id, box) {
    const alg = { name: 'ECDH', namedCurve: 'P-256' };
    const pair = { privateKey: await crypto.subtle.importKey('pkcs8', C.unb64u(box.priv), alg, true, ['deriveBits']), publicKey: await crypto.subtle.importKey('raw', C.unb64u(box.pub), alg, true, []) };
    await run('keys', 'readwrite', function (s) { return s.put(pair, 'box-' + id); });
  }
  function download(name, blob) {
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 60000);
  }
  async function bytes(method, path, body, headers) { return new Uint8Array(await (await api(method, path, body, headers)).arrayBuffer()); }
  /* One contribution, shown: the answers, a signature (checked here), and the attached files. */
  async function entryCell(id, got, docHash) {
    const td = document.createElement('td'), o = got.obj;
    function line(t, cls) { const d = document.createElement('div'); d.textContent = t; if (cls) d.className = cls; td.append(d); }
    Object.keys(o.answers || {}).forEach(function (k) { if (o.answers[k] !== '') line(k + ': ' + o.answers[k]); });
    if (o.sign) {
      const g = o.sign, ok = await C.verifyRequest(g.pub, 'sign:' + g.doc + ':' + C.b64u(new TextEncoder().encode(g.name)), id, g.ts, g.sig);
      line('Signed by ' + g.name + ' on ' + when(g.ts) + '.', 'signed');
      line(ok ? 'The signature checks' + (docHash ? (g.doc === docHash ? ', and it is over this exact document.' : ', but it is over a different document than the one open here.') : '. Open the document to compare it.') : 'THE SIGNATURE DOES NOT CHECK.', ok && (!docHash || g.doc === docHash) ? 'dim' : 'error');
      line('Signing key ' + g.pub.slice(0, 20) + '… · document SHA-256 ' + g.doc.slice(0, 16) + '…', 'dim');
    }
    let off = 0;
    (o.files || (o.file ? [Object.assign({ size: got.file.length }, o.file)] : [])).forEach(function (f) {
      const bytes = got.file.subarray(off, off + f.size); off += f.size;
      const b = document.createElement('button'); b.type = 'button'; b.className = 'btn btn-sm'; b.textContent = 'Save ' + f.name + ' (' + size(f.size) + ')';
      b.addEventListener('click', function () { download(f.name, new Blob([bytes], { type: f.type })); }); td.append(b);
    });
    return td;
  }
  /* The ways to pay an exact USDC amount: a QR and a link for a phone wallet (EIP-681). */
  function payWays(qrEl, linkEl, pay) {
    const uri = 'ethereum:' + pay.usdc + '@' + pay.chain_id + '/transfer?address=' + pay.to + '&uint256=' + pay.micro;
    qrEl.textContent = ''; if (window.InnernetQR) qrEl.append(window.InnernetQR.svg(uri, 150));
    linkEl.href = uri;
  }
  window.InnernetSendStore = { boxExport: boxExport, boxImport: boxImport, entryCell: entryCell, payWays: payWays, boxKey: boxKey, download: download, bytes: bytes,
    BASE: BASE, api: api, put: put, usdc: usdc, steps: steps, deviceKey: deviceKey, size: size, when: when, left: left, rulesLine: rulesLine,
    sent: function () { return run('sent', 'readonly', function (s) { return s.getAll(); }); },
    remember: function (rec) { return run('sent', 'readwrite', function (s) { return s.put(rec, rec.id); }); },
    forget: function (id) { return run('sent', 'readwrite', function (s) { return s.delete(id); }); }
  };
})();
