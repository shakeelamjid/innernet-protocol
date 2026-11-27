/* INNERNET Send: the sender's page. Seals the file here, deposits the keeper share and the rules,
   uploads the sealed parts, then shows the link and the PIN. */
(function () {
  'use strict';
  const C = window.InnernetSend, St = window.InnernetSendStore, $ = function (id) { return document.getElementById(id); };
  const PRESETS = { private: { keep: 'max', opens: '1', forward: '0' }, working: { keep: 'max', opens: '0', forward: '1' }, fading: { keep: 'fade', opens: '0', forward: '0' } };
  let lim = null, busy = false;

  function say(id, text, err) { $(id).textContent = text || ''; $(id).classList.toggle('error', !!err); }
  function days(s) { return s === 86400 ? '1 day' : Math.round(s / 86400) + ' days'; }

  function rulesNote() {
    const keep = $('keep').value, opens = $('opens').value, fwd = $('forward').value === '1';
    const life = keep === 'fade'
      ? 'It fades: each day it is half as likely to still open, and it is gone within ' + days(Math.max.apply(null, lim.keeps)) + '.'
      : 'After ' + days(Number(keep)) + ' it is destroyed.';
    const open = opens === '1' ? 'It opens once, then it is destroyed.' : opens === '3' ? 'It opens 3 times, then it is destroyed.' : 'It opens any number of times until then.';
    $('rules-note').textContent = life + ' ' + open + ' ' + (fwd ? 'Anyone with the link and the PIN can open it.' : 'Only the first device that opens it can open it again.');
    document.querySelectorAll('[data-preset]').forEach(function (b) {
      const p = PRESETS[b.dataset.preset], k = p.keep === 'max' ? String(Math.max.apply(null, lim.keeps)) : p.keep;
      b.setAttribute('aria-pressed', String(k === keep && p.opens === opens && p.forward === $('forward').value));
    });
  }
  function preset(name) {
    const p = PRESETS[name];
    $('keep').value = p.keep === 'max' ? String(Math.max.apply(null, lim.keeps)) : p.keep;
    $('opens').value = p.opens; $('forward').value = p.forward;
    rulesNote();
  }

  async function send(file) {
    const id = C.newId(), secret = C.random(32), share = C.random(32), pin = C.newPin();
    const device = await St.deviceKey();
    say('msg', 'Sealing…');
    const keys = await C.linkKeys(secret, id);
    const key = await C.fileKey(secret, share, pin, id);
    const parts = C.partCount(file.size);
    const fade = $('keep').value === 'fade';
    const keep = fade ? Math.max.apply(null, lim.keeps) : Number($('keep').value);
    const made = await (await St.api('POST', '/files', {
      id: id, size: file.size + parts * C.TAG, parts: parts, keep: keep, fade: fade, max_opens: Number($('opens').value),
      forward: $('forward').value === '1', auth_hash: keys.authHash, pin_tag: await C.pinTag(keys, pin),
      owner_pub: await C.publicRaw(device), keeper_share: C.b64u(share),
      preview: await C.sealSmall(keys.preview, id, 'preview', { from: $('from').value.trim(), note: $('note').value.trim() }),
      meta: await C.sealSmall(key, id, 'meta', { name: file.name, type: file.type || 'application/octet-stream', size: file.size })
    })).json();
    for (let n = 0; n < parts; n++) {
      say('msg', 'Sealing and storing: ' + Math.round(100 * n / parts) + '%');
      const plain = new Uint8Array(await file.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer());
      await St.api('PUT', '/files/' + id + '/parts/' + n, await C.sealPart(key, id, n, parts, plain), { 'X-Send-Upload': made.upload, 'Content-Type': 'application/octet-stream' });
    }
    const link = location.origin + St.BASE + '/send/o/' + id + '#' + C.b64u(secret);
    const rec = { id: id, name: file.name, size: file.size, created_at: Math.floor(Date.now() / 1000), expires_at: made.expires_at, link: link, pin: pin,
      rules: { max_opens: Number($('opens').value), fade: fade, forward: $('forward').value === '1', expires_at: made.expires_at } };
    await St.remember(rec);
    return rec;
  }

  function showDone(rec) {
    $('link').textContent = rec.link; $('pin').textContent = rec.pin;
    $('done-rules').textContent = St.rulesLine(rec.rules);
    $('form').hidden = true; $('done').hidden = false;
    $('done').scrollIntoView({ block: 'start' });
  }

  async function act(rec, action) {
    const d = await St.deviceKey();
    return (await St.api('POST', '/files/' + rec.id + '/' + action, await C.signRequest(d, action, rec.id))).json();
  }
  function line(tag, text, cls) { const e = document.createElement(tag); e.textContent = text; if (cls) e.className = cls; return e; }

  async function renderSent() {
    const list = (await St.sent()).sort(function (a, b) { return b.created_at - a.created_at; });
    $('sent-card').hidden = !list.length;
    $('sent').textContent = '';
    list.forEach(function (rec) {
      const li = document.createElement('li');
      const head = document.createElement('div'); head.className = 'sent-head';
      head.append(line('strong', rec.name), line('span', St.size(rec.size) + ' · sent ' + St.when(rec.created_at), 'dim'));
      const state = line('p', 'Checking…', 'msg');
      const acts = document.createElement('div'); acts.className = 'row-actions';
      const back = line('button', 'Take it back', 'btn btn-sm btn-danger'); back.type = 'button';
      const copy = line('button', 'Copy link', 'btn btn-sm'); copy.type = 'button';
      const forget = line('button', 'Remove from this list', 'btn btn-sm'); forget.type = 'button';
      acts.append(copy, back, forget);
      li.append(head, state, acts);
      $('sent').append(li);
      function show(s) {
        const opened = s.events.filter(function (e) { return e.event === 'opened'; });
        let text;
        if (s.state === 'dead') text = 'Destroyed: ' + s.reason + '.';
        else if (s.state === 'spent') text = 'Opened; no more openings. It is being destroyed.';
        else text = St.rulesLine(s) + ' PIN ' + rec.pin + '.';
        if (opened.length) text += ' Opened ' + opened.map(function (e) { return St.when(e.ts); }).join(', ') + '.';
        else if (s.state !== 'dead') text += ' Not opened yet.';
        if (s.pin_fails) text += ' Wrong PIN tried ' + s.pin_fails + ' time' + (s.pin_fails > 1 ? 's' : '') + '.';
        state.textContent = text;
        back.hidden = copy.hidden = s.state === 'dead';
      }
      act(rec, 'status').then(show).catch(function (e) {
        state.textContent = e.status === 404 ? 'No longer on record (ended more than 30 days ago).' : e.message;
        back.hidden = copy.hidden = e.status === 404;
      });
      copy.addEventListener('click', function () { navigator.clipboard.writeText(rec.link).then(function () { copy.textContent = 'Copied'; }); });
      back.addEventListener('click', function () {
        back.disabled = true;
        act(rec, 'revoke').then(function () { return act(rec, 'status'); }).then(show).catch(function (e) { state.textContent = e.message; back.disabled = false; });
      });
      forget.addEventListener('click', function () { St.forget(rec.id).then(renderSent); });
    });
  }

  async function start() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      $('off').textContent = 'This browser cannot seal files (it needs a secure https page and a current browser).'; $('off').hidden = false; $('form').hidden = true; return;
    }
    lim = await (await St.api('GET', '/limits')).json();
    if (!lim.on) { $('off').textContent = 'Sending files is switched off on this registry for now.'; $('off').hidden = false; $('form').hidden = true; }
    lim.keeps.forEach(function (k) { const o = document.createElement('option'); o.value = String(k); o.textContent = days(k); $('keep').append(o); });
    const f = document.createElement('option'); f.value = 'fade'; f.textContent = 'Let it fade'; $('keep').append(f);
    say('file-msg', 'Up to ' + St.size(lim.max_bytes) + ', free. Larger files and longer lifetimes will need a wallet (not open yet).');
    preset('private');
    ['keep', 'opens', 'forward'].forEach(function (id) { $(id).addEventListener('change', rulesNote); });
    document.querySelectorAll('[data-preset]').forEach(function (b) { b.addEventListener('click', function () { preset(b.dataset.preset); }); });
    document.querySelectorAll('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () { navigator.clipboard.writeText($(b.dataset.copy).textContent).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); }); });
    });
    $('again').addEventListener('click', function () { $('done').hidden = true; $('form').hidden = false; $('form').reset(); preset('private'); say('msg', ''); });
    $('form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) return;
      const file = $('file').files[0];
      if (!file) return say('msg', 'Choose a file first.', true);
      if (!file.size) return say('msg', 'That file is empty.', true);
      if (file.size > lim.max_bytes) return say('msg', 'That file is ' + St.size(file.size) + '. The largest file is ' + St.size(lim.max_bytes) + '.', true);
      if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true);
      busy = true; $('go').disabled = true;
      send(file).then(function (rec) { say('msg', ''); showDone(rec); return renderSent(); })
        .catch(function (e) { say('msg', 'Not sent: ' + e.message, true); })
        .finally(function () { busy = false; $('go').disabled = false; });
    });
    renderSent();
  }
  start().catch(function (e) { $('off').textContent = 'This page could not start: ' + e.message; $('off').hidden = false; });
})();
