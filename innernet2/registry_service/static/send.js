/* INNERNET Send: the sender's page. Seals a file or a note here, deposits the keeper part and the
   rules (paying first when something was added), stores the sealed parts, then shows link and PIN.
   The six steps on screen are the steps this code takes, in this order. */
(function () {
  'use strict';
  const C = window.InnernetSend, St = window.InnernetSendStore, W = window.InnernetWallet;
  const $ = function (id) { return document.getElementById(id); };
  const calm = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  let lim = null, busy = false, picked = null, timer = null, quoted = { micro: 0, lines: [], total: '0' }, stopPay = null;

  function say(id, text, err) { $(id).textContent = text || ''; $(id).classList.toggle('error', !!err); }
  function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }
  function pause(ms) { return calm ? Promise.resolve() : new Promise(function (ok) { setTimeout(ok, ms); }); }
  function kind() { return document.querySelector('input[name=kind]:checked').value; }
  function words(t) { const m = t.trim().match(/\S+/g); return m ? m.length : 0; }
  function days(s) { const d = Math.round(s / 86400); return d === 1 ? '1 day' : d + ' days'; }

  function content() {
    if (kind() === 'note') {
      const text = $('text').value.trim();
      const bytes = new TextEncoder().encode(text);
      return { kind: 'note', name: 'Note', type: 'text/plain;charset=utf-8', size: bytes.length, blob: new Blob([bytes]), words: words(text) };
    }
    return picked ? { kind: 'file', name: picked.name, type: picked.type || 'application/octet-stream', size: picked.size, blob: picked } : null;
  }
  function opts() {
    const d = Math.min(365, Math.max(1, parseInt($('o-days').value, 10) || lim.free_keep / 86400));
    const after = $('o-after').value ? Math.floor(new Date($('o-after').value).getTime() / 1000) : 0;
    return { keep: d * 86400, max_opens: $('o-any').checked ? 0 : Math.min(1000, Math.max(1, parseInt($('o-opens').value, 10) || 1)),
      forward: $('o-forward').checked, open_after: after || 0, receipt: $('o-receipt').checked, reply: $('o-reply').checked, control: $('o-control').checked };
  }
  /* What the chosen rules mean, in plain words. Used in step 3 and on the done card. */
  function commentary(o, end) {
    const out = [];
    out.push((o.max_opens === 1 ? 'Opens once' : o.max_opens ? 'Opens ' + o.max_opens + ' times' : 'Opens any number of times')
      + (o.forward ? ', on any device that has link and PIN.' : ', only on the first device that opens it.'));
    if (o.open_after) out.push('The keeper holds its part until ' + St.when(o.open_after) + '. Before that, link and PIN open nothing.');
    out.push(o.max_opens === 1 ? 'Destroyed right after that opening, or on ' + St.when(end) + ' if unopened.' : 'Destroyed on ' + St.when(end) + ', unless you extend it before then.');
    if (o.receipt) out.push('You see the time of each opening here.');
    if (o.reply) out.push('The receiver can send you one sealed reply.');
    if (o.control) out.push('You can take it back while it is waiting.');
    return out;
  }

  function requote() {
    clearTimeout(timer);
    timer = setTimeout(async function () {
      const c = content();
      try {
        quoted = await (await St.api('POST', '/quote', Object.assign({ plain: (c && c.size) || 1, kind: kind() }, opts()))).json();
        say('msg', '');
      } catch (e) { quoted = { micro: 0, lines: [], total: '0', error: e.message }; say('msg', e.message, true); }
      $('meter-lines').textContent = '';
      quoted.lines.forEach(function (l) { const li = el('li'); li.append(el('span', l.label), el('span', St.usdc(l.usdc))); $('meter-lines').append(li); });
      $('meter-total').textContent = quoted.micro ? St.usdc(quoted.total) + ' USDC' : 'Free';
      $('go').textContent = quoted.micro ? 'Pay ' + St.usdc(quoted.total) + ' USDC, then seal and send' : 'Seal and send, free';
      $('go').disabled = busy || !!quoted.error;
    }, 200);
  }

  async function act(id, action, extra) {
    const d = await St.deviceKey();
    return (await St.api('POST', '/files/' + id + '/' + action, Object.assign(await C.signRequest(d, action, id), extra || {}))).json();
  }

  /* Show the payment box and wait until the keeper sees the payment on the chain. */
  function payment(id, pay) {
    $('pay').hidden = false;
    $('pay-amount').textContent = St.usdc(pay.amount); $('pay-exact').textContent = pay.amount;
    $('pay-net').textContent = pay.network_name; $('pay-net2').textContent = pay.network_name;
    $('pay-to').textContent = pay.to; $('pay-by').textContent = St.when(pay.pay_by);
    $('pay-wallet').hidden = !window.ethereum; $('pay-wallet').disabled = false;
    say('pay-msg', 'Waiting for the payment…');
    return new Promise(function (ok, bad) {
      let tx = null, stopped = false, t = null;
      function finish(fn, v) { stopped = true; clearTimeout(t); $('pay').hidden = true; stopPay = null; fn(v); }
      async function look() {
        if (stopped) return;
        try {
          const r = await act(id, 'pay', tx ? { tx: tx } : {});
          if (r.paid) return finish(ok, r);
          if (Date.now() / 1000 > pay.pay_by + 600) return finish(bad, new Error('the price was not paid in time; nothing was sent'));
        } catch (e) { if (e.status === 410 || e.status === 422) return finish(bad, e); say('pay-msg', e.message); }
        t = setTimeout(look, 4000);
      }
      stopPay = function () { finish(bad, new Error('cancelled; nothing was sent')); };
      $('pay-cancel').onclick = stopPay;
      $('pay-wallet').onclick = async function () {
        $('pay-wallet').disabled = true;
        try {
          say('pay-msg', 'Confirm in your wallet…');
          const from = await W.connect(pay.chain_id);
          tx = await W.request('eth_sendTransaction', [{ from: from, to: pay.usdc, data: '0xa9059cbb' + W.pad(pay.to) + BigInt(pay.micro).toString(16).padStart(64, '0') }]);
          say('pay-msg', 'Paid. Waiting for the chain to confirm…');
        } catch (e) { say('pay-msg', W.friendly(e), true); $('pay-wallet').disabled = false; }
      };
      t = setTimeout(look, 1500);
    });
  }

  async function store(id, n, sealed, upload, onProgress) {
    for (let tries = 0; ; tries++) {
      try { return await St.put('/files/' + id + '/parts/' + n, sealed, { 'X-Send-Upload': upload, 'Content-Type': 'application/octet-stream' }, onProgress); }
      catch (e) {
        if (e.status === 409 && e.message.indexOf('part ' + (n + 1) + ' is next') >= 0) return;     // it did arrive
        if (tries >= 4 || (e.status && e.status !== 409 && e.status < 500)) throw e;
        await new Promise(function (ok) { setTimeout(ok, 2000); });
      }
    }
  }

  async function send(c, o) {
    const steps = St.steps($('six'), $('bar'), [
      { title: 'Keys made on this device', text: 'Three random pieces: a link secret, a PIN and a keeper part.' },
      { title: 'File key built', text: 'From all three pieces together.' },
      { title: 'Rules and keeper part deposited', text: 'The keeper gets one piece and your rules. It never gets the other two.' },
      { title: 'Cut into parts', text: '' },
      { title: 'Each part sealed', text: 'AES-256-GCM, on this device.', cells: true },
      { title: 'Sealed parts stored', text: 'Only sealed bytes leave this device.', cells: true }]);
    $('six').hidden = false; $('bar').hidden = false; $('pay').hidden = true; say('work-msg', '');
    $('work-title').textContent = 'Sealing on this device';
    $('form').hidden = true; $('work').hidden = false; $('work').scrollIntoView({ block: 'start' });

    steps.set(0, 'run');
    const id = C.newId(), secret = C.random(32), share = C.random(32), pin = C.newPin();
    const device = await St.deviceKey();
    await pause(350);
    steps.set(0, 'done', 'A link secret, a 6-digit PIN and a keeper part. The first two never reach a server.');

    steps.set(1, 'run', 'Stretching the PIN 200,000 rounds, so it cannot be guessed quickly…');
    const keys = await C.linkKeys(secret, id);
    const key = await C.fileKey(secret, share, pin, id);
    await pause(250);
    steps.set(1, 'done', 'Built from link secret + PIN + keeper part. Missing any one, there is no key.');

    steps.set(2, 'run', 'Depositing the keeper part and your rules…', 0.3);
    const parts = C.partCount(c.size);
    const made = await (await St.api('POST', '/files', Object.assign({
      id: id, kind: c.kind, size: c.size + parts * C.TAG, parts: parts, auth_hash: keys.authHash, pin_tag: await C.pinTag(keys, pin),
      owner_pub: await C.publicRaw(device), keeper_share: C.b64u(share),
      preview: await C.sealSmall(keys.preview, id, 'preview', { from: $('from').value.trim(), note: $('note').value.trim() }),
      meta: await C.sealSmall(key, id, 'meta', { name: c.name, type: c.type, size: c.size, kind: c.kind })
    }, o))).json();
    const link = location.origin + St.BASE + '/send/o/' + id + '#' + C.b64u(secret);
    const rec = { id: id, name: c.name, kind: c.kind, size: c.size, created_at: Math.floor(Date.now() / 1000), expires_at: made.expires_at, link: link, pin: pin,
      parts: parts, rules: o, paid: made.pay ? made.pay.amount : null };
    await St.remember(rec);
    if (made.pay) {
      steps.set(2, 'run', 'Deposited. Waiting for your payment of ' + St.usdc(made.pay.amount) + ' USDC before anything is uploaded…', 0.6);
      await payment(id, made.pay);
    }
    steps.set(2, 'done', commentary(o, made.expires_at).join(' ') + (made.pay ? ' Paid ' + St.usdc(made.pay.amount) + ' USDC.' : ''));

    steps.set(3, 'run');
    await pause(250);
    steps.set(3, 'done', parts === 1 ? St.size(c.size) + ' fits in one part.' : St.size(c.size) + ' in ' + parts + ' parts of up to 4 MB.');

    for (let n = 0; n < parts; n++) {
      steps.set(4, 'run', 'Sealing part ' + (n + 1) + ' of ' + parts + '. Each is numbered, so none can be swapped, dropped or cut.', n / parts);
      const plain = new Uint8Array(await c.blob.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer());
      const sealed = await C.sealPart(key, id, n, parts, plain);
      steps.set(4, n + 1 === parts ? 'done' : 'run', n + 1 === parts ? 'All ' + parts + (parts === 1 ? ' part' : ' parts') + ' sealed with AES-256-GCM, numbered so none can be swapped, dropped or cut.' : null, (n + 1) / parts);
      steps.set(5, 'run', 'Storing part ' + (n + 1) + ' of ' + parts + ' with the keeper…', n / parts);
      await store(id, n, sealed, made.upload, function (f) { steps.set(5, 'run', null, (n + f) / parts); });
    }
    steps.set(5, 'done', 'Stored. The keeper holds sealed bytes and cannot read them.');
    await pause(500);
    return { rec: rec, lines: commentary(o, made.expires_at) };
  }

  function showDone(r) {
    $('link').textContent = r.rec.link; $('pin').textContent = r.rec.pin;
    $('set-lines').textContent = '';
    r.lines.forEach(function (t) { $('set-lines').append(el('li', t)); });
    $('work').hidden = true; $('done').hidden = false;
    $('done').scrollIntoView({ block: 'start' });
  }

  async function readReply(rec, sealed) {
    const keys = await C.linkKeys(C.unb64u(rec.link.split('#')[1]), rec.id);
    return (await C.openSmall(keys.preview, rec.id, 'reply', sealed)).text;
  }

  async function renderSent() {
    const list = (await St.sent()).sort(function (a, b) { return b.created_at - a.created_at; });
    $('sent-card').hidden = !list.length;
    $('sent').textContent = '';
    list.forEach(function (rec) {
      const li = el('li');
      const head = el('div', null, 'sent-head');
      const chip = el('span', 'Checking', 'chip');
      head.append(el('strong', rec.name), chip, el('span', St.size(rec.size) + ' · sent ' + St.when(rec.created_at), 'dim'));
      const state = el('p', '', 'msg'), warn = el('p', '', 'msg warn'), reply = el('p', '', 'reply');
      warn.hidden = true; reply.hidden = true;
      const acts = el('div', null, 'row-actions');
      const copy = el('button', 'Copy link', 'btn btn-sm'), more = el('button', 'Extend', 'btn btn-sm'), back = el('button', 'Take it back', 'btn btn-sm btn-danger'), forget = el('button', 'Remove from this list', 'btn btn-sm');
      const ext = el('div', null, 'inline ext'); ext.hidden = true;
      const extDays = el('input', null, 'field num'); extDays.type = 'number'; extDays.min = '1'; extDays.max = '365'; extDays.value = '30';
      const extGo = el('button', 'Get the price', 'btn btn-sm btn-light');
      ext.append(el('span', 'Add'), extDays, el('span', 'days'), extGo);
      [copy, more, back, forget, extGo].forEach(function (b) { b.type = 'button'; });
      copy.hidden = more.hidden = back.hidden = true;
      acts.append(copy, more, back, forget);
      li.append(head, state, warn, reply, acts, ext);
      $('sent').append(li);
      function show(s) {
        const opened = s.events.filter(function (e) { return e.event === 'opened'; });
        const now = Date.now() / 1000;
        let text, label;
        if (s.state === 'dead') { label = 'Destroyed'; text = 'Destroyed: ' + s.reason + '.'; }
        else if (s.state === 'spent') { label = 'Opened'; text = 'Opened' + (opened.length && opened[opened.length - 1].ts ? ' ' + St.when(opened[opened.length - 1].ts) : '') + '; no openings left. It is being destroyed.'; }
        else if (s.state === 'unpaid') { label = 'Not paid'; text = 'Waiting for payment; nothing was uploaded.'; }
        else if (s.state === 'uploading') { label = 'Not finished'; text = 'The upload did not finish (' + s.got + ' of ' + s.parts + ' parts).'; }
        else {
          label = opened.length ? 'Opened' : s.open_after > now ? 'Held' : 'Waiting';
          text = (s.open_after > now ? 'Held until ' + St.when(s.open_after) + '. ' : '') + 'PIN ' + rec.pin + '. Ends ' + St.when(s.expires_at) + '.';
        }
        if (opened.length && s.state !== 'spent') text += ' Opened' + (opened[0].ts ? ' ' + opened.map(function (e) { return St.when(e.ts); }).join(', ') : opened.length > 1 ? ' ' + opened.length + ' times' : '') + '.';
        else if (s.state === 'live') text += ' Not opened yet.';
        if (s.pin_fails) text += ' Wrong PIN tried ' + s.pin_fails + ' time' + (s.pin_fails > 1 ? 's' : '') + '.';
        if (s.paid) text += ' Paid ' + St.usdc(s.paid) + ' USDC.';
        state.textContent = text; chip.textContent = label; chip.className = 'chip ' + (s.state === 'dead' ? 'off' : opened.length ? 'on' : '');
        const live = s.state === 'live';
        copy.hidden = !live; more.hidden = !(live && lim.paid.on); back.hidden = !(live && s.control);
        const left = s.expires_at - now;
        warn.hidden = !(live && left < Math.max(86400, 0.2 * (s.expires_at - s.created_at)));
        warn.textContent = 'Ends in ' + St.left(s.expires_at) + '.' + (lim.paid.on ? ' Extend it, or it is destroyed then.' : ' It is destroyed then.');
        if (s.reply) readReply(rec, s.reply).then(function (t) { reply.textContent = 'Reply: ' + t; reply.hidden = false; }).catch(function () {});
      }
      function refresh() {
        return act(rec.id, 'status').then(show).catch(function (e) {
          chip.textContent = 'Gone'; chip.className = 'chip off';
          state.textContent = e.status === 404 ? 'No longer on record (ended more than 30 days ago).' : e.message;
        });
      }
      refresh();
      copy.addEventListener('click', function () { navigator.clipboard.writeText(rec.link).then(function () { copy.textContent = 'Copied'; }); });
      forget.addEventListener('click', function () { St.forget(rec.id).then(renderSent); });
      back.addEventListener('click', function () { back.disabled = true; act(rec.id, 'revoke').then(refresh, function (e) { state.textContent = e.message; back.disabled = false; }); });
      more.addEventListener('click', function () { ext.hidden = !ext.hidden; });
      extGo.addEventListener('click', async function () {
        if (busy) return;
        busy = true; extGo.disabled = true;
        try {
          const r = await act(rec.id, 'extend', { days: Math.max(1, parseInt(extDays.value, 10) || 30) });
          if (r.pay) {
            $('six').hidden = true; $('bar').hidden = true; say('work-msg', '');
            $('work-title').textContent = 'Extend “' + rec.name + '” by ' + r.days + ' days';
            $('form').hidden = true; $('done').hidden = true; $('work').hidden = false; $('work').scrollIntoView({ block: 'start' });
            await payment(rec.id, r.pay);
          }
          ext.hidden = true;
        } catch (e) { state.textContent = e.message; }
        $('work').hidden = true; $('form').hidden = false;
        busy = false; extGo.disabled = false;
        refresh();
      });
    });
  }

  function pick(file) {
    picked = file || null;
    $('drop-title').textContent = picked ? picked.name : 'Choose a file, or drop it here';
    $('drop').classList.toggle('has', !!picked);
    say('file-msg', picked ? St.size(picked.size) : 'Up to ' + St.size(lim.max_bytes).replace('.0', '') + ' free' + (lim.paid.on ? '. Larger, up to ' + St.size(lim.paid.max_bytes).replace('.0', '').replace('.00', '') + ', is paid.' : '.'));
    requote();
  }

  async function tally() {
    try {
      const t = await (await St.api('GET', '/stats')).json();
      if (!t.sent) return;
      $('t-sent').textContent = t.sent.toLocaleString(); $('t-bytes').textContent = St.size(t.bytes);
      $('t-opened').textContent = t.opened.toLocaleString(); $('t-destroyed').textContent = t.destroyed.toLocaleString();
      $('tally').hidden = false;
    } catch (e) { /* the numbers are optional */ }
  }

  async function start() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      $('off').textContent = 'This browser cannot seal files (it needs a secure https page and a current browser).'; $('off').hidden = false; $('form').hidden = true; return;
    }
    lim = await (await St.api('GET', '/limits')).json();
    if (!lim.on) { $('off').textContent = 'Sending is switched off on this registry for now.'; $('off').hidden = false; $('form').hidden = true; }
    $('keep-days').textContent = days(lim.free_keep);
    $('o-days').value = lim.free_keep / 86400; $('o-days').max = lim.paid.max_keep / 86400;
    document.querySelectorAll('.price').forEach(function (b) { b.textContent = '+' + St.usdc(lim.paid.prices[b.dataset.p]) + (b.dataset.s || ''); });
    if (!lim.paid.on) {
      $('paid-off').hidden = false;
      $('opts').querySelectorAll('input').forEach(function (i) { i.disabled = true; });
    }
    document.querySelectorAll('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () { navigator.clipboard.writeText($(b.dataset.copy).textContent).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); }); });
    });
    document.querySelectorAll('input[name=kind]').forEach(function (r) {
      r.addEventListener('change', function () { $('file-box').hidden = kind() !== 'file'; $('note-box').hidden = kind() !== 'note'; requote(); });
    });
    $('file').addEventListener('change', function () { pick($('file').files[0]); });
    ['dragenter', 'dragover'].forEach(function (n) { $('drop').addEventListener(n, function (e) { e.preventDefault(); $('drop').classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (n) { $('drop').addEventListener(n, function (e) { e.preventDefault(); $('drop').classList.remove('over'); }); });
    $('drop').addEventListener('drop', function (e) { if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]); });
    $('text').addEventListener('input', function () {
      const n = words($('text').value);
      say('text-msg', n + ' of 500 words', n > 500);
      requote();
    });
    $('opts').addEventListener('input', function () { $('o-opens').disabled = $('o-any').checked; requote(); });
    $('again').addEventListener('click', function () {
      $('done').hidden = true; $('form').hidden = false; $('form').reset(); $('file-box').hidden = false; $('note-box').hidden = true;
      $('o-days').value = lim.free_keep / 86400; $('o-opens').disabled = false; say('text-msg', ''); pick(null);
    });
    $('form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) return;
      const c = content();
      if (!c) return say('msg', 'Choose a file first.', true);
      if (!c.size) return say('msg', c.kind === 'note' ? 'Write the note first.' : 'That file is empty.', true);
      if (c.kind === 'note' && (c.words > 500 || c.size > lim.note_bytes)) return say('msg', 'A note is at most 500 words.', true);
      if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true);
      if (quoted.error) return say('msg', quoted.error, true);
      busy = true; $('go').disabled = true;
      send(c, opts()).then(function (r) { say('msg', ''); showDone(r); })
        .catch(function (e) { $('work').hidden = true; $('form').hidden = false; say('msg', 'Not sent: ' + e.message, true); })
        .finally(function () { busy = false; $('go').disabled = false; renderSent(); tally(); });
    });
    pick(null);
    renderSent();
    tally();
  }
  start().catch(function (e) { $('off').textContent = 'This page could not start: ' + e.message; $('off').hidden = false; });
})();
