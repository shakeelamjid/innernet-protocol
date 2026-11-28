/* INNERNET Send: the page behind a link. What it does depends on the link and on the sender's rules:
   open with a PIN or with the holders' keys, approve a release, watch as a witness, pay to open,
   add a sealed contribution, read what was added, hand it on. Everything is unsealed on this device. */
(function () {
  'use strict';
  const C = window.InnernetSend, St = window.InnernetSendStore, W = window.InnernetWallet;
  const $ = function (id) { return document.getElementById(id); };
  const path = location.pathname.match(/\/send\/(?:o\/([0-9a-f]{32})|n\/([a-z0-9-]+))\/?$/);
  let id = path && path[1], secret = null, keys = null, busy = false, steps = null, isNote = false, token = null;
  let joint = false, held = false, due = 0, autoPin = null, info = null, roomCall = null, roomNeed = 0, opened = null;

  function say(text, err) { $('msg').textContent = text || ''; $('msg').classList.toggle('error', !!err); }
  function end(title, text) { $('title').textContent = title; $('lede').textContent = text; ['ask', 'custody', 'side', 'collect'].forEach(function (s) { $(s).hidden = true; }); }
  function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }
  function fail(e) { end('Something went wrong', e.message); }
  async function who() { const d = await St.deviceKey(); return { device: d, pub: await C.publicRaw(d) }; }

  async function start() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) return end('This browser cannot open sealed files', 'Use a current browser on a secure (https) page.');
    if (!id && path && path[2]) {
      try { id = (await (await St.api('GET', '/names/' + path[2])).json()).id; } catch (e) { return end('This link does not exist', 'No send has that name. It may have ended.'); }
    }
    const hash = location.hash.slice(1);
    if (id && /^a\d+\./.test(hash)) return approver(hash);
    if (id && /^w[A-Za-z0-9_-]{20,}$/.test(hash)) return witness(hash.slice(1));
    const jl = C.parseJoint(location.hash);
    if (id && jl && !secret) return custody(jl);
    if (!secret) {
      const bits = hash.split('.');
      try { secret = C.unb64u(bits[0]); } catch (e) { secret = null; }
      if (bits[1] && /^[0-9]{6}$/.test(bits[1])) autoPin = bits[1];
    }
    if (!id || !secret || secret.length !== 32) return end('This link is not complete', 'Ask the sender for the whole link, including the part after the # sign.');
    keys = await C.linkKeys(secret, id);
    try { info = await (await St.api('POST', '/files/' + id + '/info', { auth: C.b64u(keys.auth), device_pub: (await who()).pub })).json(); }
    catch (e) {
      if (joint && e.status === 403) { secret = null; $('custody').hidden = false; $('cu-msg').textContent = 'These keys do not open this link. One of them is mistyped or belongs to another send.'; $('cu-msg').classList.add('error'); return; }
      return end(e.status === 404 ? 'This does not exist' : 'This link does not work', e.status === 404 ? 'It may have ended more than 30 days ago, or the link is wrong.' : e.message);
    }
    $('custody').hidden = true;
    if (info.state === 'dead') return end('This is gone', 'It was destroyed (' + info.reason + '). The link no longer opens anything.');
    if (info.state === 'uploading') return end('Not ready yet', 'The sender has not finished sending this. Try again in a minute.');
    if (info.state === 'spent') return end('This was already opened', 'It could be opened ' + (info.max_opens === 1 ? 'once' : info.max_opens + ' times') + ', and that is used up.');
    let pv = { from: '', note: '' };
    try { pv = await C.openSmall(keys.preview, id, 'preview', info.preview); } catch (e) { /* shown without a name */ }
    $('lede').textContent = 'It was sealed on the sender’s device. It opens here, on yours.';
    $('from').textContent = pv.from ? 'From ' + pv.from : 'Sealed';
    if (pv.note) { $('note').textContent = pv.note; $('note').hidden = false; }
    isNote = info.kind === 'note';
    $('title').textContent = info.collect ? 'You are asked to add something, sealed' : isNote ? 'A sealed note for you' : 'A sealed file for you';
    const badges = [];
    if (info.origin) badges.push('Sent from ' + info.origin + ' (that domain publishes this sender’s key)');
    if (info.chain && info.chain.length) badges.push('Handed on ' + info.chain.length + (info.chain.length === 1 ? ' time' : ' times') + '; first sealed ' + St.when(info.chain[info.chain.length - 1].sealed_at));
    if (info.version > 1) badges.push('Version ' + info.version);
    badges.push('Sealed ' + St.when(info.sealed_at));
    $('badges').textContent = badges.join(' · ');
    if (info.summary) { try { $('summary').textContent = (await C.openSmall(keys.preview, id, 'summary', info.summary)).text; $('summary').hidden = false; } catch (e) { /* no summary */ } }
    const leftOpens = info.max_opens > 1 && !info.holders ? ' ' + (info.max_opens - info.opens) + ' opening' + (info.max_opens - info.opens === 1 ? '' : 's') + ' left.' : '';
    $('rules').textContent = (isNote ? 'A note, shown on this screen. ' : St.size(info.size) + '. ') +
      (info.max_opens === 1 ? 'It opens once and is then destroyed.' : info.max_opens ? '' : 'It opens any number of times until it ends.') +
      (info.forward || info.named || info.max_opens !== 1 ? '' : ' Only on the first device that opens it.') + (info.open_until ? ' The window closes ' + St.when(info.open_until) + '.' : '') +
      ' Ends ' + St.when(info.expires_at) + '.' + leftOpens;
    steps = St.steps($('six'), $('bar'), [
      { title: 'Link proved', text: 'This device showed it holds the link, without sending the link secret.' },
      { title: 'PIN proved', text: 'A proof made from the PIN is sent. The PIN itself is not.' },
      { title: 'Keeper part released', text: 'The keeper checks the sender’s rules, then hands over its part.' },
      { title: 'File key rebuilt', text: 'From link secret + PIN + keeper part, on this device.' },
      { title: 'Sealed parts fetched and opened', text: '', cells: true },
      { title: 'Checked and put together', text: '' }]);
    steps.set(0, 'done');
    $('ask').hidden = false;
    held = info.held; due = info.release_at;
    if (autoPin) { $('pin').value = autoPin; $('pin').hidden = true; document.querySelector('label[for=pin]').hidden = true; }
    gate();
    if (info.collect) collect();
    if (joint && autoPin && !$('go').disabled) $('form').requestSubmit();
  }

  /* What still stands between this device and the content: a time, a check-in, approvals, a payment. */
  function gate() {
    const now = Date.now() / 1000;
    let why = '';
    if (info.locked) why = 'This is locked: its time ended. The sender can still renew it; after a few days it is destroyed.';
    else if (held) why = 'This is held while the sender keeps checking in. If the sender does not check in by ' + St.when(due) + ', it can be opened here. Keep ' + (joint ? 'the link and your keys' : 'the link and the PIN') + ' safe until then.';
    else if (info.open_after > now && !info.collect) why = 'The sender set this to open after ' + St.when(info.open_after) + ' (in ' + St.left(info.open_after) + '). Keep the link and the PIN until then.';
    else if (info.approvals && info.approvals.have < info.approvals.need) why = 'Waiting for approval: ' + info.approvals.have + ' of ' + info.approvals.need + ' approvers have released it.';
    const pay = info.paylock && !info.access;
    $('held').hidden = !why; $('held').textContent = why;
    $('buy').hidden = !pay || !!why;
    if (pay && !why) buyBox();
    const stop = !!why || pay;
    $('go').disabled = stop; $('pin').disabled = stop;
    if (stop && !busy) setTimeout(refresh, why && info.open_after > now ? Math.min((info.open_after - now) * 1000 + 500, 30000) : 6000);
    else if (!busy && !autoPin && !$('ask').hidden) $('pin').focus();
  }
  async function refresh() {
    if (busy || opened) return;
    try {
      const fresh = await (await St.api('POST', '/files/' + id + '/info', { auth: C.b64u(keys.auth), device_pub: (await who()).pub })).json();
      if (fresh.state !== 'live') return start();
      info = fresh; held = info.held; due = info.release_at; gate();
    } catch (e) { /* try again on the next round */ setTimeout(refresh, 8000); }
  }

  /* Payment as a lock: the reader pays the sender's own address; the keeper only looks at the chain. */
  let buying = null;
  function buyBox() {
    const p = info.paylock, crowd = p.mode === 'crowd';
    $('buy-title').textContent = crowd ? 'It opens for everyone at ' + St.usdc(p.target) + ' USDC' : 'It opens after payment: ' + St.usdc(p.price) + ' USDC' + (p.mode === 'period' ? ' per ' + p.period_days + ' days' : '');
    $('buy-text').textContent = crowd ? St.usdc(p.raised) + ' USDC paid so far. Put in ' + St.usdc(p.price) + ' USDC or more.' : p.sold + ' of ' + p.buyers + ' readers so far.';
    $('buy-own').hidden = !crowd; if (crowd && !$('buy-amount').value) $('buy-amount').value = St.usdc(p.price);
    if (buying) return;
    $('buy-go').onclick = async function () {
      $('buy-go').disabled = true;
      try {
        const d = await who();
        buying = await (await St.api('POST', '/files/' + id + '/buy', Object.assign({ auth: C.b64u(keys.auth), device_pub: d.pub, amount: crowd ? $('buy-amount').value : undefined }, await C.signRequest(d.device, 'buy', id)))).json();
        $('buy-exact').textContent = buying.amount; $('buy-to').textContent = buying.to; $('buy-net').textContent = buying.network_name;
        $('buy-how').hidden = false; $('buy-wallet').hidden = !window.ethereum; $('buy-go').hidden = true;
        $('buy-msg').textContent = 'Waiting for the payment…';
        watchPay();
      } catch (e) { $('buy-msg').textContent = e.message; $('buy-go').disabled = false; }
    };
    $('buy-wallet').onclick = async function () {
      try {
        $('buy-msg').textContent = 'Confirm in your wallet…';
        const from = await W.connect(buying.chain_id);
        buying.tx = await W.request('eth_sendTransaction', [{ from: from, to: buying.usdc, data: '0xa9059cbb' + W.pad(buying.to) + BigInt(buying.micro).toString(16).padStart(64, '0') }]);
        $('buy-msg').textContent = 'Paid. Waiting for the chain to confirm…';
      } catch (e) { $('buy-msg').textContent = W.friendly(e); }
    };
  }
  async function watchPay() {
    try {
      const d = await who();
      const r = await (await St.api('POST', '/files/' + id + '/buy/check', Object.assign({ auth: C.b64u(keys.auth), device_pub: d.pub, tx: buying.tx }, await C.signRequest(d.device, 'buy', id)))).json();
      if (r.access) { info.access = true; buying = null; $('buy').hidden = true; return gate(); }
      if (r.mode === 'crowd' && Number(r.raised) > Number(info.paylock.raised)) { info.paylock = r; buying = null; $('buy-how').hidden = true; $('buy-go').hidden = false; $('buy-go').disabled = false; $('buy-msg').textContent = 'Your payment is in. It opens when the target is reached.'; return buyBox(); }
    } catch (e) { $('buy-msg').textContent = e.message; }
    setTimeout(watchPay, 4000);
  }

  /* An approver's link: agree to the release. The approver holds no part of any key. */
  async function approver(hash) {
    const bits = hash.split('.'), idx = Number(bits[0].slice(1));
    let about = {}; try { about = JSON.parse(new TextDecoder().decode(C.unb64u(bits[2]))); } catch (e) { /* no words from the sender */ }
    $('title').textContent = 'You are asked to approve a release';
    $('lede').textContent = 'Approving lets the people it was sent to open it. It shows you nothing of what is inside.';
    $('side-title').textContent = about.from ? 'From ' + about.from : 'A sealed send';
    $('side-text').textContent = about.line || '';
    const b = el('button', 'I approve the release', 'btn btn-light'); b.type = 'button';
    $('side-body').append(b); $('side').hidden = false;
    async function call(approve) {
      try {
        const s = await (await St.api('POST', '/files/' + id + '/approve', { idx: idx, token: bits[1], approve: approve })).json();
        $('side-msg').textContent = (s.mine ? 'You have approved. ' : '') + s.have + ' of ' + s.need + ' needed approvals are in' + (s.have >= s.need ? ': it can now be opened.' : '.');
        b.hidden = s.mine;
      } catch (e) { $('side-msg').textContent = e.message; $('side-msg').classList.add('error'); b.hidden = e.status === 403 || e.status === 410; }
    }
    b.addEventListener('click', function () { call(true); });
    call(false);
  }

  /* A witness's link: what happens to the send, and the signed record. No content. */
  async function witness(tok) {
    $('title').textContent = 'You are a witness to a sealed send';
    $('lede').textContent = 'You can see what happens to it and keep the signed record. You cannot open it.';
    let last = null;
    async function load() {
      try {
        const s = await (await St.api('POST', '/files/' + id + '/witness', { token: tok })).json();
        last = s;
        $('side-title').textContent = s.state === 'dead' ? 'Ended: ' + s.reason : s.state === 'spent' ? 'Opened; being destroyed' : s.held ? 'Held while the sender checks in' : 'Waiting';
        $('side-text').textContent = 'Sealed ' + St.when(s.sealed_at) + '. Ends ' + St.when(s.expires_at) + '. Opened ' + s.opens + (s.max_opens ? ' of ' + s.max_opens : '') + ' times.' +
          (s.approvals ? ' Approvals: ' + s.approvals.have + ' of ' + s.approvals.need + ' needed.' : '') + (s.holders ? ' Key holders: ' + s.need + ' of ' + s.holders + ' needed.' : '');
        const ul = el('ul', null, 'plain');
        (s.signed ? s.signed.record.events : []).forEach(function (e) { ul.append(el('li', St.when(e.at) + ': ' + e.event)); });
        const b = el('button', 'Save the signed record', 'btn'); b.type = 'button';
        b.addEventListener('click', function () { St.download('innernet-record-' + id.slice(0, 8) + '.json', new Blob([JSON.stringify(last.signed, null, 2)], { type: 'application/json' })); });
        $('side-body').textContent = ''; $('side-body').append(ul); if (s.signed) $('side-body').append(b);
        $('side').hidden = false;
        if (s.state !== 'dead') setTimeout(load, 10000);
      } catch (e) { end('This witness link does not work', e.message); }
    }
    load();
  }

  /* Split custody: the link names the holders. Each opens it at their own place and adds their own key.
     When enough keys are in within one window, the keeper hands the sealed keys to every place that added
     one; each place unseals them with the room secret from the link, rebuilds the link secret and opens. */
  async function custody(jl) {
    joint = true; roomNeed = jl.k;
    const all = jl.k === jl.names.length, d = await who(), rm = await C.room(jl.room, id);
    let timer = null, over = false;
    $('title').textContent = 'Sealed under split custody';
    $('lede').textContent = 'The sender gave a key to each person below, so that no one can open this alone.';
    $('cu-title').textContent = all ? 'All ' + jl.k + ' keys are needed' : 'Any ' + jl.k + ' of these ' + jl.names.length + ' keys are needed';
    $('cu-text').textContent = 'Open this link on your own device and add your key next to your name. When the keys are in within the same 10 minutes, it opens at every place that added one.';
    $('cu-fields').textContent = '';
    function note(text, err) { $('cu-msg').textContent = text; $('cu-msg').classList.toggle('error', !!err); }
    async function call(p, extra) {
      const body = Object.assign({ room_auth: rm.auth, device_pub: d.pub }, await C.signRequest(d.device, 'room', id), extra || {});
      return (await St.api('POST', '/files/' + id + '/room' + p, body)).json();
    }
    roomCall = call;
    const rows = jl.names.map(function (name, i) {
      const row = el('div', null, 'keyrow'), f = el('input', null, 'field'), add = el('button', 'Add key', 'btn btn-sm'), mk = el('span', 'Waiting', 'chip');
      f.autocomplete = 'off'; f.spellcheck = false; f.placeholder = 'Key'; f.setAttribute('aria-label', 'Key of ' + name); add.type = 'button';
      add.addEventListener('click', async function () {
        const p = C.parsePart(f.value);
        if (!p) return note('That is not a key. Paste the whole key the sender gave ' + name + '.', true);
        if (p.x !== i + 1 || p.k !== jl.k) return note('That key belongs to another person, not to ' + name + '.', true);
        add.disabled = true;
        try { paint(await call('/key', { seat: i + 1, ct: C.b64u(await rm.seal(p)) })); f.value = ''; }
        catch (e) { note(e.message, true); }
        add.disabled = false;
      });
      row.append(el('strong', name), f, add, mk); $('cu-fields').append(row);
      return { row: row, f: f, add: add, mk: mk };
    });
    async function finish(sealed) {
      over = true; clearTimeout(timer);
      const parts = [];
      for (const seat of Object.keys(sealed)) parts.push(await rm.open(Number(seat), jl.k, C.unb64u(sealed[seat])));
      secret = C.combine(parts.slice(0, jl.k));
      autoPin = await C.jointPin(secret);
      note('The keys are in. Opening…');
      await start();
    }
    function paint(s) {
      rows.forEach(function (r, i) {
        const inn = s.added.indexOf(i + 1) >= 0;
        r.mk.textContent = inn ? 'Key added' : 'Waiting'; r.mk.className = 'chip ' + (inn ? 'on' : '');
        r.f.hidden = inn; r.add.hidden = inn; r.row.classList.toggle('ok', inn);
      });
      let text = s.here + ' of ' + s.holders + ' places have this open now. ' + s.added.length + ' of ' + s.need + ' keys are in.';
      if (s.window_ends && !s.released) text += ' The rest must be added by ' + St.when(s.window_ends).replace(/^.*?, /, '') + ', or the keys are cleared.';
      if (s.released && !s.mine) text = 'The keys are in, and it opened at the places that added one. No key was added here, so it stays closed here.';
      if (s.held) text += ' It is held while the sender keeps checking in (next check-in by ' + St.when(s.checkin_due) + ').';
      note(text);
      if (s.keys && !over) finish(s.keys).catch(fail);
    }
    async function poll() {
      if (over) return;
      try { paint(await call('')); }
      catch (e) {
        if (e.status === 410 || e.status === 404) { over = true; return end('This is gone', e.message); }
        note(e.message, e.status !== 429);
      }
      timer = setTimeout(poll, 3000);
    }
    $('custody').hidden = false;
    $('cu-form').onsubmit = function (ev) { ev.preventDefault(); };
    poll();
  }

  async function open(pin) {
    const d = await who();
    $('work').hidden = false;
    steps.set(1, 'run');
    const body = Object.assign({ auth: C.b64u(keys.auth), pin_proof: await C.pinTag(keys, pin), device_pub: d.pub }, await C.signRequest(d.device, 'open', id));
    steps.set(2, 'run', 'Asking the keeper…', 0.4);
    let rel;
    try { rel = await (await St.api('POST', '/files/' + id + '/open', body)).json(); }
    catch (e) { steps.set(1, 'wait'); steps.set(2, 'wait', 'The keeper checks the sender’s rules, then hands over its part.'); $('work').hidden = true; throw e; }
    $('ask').hidden = true;
    steps.set(1, 'done');
    steps.set(2, 'done', rel.last ? 'Released for the last time. The keeper has now destroyed its part: this link will open nothing again.'
      : 'Released. Opening ' + rel.opens + (rel.max_opens ? ' of ' + rel.max_opens : '') + '.');
    steps.set(3, 'run', 'Stretching the PIN 200,000 rounds…');
    let key = await C.fileKey(secret, C.unb64u(rel.keeper_share), pin, id);
    if (rel.wrap) key = await C.unwrapKey(key, id, rel.wrap);          // this person's own PIN opens their copy of the content key
    const meta = await C.openSmall(key, id, 'meta', rel.meta);
    steps.set(3, 'done', 'Rebuilt here. The keeper never had the whole key.');
    const out = [];
    for (let n = 0; n < rel.parts; n++) {
      steps.set(4, 'run', 'Part ' + (n + 1) + ' of ' + rel.parts + ': fetched sealed, opened here.', n / rel.parts);
      const sealed = await St.bytes('GET', '/files/' + id + '/parts/' + n, null, { 'X-Send-Token': rel.token });
      out.push(await C.openPart(key, id, n, rel.parts, sealed));
      steps.set(4, 'run', null, (n + 1) / rel.parts);
    }
    steps.set(4, 'done', rel.parts + (rel.parts === 1 ? ' part' : ' parts') + ' opened. Each seal matched, so nothing was changed on the way.');
    steps.set(5, 'run');
    const blob = new Blob(out, { type: meta.type });
    if (blob.size !== meta.size) throw new Error('it is not complete');
    steps.set(5, 'done', St.size(meta.size) + ', complete and unchanged.');
    return { blob: blob, meta: meta, rel: rel };
  }

  async function show(r) {
    const m = r.meta, note = m.kind === 'note', pic = /^image\/(png|jpeg|gif|webp)$/.test(m.type), text = /^text\//.test(m.type);
    const onScreen = note || (m.view_only && (pic || text));
    opened = r;
    $('name').textContent = note ? 'The note' : m.name;
    if (onScreen) {
      $('view').hidden = false; $('save').hidden = true;
      if (pic) { $('pic').src = URL.createObjectURL(r.blob); $('pic').hidden = false; }
      else { $('shown').textContent = await r.blob.text(); $('shown').hidden = false; if (m.card) $('shown').className = 'shown card-' + m.card; }
      if (m.view_only && m.mark) { $('mark').textContent = (m.mark + ' · ' + St.when(Date.now() / 1000) + '   ').repeat(40); $('mark').hidden = false; }
      $('facts').textContent = 'Opened and checked on this device. It is shown only here.';
    } else if (m.view_only) {
      $('save').hidden = true;
      $('facts').textContent = 'The sender allowed this to be shown on screen only, and this kind of file (' + (m.type || 'unknown') + ') cannot be shown in the page. Ask the sender for a picture or text version.';
    } else {
      $('save').href = URL.createObjectURL(r.blob); $('save').download = m.name;
      $('facts').textContent = St.size(m.size) + '. Opened and checked on this device.';
    }
    $('after').textContent = (r.rel.last ? 'That was the last opening: it is now being destroyed on the network. ' : '') + (onScreen ? 'Closing this page discards it.' : m.view_only ? '' : 'Save it now; closing this page discards it.');
    $('title').textContent = note ? 'Your note is open' : 'Your file is open';
    $('lede').textContent = 'Nothing was unsealed anywhere but here.';
    $('got').hidden = false;
    if (r.rel.reply_on) { token = r.rel.token; $('reply').hidden = false; }
    if (info.extras && info.extras.chain) { token = r.rel.token; $('handon').hidden = false; }
    if (info.extras && info.extras.record) $('rec').hidden = false;
    if (r.rel.last) setTimeout(function () { steps.burn(); }, 900);
    if (!onScreen && !m.view_only) $('save').click();
    if (m.view_secs) {                                    // the view timer: after this, the page lets go of it
      let left = m.view_secs;
      const t = setInterval(function () {
        left--; $('timer').hidden = false; $('timer').textContent = 'Visible for ' + Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0') + ' more.';
        if (left <= 0) { clearInterval(t); wipe('The time the sender allowed has passed. It has left this screen.'); }
      }, 1000);
    }
    if (m.presence && roomCall) {                         // visible only while enough holders still have the link open
      const p = setInterval(async function () {
        if (!opened) return clearInterval(p);
        try { const s = await roomCall(''); $('view').classList.toggle('away', s.here < roomNeed); $('timer').hidden = s.here >= roomNeed && !m.view_secs; if (s.here < roomNeed) $('timer').textContent = 'Hidden: only ' + s.here + ' of the ' + roomNeed + ' needed holders are here.'; }
        catch (e) { clearInterval(p); wipe('This send has ended. It has left this screen.'); }
      }, 3000);
    }
  }
  function wipe(why) {
    opened = null; $('shown').textContent = ''; $('pic').removeAttribute('src'); $('view').hidden = true; $('save').hidden = true; $('save').removeAttribute('href');
    $('reply').hidden = true; $('handon').hidden = true; $('timer').hidden = false; $('timer').textContent = why; $('facts').textContent = '';
  }

  /* Others add to it: a form the sender wrote, filled in here, sealed here. */
  async function collect() {
    const c = info.collect, d = await who();
    let form = { fields: [], file: false };
    try { if (c.form) form = await C.openSmall(keys.preview, id, 'form', c.form); } catch (e) { /* no form: a file only */ }
    $('co-fields').textContent = '';
    const inputs = form.fields.map(function (q, i) {
      const l = el('label', q, 'label'), f = el('input', null, 'field'); f.id = 'co-q' + i; l.setAttribute('for', f.id); f.maxLength = 500; f.autocomplete = 'off';
      $('co-fields').append(l, f); return f;
    });
    $('co-file-box').hidden = !form.file;
    async function state() { return (await St.api('POST', '/files/' + id + '/adds/list', { auth: C.b64u(keys.auth), device_pub: d.pub })).json(); }
    async function paint() {
      const s = await state(), open = Date.now() / 1000 < s.closes_at && !info.locked && !(s.revealed && info.open_after);
      $('co-title').textContent = s.mine ? 'You have added yours' : 'Add yours';
      $('co-text').textContent = s.count + ' of ' + s.seats + ' have added. ' + (open ? 'You can add, or replace what you added, until ' + St.when(s.closes_at) + '.' : 'It is closed: nothing can be added or changed now.') +
        (info.open_after ? ' Everything added stays sealed until ' + St.when(info.open_after) + ', then opens ' + (s.audience === 'all' ? 'for everyone with this link.' : 'for the sender only.') : s.audience === 'owner' ? ' Only the sender can read what you add.' : '') +
        (s.reveal_count && !s.revealed ? ' It opens once ' + s.reveal_count + ' have added.' : '');
      $('co-form').hidden = !open; $('co-go').textContent = s.mine ? 'Seal and replace mine' : 'Seal and add';
      $('co-mine').textContent = '';
      if (s.mine) $('co-mine').append(el('p', 'Your entry is number ' + s.mine.entry + ', received ' + St.when(s.mine.updated_at) + (s.mine.changes ? ', changed ' + s.mine.changes + (s.mine.changes === 1 ? ' time' : ' times') : '') + '. Fingerprint ' + s.mine.sha256.slice(0, 16) + '…', 'note'));
      $('co-all').textContent = '';
      if (s.may_read && s.entries) {
        const b = el('button', 'Read what everyone added (' + s.entries.length + ')', 'btn'); b.type = 'button';
        b.addEventListener('click', async function () {
          b.disabled = true;
          const shared = await C.subKey(secret, id, 'adds'), table = el('table', null, 'adds');
          for (const e of s.entries) {
            const got = C.unpack(await C.openWith(shared, id, await St.bytes('POST', '/files/' + id + '/adds/' + e.entry, { auth: C.b64u(keys.auth) })));
            const tr = el('tr'), td = el('td'); tr.append(el('th', '#' + e.entry + ' · ' + St.when(e.received_at) + (e.changes ? ' · changed ' + e.changes + '×' : '')));
            Object.keys(got.obj.answers || {}).forEach(function (k) { td.append(el('div', k + ': ' + got.obj.answers[k])); });
            if (got.obj.file) { const sv = el('button', 'Save ' + got.obj.file.name, 'btn btn-sm'); sv.type = 'button'; sv.addEventListener('click', function () { St.download(got.obj.file.name, new Blob([got.file], { type: got.obj.file.type })); }); td.append(sv); }
            tr.append(td); table.append(tr);
          }
          $('co-all').textContent = ''; $('co-all').append(table);
        });
        $('co-all').append(b);
      }
      return s;
    }
    $('co-form').onsubmit = async function (ev) {
      ev.preventDefault();
      const answers = {}; form.fields.forEach(function (q, i) { answers[q] = inputs[i].value.trim(); });
      const file = form.file && $('co-file').files[0];
      if (!file && !Object.keys(answers).some(function (k) { return answers[k]; })) { $('co-msg').textContent = 'Fill in at least one answer.'; return; }
      if (file && file.size > 4000000) { $('co-msg').textContent = 'The attached file is larger than 4 MB.'; return; }
      $('co-go').disabled = true; $('co-msg').classList.remove('error'); $('co-msg').textContent = 'Sealing on this device…';
      try {
        const packed = C.pack({ answers: answers, file: file ? { name: file.name, type: file.type || 'application/octet-stream' } : null }, file ? new Uint8Array(await file.arrayBuffer()) : null);
        const sealed = form.pub ? await C.sealTo(C.unb64u(form.pub), id, packed) : await C.sealWith(await C.subKey(secret, id, 'adds'), id, packed);
        const sig = await C.signRequest(d.device, 'add', id);
        const r = await fetch(St.BASE + '/send/api/files/' + id + '/adds', { method: 'PUT', body: sealed, credentials: 'omit', headers: { 'X-Innernet': '1', 'Content-Type': 'application/octet-stream',
          'X-Send-Auth': C.b64u(keys.auth), 'X-Send-Device': d.pub, 'X-Send-Ts': String(sig.ts), 'X-Send-Sig': sig.sig } });
        const receipt = await r.json();
        if (!r.ok) throw new Error(receipt.detail || 'The keeper refused it.');
        $('co-msg').textContent = 'Sealed and stored as entry ' + receipt.record.entry + '. ';
        const b = el('button', 'Save the signed receipt', 'btn btn-sm'); b.type = 'button';
        b.addEventListener('click', function () { St.download('innernet-receipt-' + id.slice(0, 8) + '-' + receipt.record.entry + '.json', new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' })); });
        $('co-msg').append(b);
        await paint();
      } catch (e) { $('co-msg').textContent = e.message; $('co-msg').classList.add('error'); }
      $('co-go').disabled = false;
    };
    $('collect').hidden = false;
    const s = await paint();
    if (!s.revealed && (info.open_after || s.reveal_count)) setInterval(function () { paint().catch(function () {}); }, 10000);
  }

  $('form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (busy) return;
    const pin = $('pin').value.replace(/\D/g, '');
    if (pin.length !== 6) return say('The PIN has 6 digits.', true);
    busy = true; $('go').disabled = true;
    open(pin).then(show).catch(function (e) {
      say(e.name === 'OperationError' ? 'It could not be opened: its seal does not match. Nothing was saved.' : e.message, true);
      if (e.status === 410) end('This is gone', e.message);
    }).finally(function () { busy = false; $('go').disabled = false; });
  });

  $('reply').addEventListener('submit', function (ev) {
    ev.preventDefault();
    const text = $('reply-text').value.trim();
    if (!text) return;
    $('reply-go').disabled = true;
    C.sealSmall(keys.preview, id, 'reply', { text: text }).then(function (sealed) {
      return St.api('POST', '/files/' + id + '/reply', { sealed: sealed }, { 'X-Send-Token': token });
    }).then(function () {
      $('reply-text').disabled = true; $('reply-go').hidden = true;
      $('reply-msg').textContent = 'Sent, sealed. Only the sender can read it.';
    }).catch(function (e) { $('reply-msg').textContent = e.message; $('reply-msg').classList.add('error'); $('reply-go').disabled = false; });
  });

  $('rec').addEventListener('click', async function () {
    const r = await (await St.api('POST', '/files/' + id + '/record', { auth: C.b64u(keys.auth) })).json();
    St.download('innernet-record-' + id.slice(0, 8) + '.json', new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }));
  });

  /* Hand it on: seal what was just opened for the next person; the keeper records the chain. */
  $('handon').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    if (!opened || !$('handon-from').value.trim()) { $('handon-msg').textContent = 'Add your name first.'; return; }
    $('handon-go').disabled = true; $('handon-msg').classList.remove('error'); $('handon-msg').textContent = 'Sealing on this device…';
    try {
      const d = await who(), nid = C.newId(), sec = C.random(32), share = C.random(32), pin = C.newPin(), m = opened.meta;
      const k2 = await C.linkKeys(sec, nid), key = await C.fileKey(sec, share, pin, nid), parts = C.partCount(m.size);
      const made = await (await St.api('POST', '/files', { id: nid, kind: m.kind, size: m.size + parts * C.TAG, parts: parts, auth_hash: k2.authHash, pin_tag: await C.pinTag(k2, pin),
        owner_pub: d.pub, keeper_share: C.b64u(share), parent: id, parent_token: token,
        preview: await C.sealSmall(k2.preview, nid, 'preview', { from: $('handon-from').value.trim(), note: 'Handed on' }),
        meta: await C.sealSmall(key, nid, 'meta', { name: m.name, type: m.type, size: m.size, kind: m.kind }) })).json();
      for (let n = 0; n < parts; n++) {
        await St.put('/files/' + nid + '/parts/' + n, await C.sealPart(key, nid, n, parts, new Uint8Array(await opened.blob.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer())), { 'X-Send-Upload': made.upload, 'Content-Type': 'application/octet-stream' });
      }
      $('handon-msg').textContent = 'Sealed for the next person. Send them this link and tell them the PIN.';
      $('handon-out').textContent = ''; $('handon-out').append(el('code', location.origin + St.BASE + '/send/o/' + nid + '#' + C.b64u(sec)), el('p', 'PIN ' + pin, 'big'));
      $('handon-go').hidden = true;
    } catch (e) { $('handon-msg').textContent = e.message; $('handon-msg').classList.add('error'); $('handon-go').disabled = false; }
  });

  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () { navigator.clipboard.writeText($(b.dataset.copy).textContent).then(function () { b.textContent = 'Copied'; }); });
  });
  start().catch(fail);
})();
