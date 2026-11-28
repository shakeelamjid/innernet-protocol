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
  function round(n) { return St.size(n).replace(/\.0+ /, ' '); }
  function days(s) { const d = Math.round(s / 86400); return d === 1 ? '1 day' : d + ' days'; }

  function content() {
    if (kind() === 'note') {
      const text = $('text').value.trim();
      const bytes = new TextEncoder().encode(text);
      return { kind: 'note', name: 'Note', type: 'text/plain;charset=utf-8', size: bytes.length, blob: new Blob([bytes]), words: words(text) };
    }
    return picked ? { kind: 'file', name: picked.name, type: picked.type || 'application/octet-stream', size: picked.size, blob: picked } : null;
  }
  function stamp(id) { return $(id).value ? Math.floor(new Date($(id).value).getTime() / 1000) : 0; }
  let termDays = 7;
  function term() { const t = document.querySelector('input[name=term]:checked'); if (t) termDays = Number(t.value); return termDays; }
  function lines(id, most) { return $(id).value.split(/\n|,/).map(function (t) { return t.trim().slice(0, 60); }).filter(Boolean).slice(0, most); }
  function lock() { return document.querySelector('input[name=lock]:checked').value; }
  function on(id) { return $(id).checked && !$(id).disabled; }
  /* Everything beyond the basic rules, as the price list and the keeper understand it. */
  function more() {
    const named = lock() === 'named', collect = on('o-collect'), pay = on('o-pay'), e = {};
    if (on('o-viewonly')) e.view_only = 1;
    if (on('o-timer')) e.view_secs = Math.max(1, parseInt($('o-timer-min').value, 10) || 5) * 60;
    if (on('o-presence') && lock() === 'keys') e.presence = 1;
    if (on('o-card') && kind() === 'note') e.card = $('o-card-kind').value;
    if (on('o-alarm') && $('o-alarm-url').value.trim()) e.alarm_url = $('o-alarm-url').value.trim();
    ['record', 'chain', 'qr', 'recovery'].forEach(function (k) { if (on('o-' + k)) e[k] = 1; });
    if (on('o-witness')) e.witness = 1;
    if (on('o-origin') && $('o-origin-dom').value.trim()) e.origin = $('o-origin-dom').value.trim().toLowerCase();
    if (on('o-name') && $('o-name-v').value.trim()) e.name = $('o-name-v').value.trim().toLowerCase();
    if (on('o-versions')) e.versions = Math.max(1, parseInt($('o-versions-n').value, 10) || 1);
    if (lock() === 'open' || collect || pay) e.pin_in_link = 1;
    const m = { extras: e };
    if (named) { m.recipients = lines('o-rnames', 20).length; m.succession = on('o-succ'); }
    if (on('o-approve') && lines('o-anames', 10).length) m.approvers = { count: lines('o-anames', 10).length, need: Math.min(lines('o-anames', 10).length, Math.max(1, parseInt($('o-aneed').value, 10) || 1)) };
    if (on('o-duress')) m.duress = true;
    if (on('o-summary') && $('o-summary-text').value.trim()) m.summary = '1';
    if (collect) m.collect = { audience: $('o-audience').value, anon: $('o-anon').checked, seats: Math.max(1, parseInt($('o-seats').value, 10) || 1), reveal_count: Math.max(0, parseInt($('o-reveal').value, 10) || 0) };
    if (pay) m.pay = { mode: $('o-pay-mode').value, price: $('o-pay-price').value, to: $('o-pay-to').value.trim(), buyers: Math.max(1, parseInt($('o-pay-buyers').value, 10) || 1), target: $('o-pay-target').value, period_days: Math.max(1, parseInt($('o-pay-period').value, 10) || 30) };
    return m;
  }
  function names() { return $('o-names').value.split(/\n|,/).map(function (t) { return t.trim().slice(0, 40); }).filter(Boolean).slice(0, 20); }
  function opts() {
    const many = $('o-many').checked;
    return { keep: term() * 86400, max_opens: !many ? 1 : $('o-any').checked ? 0 : Math.min(1000, Math.max(2, parseInt($('o-opens').value, 10) || 2)),
      forward: $('o-forward').checked, open_after: $('o-win-a').checked ? stamp('o-after') : 0, open_until: $('o-win-b').checked ? stamp('o-until') : 0,
      holders: $('o-split').checked ? names().length : 0,
      need: $('o-split').checked ? ($('o-all').checked ? names().length : Math.min(names().length, Math.max(2, parseInt($('o-need').value, 10) || 2))) : 0,
      checkin_days: $('o-checkin').checked ? Math.min(90, Math.max(1, parseInt($('o-every').value, 10) || 30)) : 0,
      receipt: $('o-receipt').checked, reply: $('o-reply').checked, control: $('o-control').checked };
  }
  function allOpts() {
    const o = Object.assign(opts(), more());
    if (o.collect || o.pay || lock() === 'open' && o.extras.qr) { o.max_opens = 0; o.forward = true; }
    if (lock() === 'named') { o.max_opens = o.succession ? 1 : o.recipients; o.forward = false; }
    return o;
  }
  /* What the chosen rules mean, in plain words. Used in step 3 and on the done card. */
  function commentary(o, end) {
    const out = [];
    if (o.holders) out.push(o.holders + ' people each hold a key. ' + (o.need === o.holders ? 'All ' + o.holders + ' keys' : 'Any ' + o.need + ' of the keys') + ' must be added within the same 10 minutes, each from its holder\u2019s own device; then it opens at each of those places. At most ' + o.holders + ' places can have the link open at once. The keeper never reads a key or a name.');
    out.push((o.max_opens === 1 ? 'Opens once' : o.max_opens ? 'Opens ' + o.max_opens + ' times' : 'Opens any number of times')
      + (o.holders ? ', for the holders together.' : o.forward ? ', on any device that has link and PIN.' : ', only on the first device that opens it.'));
    if (o.checkin_days) out.push('Held while you check in here every ' + o.checkin_days + ' days. If you miss one you have 24 more hours to check in; after that it is released to whoever holds ' + (o.holders ? 'the keys.' : 'link and PIN.'));
    if (o.open_after) out.push('The keeper holds its part until ' + St.when(o.open_after) + '. Before that, link and PIN open nothing.');
    if (o.open_until) out.push('The window closes ' + St.when(o.open_until) + '. Unopened by then, it is destroyed.');
    out.push(o.max_opens === 1 && !o.checkin_days ? 'Destroyed right after that opening, or on ' + St.when(end) + ' if unopened.' : 'Stored until ' + St.when(end) + '. Renew before then, or it is destroyed.');
    if (o.recipients) out.push(o.recipients + ' people each get their own PIN' + (o.succession ? ', one after the other: if one does not open it in time, it passes to the next.' : '. You see who opened it.'));
    if (o.approvers) out.push(o.approvers.need + ' of ' + o.approvers.count + ' approvers must release it first. Approving shows them nothing.');
    if (o.pay) out.push(o.pay.mode === 'crowd' ? 'It opens for everyone once ' + o.pay.target + ' USDC has been paid to your address.' : 'Each reader pays ' + o.pay.price + ' USDC to your address' + (o.pay.mode === 'period' ? ' every ' + o.pay.period_days + ' days.' : ' once.'));
    if (o.collect) out.push('Up to ' + o.collect.seats + ' people can add to it and replace what they added' + (o.open_after ? ' until ' + St.when(o.open_after) + '; then it all opens together' : '') + (o.collect.reveal_count ? ' once ' + o.collect.reveal_count + ' have added' : '') + ', for ' + (o.collect.audience === 'all' ? 'everyone with the link.' : 'you only.'));
    if (o.duress) out.push('A duress PIN opens a decoy and tells you.');
    if (o.extras) {
      if (o.extras.view_only) out.push('Shown on screen only, with your name across it.');
      if (o.extras.view_secs) out.push('It leaves the screen ' + Math.round(o.extras.view_secs / 60) + ' minutes after opening.');
      if (o.extras.presence) out.push('It stays visible only while the holders are present.');
      if (o.extras.record) out.push('A signed record of what happened can be downloaded.');
      if (o.extras.witness) out.push('A witness link shows what happens, without the content.');
      if (o.extras.alarm_url) out.push('An alarm goes to your web address when something happens.');
      if (o.extras.origin) out.push('It will show as coming from ' + o.extras.origin + ' once you publish the proof.');
      if (o.extras.chain) out.push('It can be handed on, with each hand recorded.');
      if (o.extras.qr) out.push('You get a QR code to print.');
      if (o.extras.versions) out.push('You can post ' + o.extras.versions + ' new versions on the same link.');
    }
    if (o.receipt) out.push('You see the time of each opening here.');
    if (o.reply) out.push('The receiver can send you one sealed reply.');
    if (o.control) out.push('You can take it back while it is waiting.');
    return out;
  }
  function tidy() {                                      // show an add-on's inputs only while it is on
    document.querySelectorAll('.sub[data-for]').forEach(function (d) { d.hidden = !$(d.dataset.for).checked; });
    document.querySelectorAll('.addon:not(.lock)').forEach(function (a) { a.classList.toggle('on', a.querySelector('input[type=checkbox]').checked); });
    $('named-box').hidden = lock() !== 'named';
    $('o-pay-target-box').hidden = $('o-pay-mode').value !== 'crowd'; $('o-pay-period-box').hidden = $('o-pay-mode').value !== 'period';
    $('o-pay-price-l').textContent = $('o-pay-mode').value === 'crowd' ? 'at least, per person' : $('o-pay-mode').value === 'period' ? 'per reader, per period' : 'per reader';
    $('o-split').checked = lock() === 'keys';
    $('keys-box').hidden = !$('o-split').checked;
    if ($('o-split').checked) $('o-forward').checked = false;
    document.querySelectorAll('.addon.lock').forEach(function (a) { a.classList.toggle('on', a.querySelector('input').checked); });
    $('o-opens').disabled = $('o-any').checked; $('o-need-box').hidden = $('o-all').checked;
    plan();
  }
  function row() { const c = content(); return c ? (c.size <= lim.paid.sizes[0] ? 0 : c.size <= lim.paid.sizes[1] ? 1 : 2) : 0; }
  function cost(r, i) { return Number(lim.paid.plan[r][i]) ? St.usdc(lim.paid.plan[r][i]) : 'Free'; }
  /* The plan table: sizes down, periods across. The row follows the file; the period is the choice. */
  function plan() {
    const mine = row(), chosen = term(), t = $('plan');
    t.textContent = '';
    t.append(el('span', '', 'ph'));
    lim.paid.terms.forEach(function (d) { t.append(el('span', d === 365 ? '1 year' : d + ' days', 'ph')); });
    lim.paid.sizes.forEach(function (bytes, r) {
      t.append(el('span', 'Up to ' + round(bytes), 'pr' + (r === mine ? ' mine' : '')));
      lim.paid.terms.forEach(function (d, i) {
        if (r !== mine) return t.append(el('span', cost(r, i), 'pc off'));
        const cell = el('label', null, 'pc pick' + (d === chosen ? ' on' : '')), radio = el('input');
        radio.type = 'radio'; radio.name = 'term'; radio.value = d; radio.checked = d === chosen; radio.disabled = !lim.paid.on && cost(r, i) !== 'Free';
        cell.append(radio, el('strong', cost(r, i))); t.append(cell);
      });
    });
    const i30 = lim.paid.terms.indexOf(30);
    $('meter-renew').textContent = lim.paid.on ? 'To keep it after ' + St.when(Math.floor(Date.now() / 1000) + chosen * 86400).replace(/,.*$/, '') + ': renew from ' +
      St.usdc(lim.paid.plan[mine][i30 < 0 ? 0 : i30]) + ' USDC per 30 days. Unrenewed, a paid send is locked for 3 days, then destroyed.' : '';
  }
  function local(ts) { const d = new Date(ts * 1000 - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); }
  const USES = [
    ['burn', 'Burn after reading', 'One person, one opening, then gone. Free.'],
    ['until', 'Sealed until a date', 'Nobody can open it before the time you set.'],
    ['tender', 'Tender or quotation opening', 'Bidders add sealed offers and may change them. All open together at your deadline.'],
    ['inbox', 'Document inbox', 'Clients send you documents sealed. Only you read them.'],
    ['joint', 'Joint custody', 'A key for each person. It opens only when they add their keys together.'],
    ['gone', 'If I stop checking in', 'Held while you check in. Released to your key holders if you go silent.'],
    ['succession', 'Pass it down a line', 'First person has a week; if they do not claim it, it goes to the next.'],
    ['board', 'Company secret with approvers', 'Named approvers release it; they never see it. An alarm tells you.'],
    ['glass', 'Break-glass credentials', 'Opens once, visible for five minutes, with an alarm and a signed record.'],
    ['sell', 'Sell a file or report', 'Each reader pays you directly before it opens.'],
    ['crowd', 'Funded release', 'It opens for everyone once a total has been paid to you.'],
    ['feed', 'Paid updates', 'Readers pay per period; you post new versions on the same link.'],
    ['vote', 'Vote or survey', 'People answer without names. Answers open together at closing.'],
    ['swap', 'Exchange', 'Two people each add something. Both open only when both are in.'],
    ['seal', 'Certificate that cannot be faked', 'A printed QR opens the original, with a signed record and your domain.'],
    ['first', 'First to open wins', 'Sent to many, opens for one.'],
    ['custody', 'Evidence or sample custody', 'Handed from person to person, every hand recorded.'],
    ['year', 'Keep it a year', 'Long storage with take-back and a read receipt.']];
  function recipe(name) {
    const now = Math.floor(Date.now() / 1000);
    function lockIs(v) { document.querySelector('input[name=lock][value=' + v + ']').checked = true; }
    function tick() { Array.prototype.forEach.call(arguments, function (id) { $(id).checked = true; }); }
    function keysLock() { lockIs('keys'); $('o-all').checked = false; $('o-need').value = 2; if (names().length < 3) $('o-names').value = 'Holder 1\nHolder 2\nHolder 3'; }
    lockIs('pin');
    document.querySelectorAll('.wz .addon:not(.lock) > .check > input[type=checkbox]').forEach(function (i) { i.checked = false; });
    $('o-any').checked = false; $('o-all').checked = true; $('o-succ').checked = false;
    function pickTerm(d) { document.querySelectorAll('input[name=term]').forEach(function (r) { r.checked = false; }); termDays = d; }
    pickTerm(lim.free_keep / 86400);
    if (name === 'until') { pickTerm(30); tick('o-win-a', 'o-receipt'); $('o-after').value = local(now + 7 * 86400); }
    if (name === 'joint') { pickTerm(90); keysLock(); tick('o-receipt'); }
    if (name === 'gone') { pickTerm(365); keysLock(); tick('o-checkin', 'o-recovery'); $('o-every').value = 30; }
    if (name === 'year') { pickTerm(365); tick('o-control', 'o-receipt'); }
    if (name === 'tender') { pickTerm(30); lockIs('open'); tick('o-collect', 'o-win-a', 'o-record'); $('o-audience').value = 'owner'; $('o-anon').checked = false; $('o-reveal').value = 0; $('o-seats').value = 5; $('o-attach').checked = true; if (!$('o-fields').value.trim()) $('o-fields').value = 'Company\nPrice\nDelivery in days\nRemarks'; $('o-after').value = local(now + 14 * 86400); }
    if (name === 'inbox') { pickTerm(90); lockIs('open'); tick('o-collect'); $('o-audience').value = 'owner'; $('o-anon').checked = false; $('o-reveal').value = 0; $('o-seats').value = 20; $('o-attach').checked = true; if (!$('o-fields').value.trim()) $('o-fields').value = 'Your name\nWhat this is'; }
    if (name === 'vote') { pickTerm(30); lockIs('open'); tick('o-collect', 'o-win-a'); $('o-audience').value = 'all'; $('o-anon').checked = true; $('o-attach').checked = false; $('o-reveal').value = 0; $('o-seats').value = 20; $('o-fields').value = 'Your answer (yes / no)'; $('o-after').value = local(now + 3 * 86400); }
    if (name === 'swap') { pickTerm(30); lockIs('open'); tick('o-collect'); $('o-audience').value = 'all'; $('o-anon').checked = false; $('o-attach').checked = true; $('o-seats').value = 2; $('o-reveal').value = 2; $('o-fields').value = 'Your name\nWhat you are putting in'; }
    if (name === 'succession') { pickTerm(90); lockIs('named'); $('o-succ').checked = true; $('o-succ-days').value = 7; if (lines('o-rnames', 20).length < 2) $('o-rnames').value = 'First person\nSecond person'; tick('o-receipt', 'o-recovery'); }
    if (name === 'board') { pickTerm(90); tick('o-approve', 'o-alarm', 'o-record', 'o-witness'); $('o-aneed').value = 2; if (!lines('o-anames', 10).length) $('o-anames').value = 'Approver 1\nApprover 2\nApprover 3'; }
    if (name === 'glass') { pickTerm(90); tick('o-timer', 'o-alarm', 'o-record', 'o-control'); $('o-timer-min').value = 5; }
    if (name === 'sell') { pickTerm(30); lockIs('open'); tick('o-pay', 'o-summary'); $('o-pay-mode').value = 'each'; }
    if (name === 'crowd') { pickTerm(30); lockIs('open'); tick('o-pay', 'o-summary'); $('o-pay-mode').value = 'crowd'; }
    if (name === 'feed') { pickTerm(365); lockIs('open'); tick('o-pay', 'o-versions', 'o-summary'); $('o-pay-mode').value = 'period'; $('o-versions-n').value = 12; }
    if (name === 'seal') { pickTerm(365); lockIs('open'); tick('o-qr', 'o-record', 'o-origin', 'o-viewonly'); }
    if (name === 'first') { lockIs('open'); }
    if (name === 'custody') { pickTerm(90); tick('o-chain', 'o-record', 'o-receipt'); }
    tidy(); requote();
  }

  function requote() {
    clearTimeout(timer);
    tidy();
    timer = setTimeout(async function () {
      const c = content();
      try {
        quoted = await (await St.api('POST', '/quote', Object.assign({ plain: (c && c.size) || 1, kind: kind() }, allOpts()))).json();
        say('msg', '');
      } catch (e) { quoted = { micro: 0, lines: [], total: '0', error: e.message }; say('msg', e.message, true); }
      $('meter-lines').textContent = '';
      quoted.lines.forEach(function (l) { const li = el('li'); li.append(el('span', l.label), el('span', St.usdc(l.usdc))); $('meter-lines').append(li); });
      $('meter-total').textContent = quoted.micro ? St.usdc(quoted.total) + ' USDC' : 'Free';
      $('go').textContent = quoted.micro ? 'Pay ' + St.usdc(quoted.total) + ' USDC, then seal and send' : 'Seal and send, free';
      $('wz-sum').textContent = quoted.error ? '' : quoted.micro ? 'So far: ' + St.usdc(quoted.total) + ' USDC' : 'So far: free';
      $('review').textContent = '';
      const c2 = content();
      [(c2 ? (c2.kind === 'note' ? 'A note, ' + c2.words + ' words' : c2.name + ', ' + St.size(c2.size)) : 'Nothing chosen yet') + ', from ' + ($('from').value.trim() || '(no name yet)') + '.']
        .concat(commentary(allOpts(), Math.floor(Date.now() / 1000) + term() * 86400))
        .forEach(function (t) { $('review').append(el('li', t)); });
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
    const id = C.newId(), secret = C.random(32), share = C.random(32), who = names();
    const pin = o.holders ? await C.jointPin(secret) : C.newPin();
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
    let joint = null;
    if (o.holders) {                                       // a key for each person, and what the keeper needs to check them unread
      const roomSecret = C.random(16), rm = await C.room(roomSecret, id), ks = C.split(secret, o.holders, o.need), hashes = [];
      for (let i = 0; i < ks.length; i++) hashes.push(await C.sha256hex(await rm.seal(C.parsePart(ks[i]))));
      joint = { keys: ks, link: C.jointLink(o.need, who, roomSecret) };
      o = Object.assign({}, o, { room_hash: rm.authHash, seat_hashes: hashes });
    }
    const now0 = Math.floor(Date.now() / 1000), from = $('from').value.trim(), art = {}, ex = o.extras || {};
    const base = location.origin + St.BASE + (ex.name ? '/send/n/' + ex.name : '/send/o/' + id) + '#';
    let contentKey = key, decoy = null;
    o = Object.assign({}, o);
    if (o.recipients) {                                    // one sealed content, a wrapped key for each person's own PIN
      const raw = C.random(32), people = lines('o-rnames', 20), d = Math.max(1, parseInt($('o-succ-days').value, 10) || 7) * 86400, list = [], used = {};
      contentKey = await C.aesKey(raw); art.pins = [];
      for (let i = 0; i < people.length; i++) {
        let p = C.newPin(); while (used[p]) p = C.newPin(); used[p] = 1;
        steps.set(2, 'run', 'Making a PIN and a wrapped key for ' + people[i] + '…', 0.2);
        const it = { pin_tag: await C.pinTag(keys, p), wrap: await C.wrapKey(await C.fileKey(secret, share, p, id), id, raw) };
        if (o.succession) { it.after = i ? now0 + d * i : 0; it.until = i < people.length - 1 ? now0 + d * (i + 1) : 0; it.unless = i ? i - 1 : null; }
        list.push(it); art.pins.push({ name: people[i], pin: p, from: it.after || 0, to: it.until || 0 });
      }
      o.recipients = list;
    }
    if (o.approvers) {
      const people = lines('o-anames', 10), hashes = []; art.approvers = [];
      for (let i = 0; i < people.length; i++) {
        const t = C.random(32); hashes.push(await C.sha256hex(t));
        art.approvers.push({ name: people[i], link: base + 'a' + i + '.' + C.b64u(t) + '.' + C.b64u(new TextEncoder().encode(JSON.stringify({ from: from, line: $('note').value.trim() }))) });
      }
      o.approvers = { need: o.approvers.need, hashes: hashes };
    }
    if (ex.witness) { const t = C.random(32); o.witness_hash = await C.sha256hex(t); art.witness = base + 'w' + C.b64u(t); }
    if (ex.recovery) { const t = C.random(32); o.recover_hash = await C.sha256hex(t); art.recovery = C.b64u(t); }
    if (o.summary) o.summary = await C.sealSmall(keys.preview, id, 'summary', { text: $('o-summary-text').value.trim() });
    if (o.duress) {
      let p2 = C.newPin(); while (p2 === pin) p2 = C.newPin();
      const dShare = C.random(32), dKey = await C.fileKey(secret, dShare, p2, id), text = new TextEncoder().encode($('o-decoy').value.trim() || 'Nothing here yet.');
      decoy = await C.sealPart(dKey, id, 0, 1, text); art.duress = p2;
      o.duress = { pin_tag: await C.pinTag(keys, p2), share: C.b64u(dShare), size: decoy.length,
        meta: await C.sealSmall(dKey, id, 'meta', { name: 'Note', type: 'text/plain;charset=utf-8', size: text.length, kind: 'note' }) };
    }
    if (o.collect) {
      const box = o.collect.audience === 'owner' ? await St.boxKey(id, true) : null;
      const pub = box ? C.b64u(new Uint8Array(await crypto.subtle.exportKey('raw', box.publicKey))) : null;
      o.collect = Object.assign({}, o.collect, { pub: pub, form: await C.sealSmall(keys.preview, id, 'form',
        { fields: lines('o-fields', 12), file: $('o-attach').checked, anon: o.collect.anon, pub: pub }) });
    }
    const made = await (await St.api('POST', '/files', Object.assign({
      id: id, kind: c.kind, size: c.size + parts * C.TAG, parts: parts, auth_hash: keys.authHash, pin_tag: await C.pinTag(keys, pin),
      owner_pub: await C.publicRaw(device), keeper_share: C.b64u(share),
      preview: await C.sealSmall(keys.preview, id, 'preview', { from: from, note: $('note').value.trim() }),
      meta: await C.sealSmall(contentKey, id, 'meta', { name: c.name, type: c.type, size: c.size, kind: c.kind, mark: from,
        view_only: ex.view_only || 0, view_secs: ex.view_secs || 0, presence: ex.presence || 0, card: ex.card || '' })
    }, o))).json();
    const link = base + C.b64u(secret) + (ex.pin_in_link ? '.' + pin : '');
    if (ex.origin) art.origin = { domain: ex.origin, line: await C.publicRaw(device) };
    if (ex.qr) art.qr = 1;
    const links = joint ? joint.keys.map(function (k, i) { return { name: who[i], key: k }; }) : null;
    const shared = joint ? base + joint.link : link;
    const rec = { id: id, name: c.name, kind: c.kind, size: c.size, created_at: Math.floor(Date.now() / 1000), expires_at: made.expires_at, link: link, shared: shared, pin: pin,
      parts: parts, rules: o, links: links, art: art, recover: art.recovery || null, open_link: !!ex.pin_in_link, named: !!art.pins, paid: made.pay ? made.pay.amount : null };
    await St.remember(rec);
    if (made.pay) {
      steps.set(2, 'run', 'Deposited. Waiting for your payment of ' + St.usdc(made.pay.amount) + ' USDC before anything is uploaded…', 0.6);
      await payment(id, made.pay);
    }
    steps.set(2, 'done', commentary(o, made.expires_at).join(' ') + (made.pay ? ' Paid ' + St.usdc(made.pay.amount) + ' USDC.' : ''));

    if (decoy) await St.put('/files/' + id + '/decoy', decoy, { 'X-Send-Upload': made.upload, 'Content-Type': 'application/octet-stream' });
    steps.set(3, 'run');
    await pause(250);
    steps.set(3, 'done', parts === 1 ? St.size(c.size) + ' fits in one part.' : St.size(c.size) + ' in ' + parts + ' parts of up to 4 MB.');

    for (let n = 0; n < parts; n++) {
      steps.set(4, 'run', 'Sealing part ' + (n + 1) + ' of ' + parts + '. Each is numbered, so none can be swapped, dropped or cut.', n / parts);
      const plain = new Uint8Array(await c.blob.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer());
      const sealed = await C.sealPart(contentKey, id, n, parts, plain);
      steps.set(4, n + 1 === parts ? 'done' : 'run', n + 1 === parts ? (parts === 1 ? 'The part is' : 'All ' + parts + ' parts are') + ' sealed with AES-256-GCM, numbered so none can be swapped, dropped or cut.' : null, (n + 1) / parts);
      steps.set(5, 'run', 'Storing part ' + (n + 1) + ' of ' + parts + ' with the keeper…', n / parts);
      await store(id, n, sealed, made.upload, function (f) { steps.set(5, 'run', null, (n + f) / parts); });
    }
    steps.set(5, 'done', 'Stored. The keeper holds sealed bytes and cannot read them.');
    await pause(500);
    return { rec: rec, lines: commentary(o, made.expires_at) };
  }

  function showDone(r) {
    $('link').textContent = r.rec.shared || r.rec.link; $('pin').textContent = r.rec.pin;
    $('many-links').hidden = !r.rec.links; $('pin-box').hidden = !!r.rec.links;
    $('links').textContent = '';
    (r.rec.links || []).forEach(function (l) {
      const li = el('li'), row = el('div', null, 'copyable'), b = el('button', 'Copy', 'btn btn-sm'); b.type = 'button';
      b.addEventListener('click', function () { navigator.clipboard.writeText(l.key).then(function () { b.textContent = 'Copied'; }); });
      row.append(el('code', l.key), b); li.append(el('strong', l.name), row); $('links').append(li);
    });
    $('done-lede').textContent = r.rec.links ? 'Send the link to everyone. Give each person only their own key, by a different channel. When they want to open it, each opens the link on their own device and adds their key; it opens for them when ' + (r.rec.rules.need === r.rec.rules.holders ? 'all' : 'any ' + r.rec.rules.need) + ' of the keys are in within 10 minutes.'
      : 'Send the link any way you like. Tell the PIN by phone or in person, not in the same message as the link.';
    const A = r.rec.art || {}, box = $('artifacts'); box.textContent = '';
    function item(label, value, note) {
      const l = el('label', label, 'label'), row = el('div', null, 'copyable'), b = el('button', 'Copy', 'btn btn-sm'); b.type = 'button';
      b.addEventListener('click', function () { navigator.clipboard.writeText(value).then(function () { b.textContent = 'Copied'; }); });
      row.append(el('code', value), b); box.append(l, row); if (note) box.append(el('p', note, 'note'));
    }
    $('pin-box').hidden = !!r.rec.links || !!r.rec.named || !!r.rec.open_link;
    if (r.rec.open_link) $('done-lede').textContent = 'Anyone who has this link can use it. The PIN is inside the link.';
    (A.pins || []).forEach(function (p) { item('PIN for ' + p.name + (p.from || p.to ? ' (' + (p.from ? 'from ' + St.when(p.from) : 'from now') + (p.to ? ' until ' + St.when(p.to) : '') + ')' : ''), p.pin); });
    if (A.pins) $('done-lede').textContent = 'Send everyone the same link. Tell each person only their own PIN.';
    (A.approvers || []).forEach(function (p) { item('Approver link for ' + p.name, p.link); });
    if (A.witness) item('Witness link', A.witness, 'Shows what happens to this send and gives the signed record. It cannot open it.');
    if (A.duress) item('Duress PIN', A.duress, 'Opens only the decoy, and tells you it was used.');
    if (A.recovery) item('Recovery code', A.recovery, 'Keep it somewhere safe. With it you can take control of this send from another browser. It is also in the backup file.');
    if (A.origin) item('Publish this line at https://' + A.origin.domain + '/.well-known/innernet-send.txt', A.origin.line, 'Then press "Check origin" on this send in your list below.');
    if (A.qr && window.InnernetQR) {
      const wrap = el('div', null, 'qr'); wrap.append(window.InnernetQR.svg(r.rec.shared || r.rec.link, 220));
      const pr = el('button', 'Print this page', 'btn btn-sm'); pr.type = 'button'; pr.addEventListener('click', function () { window.print(); });
      box.append(el('label', 'Printed seal', 'label'), wrap, pr);
    }
    $('set-lines').textContent = '';
    r.lines.forEach(function (t) { $('set-lines').append(el('li', t)); });
    $('work').hidden = true; $('done').hidden = false;
    $('done').scrollIntoView({ block: 'start' });
  }

  async function readReply(rec, sealed) {
    const keys = await C.linkKeys(C.unb64u(rec.link.split('#')[1].split('.')[0]), rec.id);
    return (await C.openSmall(keys.preview, rec.id, 'reply', sealed)).text;
  }

  /* What others added: fetched sealed, opened here with the sender's box key (or the link key). */
  async function readAdds(rec, s, into) {
    const secret = C.unb64u(rec.link.split('#')[1].split('.')[0]);
    const list = await (await St.api('POST', '/files/' + rec.id + '/adds/list', await C.signRequest(await St.deviceKey(), 'adds', rec.id))).json(), box = s.collect.audience === 'owner' ? await St.boxKey(rec.id, false) : null, shared = await C.subKey(secret, rec.id, 'adds');
    if (s.collect.audience === 'owner' && !box) throw new Error('The key that opens these is in the browser this was sent from.');
    const table = el('table', null, 'adds');
    for (const e of list.entries) {
      const d = await St.deviceKey(), blob = await St.bytes('POST', '/files/' + rec.id + '/adds/' + e.entry, await C.signRequest(d, 'adds', rec.id));
      const got = C.unpack(box ? await C.openFrom(box, rec.id, blob) : await C.openWith(shared, rec.id, blob));
      const tr = el('tr'); tr.append(el('th', '#' + e.entry + ' · ' + St.when(e.received_at) + (e.changes ? ' · changed ' + e.changes + '×' : '')));
      const td = el('td');
      Object.keys(got.obj.answers || {}).forEach(function (k) { td.append(el('div', k + ': ' + got.obj.answers[k])); });
      if (got.obj.file) { const b = el('button', 'Save ' + got.obj.file.name, 'btn btn-sm'); b.type = 'button'; b.addEventListener('click', function () { St.download(got.obj.file.name, new Blob([got.file], { type: got.obj.file.type })); }); td.append(b); }
      tr.append(td); table.append(tr);
    }
    const old = into.parentNode.querySelector('table.adds'); if (old) old.remove();
    into.after(table);
  }
  /* A new version behind the same link: a new keeper part, so a new key; the link and PIN stay. */
  function newVersion(rec, done) {
    return new Promise(function (ok, bad) {
      const f = el('input'); f.type = 'file';
      f.addEventListener('change', async function () {
        try {
          const file = f.files[0]; if (!file) return ok();
          const secret = C.unb64u(rec.link.split('#')[1].split('.')[0]), share = C.random(32), key = await C.fileKey(secret, share, rec.pin, rec.id), parts = C.partCount(file.size), d = await St.deviceKey();
          const v = await (await St.api('POST', '/files/' + rec.id + '/version', Object.assign(await C.signRequest(d, 'version', rec.id), { size: file.size + parts * C.TAG, parts: parts, keeper_share: C.b64u(share),
            meta: await C.sealSmall(key, rec.id, 'meta', { name: file.name, type: file.type || 'application/octet-stream', size: file.size, kind: 'file' }) }))).json();
          for (let n = 0; n < parts; n++) await St.put('/files/' + rec.id + '/vparts/' + n, await C.sealPart(key, rec.id, n, parts, new Uint8Array(await file.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer())), { 'X-Send-Upload': v.upload, 'Content-Type': 'application/octet-stream' });
          rec.name = file.name; rec.size = file.size; await St.remember(rec); await done(); ok();
        } catch (e) { bad(e); }
      });
      f.click();
    });
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
      const copy = el('button', rec.links ? 'Copy link and all keys' : 'Copy link', 'btn btn-sm'), alive = el('button', 'Check in now', 'btn btn-sm btn-light'), more = el('button', 'Renew', 'btn btn-sm'), back = el('button', 'Take it back', 'btn btn-sm btn-danger'), forget = el('button', 'Remove from this list', 'btn btn-sm');
      const ext = el('div', null, 'inline ext'); ext.hidden = true;
      const extra = el('div', null, 'row-actions extra');
      ext.append(el('span', 'Add to the end date:'));
      [copy, alive, more, back, forget].forEach(function (b) { b.type = 'button'; });
      copy.hidden = alive.hidden = more.hidden = back.hidden = true;
      acts.append(alive, copy, more, back, forget);
      li.append(head, state, warn, reply, acts, extra, ext);
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
          label = opened.length ? 'Opened' : s.held || s.open_after > now ? 'Held' : 'Waiting';
          text = (s.held ? 'Held while you check in. Check in before ' + St.when(s.checkin_due) + ', or it is released. ' : '') + (s.open_after > now ? 'Held until ' + St.when(s.open_after) + '. ' : '') + (s.open_until ? 'Closes ' + St.when(s.open_until) + '. ' : '') + (s.holders ? s.need + ' of ' + s.holders + ' keys needed. ' : '') + (rec.links || rec.named || rec.open_link ? '' : 'PIN ' + rec.pin + '. ') + 'Ends ' + St.when(s.expires_at) + '.';
        }
        if (opened.length && s.state !== 'spent') text += ' Opened' + (opened[0].ts ? ' ' + opened.map(function (e) { return St.when(e.ts); }).join(', ') : opened.length > 1 ? ' ' + opened.length + ' times' : '') + '.';
        else if (s.state === 'live') text += ' Not opened yet.';
        if (s.pin_fails) text += ' Wrong PIN tried ' + s.pin_fails + ' time' + (s.pin_fails > 1 ? 's' : '') + '.';
        if (s.paid) text += ' Paid ' + St.usdc(s.paid) + ' USDC.';
        state.textContent = text; chip.textContent = label; chip.className = 'chip ' + (s.state === 'dead' ? 'off' : opened.length ? 'on' : '');
        const live = s.state === 'live';
        alive.hidden = !(live && s.held);
        copy.hidden = !live; more.hidden = !(live && lim.paid.on); back.hidden = !(live && s.control);
        const left = s.expires_at - now;
        const soon = live && left < Math.max(86400, 0.2 * (s.expires_at - s.created_at)), due = live && s.held && s.checkin_due - now < 3 * 86400;
        warn.hidden = !(soon || due);
        warn.textContent = due ? 'Check in within ' + St.left(s.checkin_due) + ', or it is released to its holders.' : 'Ends in ' + St.left(s.expires_at) + '.' + (lim.paid.on ? ' Renew it to keep it.' : ' It is destroyed then.');
        if (s.locked) { chip.textContent = 'Locked'; warn.hidden = false; warn.textContent = 'Its time ended. Nobody can open it now. Renew before ' + St.when(s.destroy_at) + ', or it is destroyed.'; copy.hidden = true; }
        if (!ext.dataset.made) {
          ext.dataset.made = '1';
          s.renew.forEach(function (r) {
            const b = el('button', (r.days === 365 ? '1 year' : r.days + ' days') + ' · ' + St.usdc(r.usdc), 'btn btn-sm'); b.type = 'button';
            b.addEventListener('click', function () { renew(r.days); }); ext.append(b);
          });
        }
        extra.textContent = '';
        function tool(label, fn) { const b = el('button', label, 'btn btn-sm'); b.type = 'button'; b.addEventListener('click', function () { b.disabled = true; Promise.resolve(fn()).catch(function (e) { state.textContent = e.message; }).finally(function () { b.disabled = false; }); }); extra.append(b); }
        let moreText = '';
        if (s.approvals) moreText += ' Approved by ' + s.approvals.have + ' of ' + s.approvals.need + ' needed.';
        if (s.named) { const who = s.events.filter(function (e) { return e.event.indexOf('opened by recipient ') === 0; }).map(function (e) { const p = ((rec.art || {}).pins || [])[Number(e.event.slice(20)) - 1]; return p ? p.name : e.event.slice(10); }); moreText += who.length ? ' Opened by ' + who.join(', ') + '.' : ''; }
        if (s.paylock) moreText += s.paylock.mode === 'crowd' ? ' Raised ' + St.usdc(s.paylock.raised) + ' of ' + St.usdc(s.paylock.target) + ' USDC.' : ' Sold to ' + s.paylock.sold + ' of ' + s.paylock.buyers + '; ' + St.usdc(s.paylock.raised) + ' USDC paid to you.';
        if (s.collect) moreText += ' ' + s.collect.count + ' of ' + s.collect.seats + ' have added.' + (s.collect.revealed ? '' : ' Closed to everyone until it opens.');
        if (s.events.some(function (e) { return e.event === 'duress PIN used'; })) moreText += ' The duress PIN was used.';
        if (s.version > 1) moreText += ' Version ' + s.version + '.';
        if (s.origin) moreText += ' Shown as from ' + s.origin + '.';
        state.textContent += moreText;
        if (s.collect && s.collect.count && s.collect.revealed) tool('Read what was added', function () { return readAdds(rec, s, extra); });
        if (s.extras.record || s.state === 'dead' || s.state === 'spent') tool('Signed record', async function () { St.download('innernet-record-' + rec.id.slice(0, 8) + '.json', new Blob([JSON.stringify(await act(rec.id, 'record'), null, 2)], { type: 'application/json' })); });
        if (s.origin_pending && live) tool('Check origin', async function () { await act(rec.id, 'origin'); return refresh(); });
        if (s.versions_left > 0 && live) tool('Post a new version (' + s.versions_left + ' left)', function () { return newVersion(rec, refresh); });
        if (s.reply) readReply(rec, s.reply).then(function (t) { reply.textContent = 'Reply: ' + t; reply.hidden = false; }).catch(function () {});
      }
      function refresh() {
        return act(rec.id, 'status').then(show).catch(function (e) {
          chip.textContent = 'Gone'; chip.className = 'chip off';
          state.textContent = e.status === 404 ? 'No longer on record (ended more than 30 days ago).' : e.message;
        });
      }
      refresh();
      alive.addEventListener('click', function () { alive.disabled = true; act(rec.id, 'checkin').then(refresh, function (e) { state.textContent = e.message; }).finally(function () { alive.disabled = false; }); });
      copy.addEventListener('click', function () { navigator.clipboard.writeText(rec.links ? rec.shared + '\n' + rec.links.map(function (l) { return l.name + ': ' + l.key; }).join('\n') : rec.link).then(function () { copy.textContent = 'Copied'; }); });
      forget.addEventListener('click', function () { St.forget(rec.id).then(renderSent); });
      back.addEventListener('click', function () { back.disabled = true; act(rec.id, 'revoke').then(refresh, function (e) { state.textContent = e.message; back.disabled = false; }); });
      more.addEventListener('click', function () { ext.hidden = !ext.hidden; });
      async function renew(daysMore) {
        if (busy) return;
        busy = true;
        try {
          const r = await act(rec.id, 'extend', { days: daysMore });
          if (r.pay) {
            $('six').hidden = true; $('bar').hidden = true; say('work-msg', '');
            $('work-title').textContent = 'Renew “' + rec.name + '” for ' + r.days + ' more days';
            $('form').hidden = true; $('done').hidden = true; $('work').hidden = false; $('work').scrollIntoView({ block: 'start' });
            await payment(rec.id, r.pay);
          }
          ext.hidden = true;
        } catch (e) { state.textContent = e.message; }
        $('work').hidden = true; $('form').hidden = false;
        busy = false;
        refresh();
      }
    });
  }

  /* The wizard: one question per screen. Nothing is sent until the last screen. */
  let at = 0;
  function wizard() {
    const pages = Array.prototype.slice.call(document.querySelectorAll('.wz'));
    pages.forEach(function (p, i) {
      const b = el('button', (i + 1) + '. ' + p.dataset.title, 'wz-dot'); b.type = 'button';
      b.addEventListener('click', function () { if (i <= at || check()) go(i); });
      $('wz-nav').append(b);
    });
    function check() {
      const c = content();
      if (at === 0) {
        if (!c) return say('msg', 'Choose a file first.', true), false;
        if (!c.size) return say('msg', c.kind === 'note' ? 'Write the note first.' : 'That file is empty.', true), false;
        if (c.kind === 'note' && (c.words > 500 || c.size > lim.note_bytes)) return say('msg', 'A note is at most 500 words.', true), false;
        if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true), false;
      }
      if ($('o-split').checked && names().length < 2) return say('msg', 'Split custody needs at least 2 names.', true), false;
      if (quoted.error) return say('msg', quoted.error, true), false;
      say('msg', ''); return true;
    }
    function go(i) {
      at = Math.max(0, Math.min(pages.length - 1, i));
      pages.forEach(function (p, k) { p.hidden = k !== at; });
      Array.prototype.forEach.call($('wz-nav').children, function (b, k) { b.className = 'wz-dot' + (k === at ? ' on' : k < at ? ' done' : ''); });
      const last = at === pages.length - 1;
      $('wz-back').hidden = at === 0; $('wz-next').hidden = last; $('go').hidden = !last; $('wz-free').hidden = at !== 0;
      $('wz-next').textContent = 'Next: ' + (last ? '' : pages[at + 1].dataset.title);
    }
    $('wz-next').addEventListener('click', function () { if (check()) go(at + 1); });
    $('wz-back').addEventListener('click', function () { say('msg', ''); go(at - 1); });
    $('wz-free').addEventListener('click', function () { recipe('burn'); if (check()) { go(pages.length - 1); setTimeout(function () { $('form').requestSubmit(); }, 400); } });
    $('recipes').addEventListener('click', function (e) { if (e.target.closest('button') && check()) go(1); });
    wizard.go = go;
    go(0);
  }

  function pick(file) {
    picked = file || null;
    $('drop-title').textContent = picked ? picked.name : 'Choose a file, or drop it here';
    $('drop').classList.toggle('has', !!picked);
    say('file-msg', picked ? St.size(picked.size) : 'Up to ' + round(lim.max_bytes) + ' free' + (lim.paid.on ? '. Larger, up to ' + round(lim.paid.max_bytes) + ', is paid.' : '.'));
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
    termDays = lim.free_keep / 86400;
    document.querySelectorAll('.price[data-p]').forEach(function (b) { b.textContent = '+' + St.usdc(lim.paid.prices[b.dataset.p]) + (b.dataset.s || ''); });
    $('plan').addEventListener('change', requote);
    if (!lim.paid.on) {
      $('paid-off').hidden = false;
      document.querySelectorAll('.paid input, .paid textarea').forEach(function (i) { i.disabled = true; });

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
    $('form').addEventListener('input', requote);
    USES.forEach(function (u) { const b = el('button', null, 'use'); b.type = 'button'; b.dataset.r = u[0]; b.append(el('strong', u[1]), el('span', u[2])); $('recipes').append(b); });
    $('exp').addEventListener('click', async function () { St.download('innernet-send-backup.json', new Blob([JSON.stringify({ type: 'innernet-send-backup/1', sent: await St.sent() })], { type: 'application/json' })); });
    $('imp').addEventListener('change', async function () {
      try {
        const data = JSON.parse(await $('imp').files[0].text()), d = await St.deviceKey();
        for (const rec of data.sent || []) {
          if (rec.recover) { try { await St.api('POST', '/files/' + rec.id + '/recover', Object.assign({ code: rec.recover, owner_pub: await C.publicRaw(d) }, await C.signRequest(d, 'recover', rec.id))); } catch (e) { /* ended, or the code was used elsewhere */ } }
          await St.remember(rec);
        }
        renderSent();
      } catch (e) { say('msg', 'That is not a backup file.', true); }
    });
    wizard();
    $('recipes').addEventListener('click', function (e) { const b = e.target.closest('button'); if (b) recipe(b.dataset.r); });
    if (!lim.paid.on) $('recipes').querySelectorAll('button').forEach(function (b) { b.disabled = ['burn', 'first'].indexOf(b.dataset.r) < 0; });
    $('again').addEventListener('click', function () {
      $('done').hidden = true; $('form').hidden = false; $('form').reset(); $('file-box').hidden = false; $('note-box').hidden = true;
      say('text-msg', ''); recipe('burn'); pick(null); wizard.go(0);
    });
    $('form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) return;
      const c = content();
      if (!c) return say('msg', 'Choose a file first.', true);
      if (!c.size) return say('msg', c.kind === 'note' ? 'Write the note first.' : 'That file is empty.', true);
      if (c.kind === 'note' && (c.words > 500 || c.size > lim.note_bytes)) return say('msg', 'A note is at most 500 words.', true);
      if ($('o-split').checked && names().length < 2) return say('msg', 'Split custody needs at least 2 names.', true);
      if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true);
      if (quoted.error) return say('msg', quoted.error, true);
      busy = true; $('go').disabled = true;
      send(c, allOpts()).then(function (r) { say('msg', ''); showDone(r); })
        .catch(function (e) { $('work').hidden = true; $('form').hidden = false; say('msg', 'Not sent: ' + e.message, true); })
        .finally(function () { busy = false; $('go').disabled = false; renderSent(); tally(); });
    });
    pick(null);
    renderSent();
    tally();
  }
  start().catch(function (e) { $('off').textContent = 'This page could not start: ' + e.message; $('off').hidden = false; });
})();
