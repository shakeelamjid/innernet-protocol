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
  function fmt() { const f = document.querySelector('input[name=fmt]:checked'); return f ? Number(f.value) : 0; }
  function words(t) { if (fmt() === 2 && window.InnernetHtml) return window.InnernetHtml.words(t); const m = t.trim().match(/\S+/g); return m ? m.length : 0; }
  function round(n) { return St.size(n).replace(/\.0+ /, ' '); }
  function days(s) { const d = Math.round(s / 86400); return d === 1 ? '1 day' : d + ' days'; }

  function content() {
    if (kind() === 'note') {
      const text = $('text').value.trim();
      const bytes = new TextEncoder().encode(text);
      return { kind: 'note', name: 'Note', type: fmt() === 2 ? 'text/html;charset=utf-8' : 'text/plain;charset=utf-8', size: bytes.length, blob: new Blob([bytes]), words: words(text) };
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
    if (on('o-device')) e.device = 1;
    if (on('o-spread')) e.spread = Math.min(32, Math.max(6, parseInt($('o-spread-n').value, 10) || 8));
    if (on('o-origin') && $('o-origin-dom').value.trim()) e.origin = $('o-origin-dom').value.trim().toLowerCase();
    if (on('o-name') && $('o-name-v').value.trim()) e.name = $('o-name-v').value.trim().toLowerCase();
    if (on('o-versions')) e.versions = Math.max(1, parseInt($('o-versions-n').value, 10) || 1);
    if (lock() === 'open' || collect || pay) e.pin_in_link = 1;
    if ($('o-strong').checked) e.strong_pin = 1;
    e.pin_tries = Math.min(10, Math.max(1, parseInt($('o-tries').value, 10) || 5));
    const m = { extras: e };
    if (named) { m.recipients = lines('o-rnames', 20).length; m.succession = on('o-succ'); }
    if (on('o-approve') && lines('o-anames', 10).length) m.approvers = { count: lines('o-anames', 10).length, need: Math.min(lines('o-anames', 10).length, Math.max(1, parseInt($('o-aneed').value, 10) || 1)) };
    if (on('o-duress')) m.duress = true;
    if (on('o-summary') && $('o-summary-text').value.trim()) m.summary = '1';
    if (collect) m.collect = { audience: $('o-audience').value, anon: $('o-anon').checked, seats: Math.max(1, parseInt($('o-seats').value, 10) || 1), reveal_count: Math.max(0, parseInt($('o-reveal').value, 10) || 0) };
    if (pay) m.pay = { mode: $('o-pay-mode').value, price: $('o-pay-price').value, to: $('o-pay-to').value.trim(), buyers: Math.max(1, parseInt($('o-pay-buyers').value, 10) || 1), target: $('o-pay-target').value, period_days: Math.max(1, parseInt($('o-pay-period').value, 10) || 30) };
    return m;
  }
  /* The form others fill in: a list of questions, each with a kind of answer. */
  const KINDS = [['text', 'Short text'], ['long', 'Long text'], ['number', 'Number'], ['date', 'Date'], ['choice', 'Choice from a list'], ['yes', 'Yes or no']];
  function addRow(f) {
    f = typeof f === 'string' ? { q: f } : (f || {});
    const row = el('div', null, 'formrow'), q = el('input', null, 'field'), k = el('select', null, 'field'), opts = el('input', null, 'field'), req = el('label', null, 'check'), box = el('input'), rm = el('button', 'Remove', 'btn btn-sm');
    q.placeholder = 'Question'; q.value = f.q || ''; q.maxLength = 80; q.setAttribute('aria-label', 'Question');
    KINDS.forEach(function (x) { const o = el('option', x[1]); o.value = x[0]; k.append(o); }); k.value = f.type || 'text'; k.setAttribute('aria-label', 'Kind of answer');
    opts.placeholder = 'Choices, separated by commas'; opts.value = (f.opts || []).join(', '); opts.hidden = k.value !== 'choice';
    box.type = 'checkbox'; box.checked = !!f.req; req.append(box, document.createTextNode(' required')); rm.type = 'button';
    k.addEventListener('change', function () { opts.hidden = k.value !== 'choice'; });
    rm.addEventListener('click', function () { row.remove(); });
    row.append(q, k, req, rm, opts); $('o-form').append(row);
  }
  function setFields(list) { $('o-form').textContent = ''; list.forEach(addRow); }
  function formRows() {
    return Array.prototype.map.call($('o-form').children, function (r) {
      const i = r.querySelectorAll('input.field'), type = r.querySelector('select').value;
      return { q: i[0].value.trim(), type: type, req: r.querySelector('input[type=checkbox]').checked, opts: type === 'choice' ? i[1].value.split(',').map(function (t) { return t.trim(); }).filter(Boolean) : [] };
    }).filter(function (f) { return f.q; }).slice(0, 20);
  }
  function machinesNow() { const m = (lim.paid.spread || {}).machines || 0; return m === 0 ? 'No storage machine is online right now.' : m === 1 ? '1 storage machine is online now.' : m + ' storage machines are online now.'; }
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
      if (o.extras.spread) out.push('Coded into ' + o.extras.spread + ' shards for ' + o.extras.spread + ' machines; any 4 rebuild it. ' + machinesNow() + ' Until then the keeper holds it.');
      if (o.extras.device) out.push('It opens only on a device you approve, after you match its 4-digit code with the receiver.');
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
    out.push('With your sender key you can pause, change, renew or delete it at any time.');
    return out;
  }
  function tidy() {                                      // show an add-on's inputs only while it is on
    document.querySelectorAll('.sub[data-for]').forEach(function (d) { d.hidden = !$(d.dataset.for).checked; });
    document.querySelectorAll('.addon:not(.lock)').forEach(function (a) { a.classList.toggle('on', a.querySelector('input[type=checkbox]').checked); });
    $('named-box').hidden = lock() !== 'named';
    $('o-pay-target-box').hidden = $('o-pay-mode').value !== 'crowd'; $('o-pay-period-box').hidden = $('o-pay-mode').value !== 'period';
    $('o-pay-price-l').textContent = $('o-pay-mode').value === 'crowd' ? 'at least, per person' : $('o-pay-mode').value === 'period' ? 'per reader, per period' : 'per reader';
    (function () {
      const mode = $('o-pay-mode').value, price = Number($('o-pay-price').value) || 0, n = Math.max(1, parseInt($('o-pay-buyers').value, 10) || 1);
      const sale = lim.paid && lim.paid.sale, cut = sale ? sale.fee_bps / 100 : 2.5;
      const take = mode === 'crowd' ? Number($('o-pay-target').value) || 0 : price * n;
      $('o-pay-fee').textContent = !sale ? 'Selling is not available on this keeper right now.' :
        (mode === 'crowd' ? 'Target ' + take.toFixed(2) + ' USDC.' : price.toFixed(2) + ' USDC × up to ' + n + ' readers = up to ' + take.toFixed(2) + ' USDC.') +
        ' Nothing to pay upfront for selling. Each reader pays your own sales contract, which sends ' + (100 - cut) + '% to your wallet and ' + cut + '% to INNERNET, split on the chain. You keep ' + (take * (1 - cut / 100)).toFixed(2) + ' USDC of that. Storage machines receive none of it.';
    })();
    (function () {
      const pq = !(on('o-collect') && $('o-audience').value === 'owner');
      const sh = { tries: Math.min(10, Math.max(1, parseInt($('o-tries').value, 10) || 5)), strong: $('o-strong').checked && lock() !== 'keys', pq: pq };
      ['shield-lock', 'shield-review'].forEach(function (id) { $(id).textContent = ''; $(id).append(St.shield(sh)); });
    })();
    $('o-spread-now').textContent = machinesNow() + ' Each shard moves to its own machine as one becomes free.';
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
    ['sell', 'Sell a file or report', 'Each reader pays before it opens: 97.5% goes to your wallet.'],
    ['crowd', 'Funded release', 'It opens for everyone once a total has been paid to you.'],
    ['feed', 'Paid updates', 'Readers pay per period; you post new versions on the same link.'],
    ['vote', 'Vote or survey', 'People answer without names. Answers open together at closing.'],
    ['swap', 'Exchange', 'Two people each add something. Both open only when both are in.'],
    ['seal', 'Certificate that cannot be faked', 'A printed QR opens the original, with a signed record and your domain.'],
    ['first', 'First to open wins', 'Sent to many, opens for one.'],
    ['custody', 'Evidence or sample custody', 'Handed from person to person, every hand recorded.'],
    ['sign', 'Sign a contract', 'Each party reads it, signs with their own key, and everyone gets a signed record.'],
    ['year', 'Keep it a year', 'Long storage with take-back and a read receipt.']];
  /* How each use presents itself: its group on the home screen, and the words of its setup screen. */
  const GROUPS = [['send', 'Send something'], ['hold', 'Hold it until the right moment'], ['collect', 'Collect from others'], ['sell', 'Sell']];
  const INFO = {
    burn: ['send'], until: ['send', 'Seal it until a date', 'Nobody, you included, can open it through this link before the time you set.'],
    first: ['send', 'First to open wins', 'Send the same link to many people. It opens for the first one and for nobody after.'],
    year: ['send', 'Keep it for a year', 'Long storage, with a read receipt. Renew it each year to keep it.'],
    glass: ['send', 'Break-glass credentials', 'A secret for emergencies: it opens once, stays on screen five minutes, and you are told the moment it is used.'],
    seal: ['send', 'A certificate that cannot be faked', 'You get a QR code to print. Anyone who scans it sees your original and proof that it was not changed.'],
    custody: ['send', 'Evidence or sample custody', 'Each person who opens it can seal it on to the next. Every hand is recorded.'],
    joint: ['hold', 'Joint custody', 'Name the people. Each gets a key; it opens only when they add their keys together.'],
    gone: ['hold', 'Release if I stop checking in', 'It stays closed while you check in. If you go silent, the people holding keys can open it.'],
    succession: ['hold', 'Pass it down a line', 'The first person has a set time to claim it. If they do not, it passes to the next.'],
    board: ['hold', 'Release with approvers', 'People you name must approve before it opens. Approving shows them nothing.'],
    tender: ['collect', 'Open a tender or ask for quotations', 'Write what bidders must fill in. They add sealed offers and can change them until your deadline; then all open together.', 'What should bidders read first?', 'The tender notice, terms or instructions.'],
    inbox: ['collect', 'Set up a sealed inbox', 'You get one link to give to clients. What they send is sealed to you; nobody else can read it.', 'What should people see when they open your link?', 'For example: Please send your signed forms and ID here.'],
    vote: ['collect', 'Run a vote or a survey', 'People answer without names. The answers stay closed until closing time, then open together.', 'What are you asking?', 'The question, and anything voters should know.'],
    swap: ['collect', 'Exchange with someone', 'Two people each add something. Neither sees the other\u2019s until both are in.', 'What is this exchange about?', 'A line both sides will see.'],
    sign: ['collect', 'Get a document signed', 'Each party opens the document, signs it with their own key, and everyone can check every signature.', 'The document to be signed', 'Paste the text, or switch to a file.'],
    sell: ['sell', 'Sell a file or a report', 'Set a price and your wallet. The reader pays, it opens, and 97.5% goes to your wallet on the chain.'],
    crowd: ['sell', 'Funded release', 'It opens for everyone once a total has been paid to your wallet.'],
    feed: ['sell', 'Paid updates', 'Readers pay per period. You post new versions behind the same link.'] };
  let using = null;
  function setUse(name) {
    using = name;
    const u = USES.filter(function (x) { return x[0] === name; })[0], i = INFO[name] || [];
    $('use-name').textContent = u ? u[1] : 'New send';
    $('new-title').textContent = i[1] || (u && name !== 'burn' ? u[1] : 'New send');
    $('new-lede').textContent = i[2] || (u && name !== 'burn' ? u[2] : 'A file or a note, sealed on this device before it leaves. As it is, it opens once for the person with your link and your PIN, and is then destroyed.');
    $('what-h').textContent = i[3] || 'What are you sending?';
    $('text').placeholder = i[4] || '';
    if (i[3] && !picked) { document.querySelector('input[name=kind][value=note]').checked = true; $('file-box').hidden = true; $('note-box').hidden = false; }
  }
  function view(name) {
    document.querySelectorAll('[data-view]').forEach(function (v) { v.hidden = v.dataset.view !== name; });
    ['new', 'sends', 'home'].forEach(function (n) { $('nav-' + n).classList.toggle('on', n === name); });
    window.scrollTo(0, 0);
  }
  function route() {
    const h = location.hash.replace('#', '');
    if (busy && h !== 'new') return;
    if (h === 'sends') { view('sends'); renderSent(); }
    else if (h === 'new') { if (!using && !$('done').hidden) { /* the result of the last send stays on screen */ } view('new'); }
    else view('home');
  }
  function choose(name) {                                  // start a send from a use (or a plain one)
    if (busy) return;
    $('done').hidden = true; $('work').hidden = true; $('form').hidden = false;
    recipe(name || 'burn'); setUse(name); if (wizard.go) wizard.go(0);
    if (location.hash !== '#new') location.hash = '#new'; else view('new');
  }
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
    if (name === 'sign') { pickTerm(90); lockIs('open'); tick('o-collect', 'o-record', 'o-sign'); $('o-audience').value = 'all'; $('o-anon').checked = false; $('o-attach').checked = false; $('o-seats').value = 2; $('o-reveal').value = 0; $('o-fields').value = 'Full name\nTitle or company'; }
    if (name === 'custody') { pickTerm(90); tick('o-chain', 'o-record', 'o-receipt'); }
    if ($('o-collect').checked) {                          // the preset's questions become the form
      const typed = { tender: [{ q: 'Company', req: true }, { q: 'Price', type: 'number', req: true }, { q: 'Delivery in days', type: 'number' }, { q: 'Remarks', type: 'long' }],
        vote: [{ q: 'Your answer', type: 'choice', opts: ['Yes', 'No', 'Abstain'], req: true }], sign: [{ q: 'Full name', req: true }, { q: 'Title or company' }] };
      setFields(typed[name] || lines('o-fields', 12)); $('o-files').value = $('o-attach').checked ? '1' : '0';
    }
    if (name !== 'sign') $('o-sign').checked = false;
    document.querySelectorAll('#recipes .use').forEach(function (b) { b.classList.toggle('on', b.dataset.r === name); });
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

  const codes = {};                                       // send id -> its sender key, which works from any device
  async function proof(id, action) { return Object.assign(await C.signRequest(await St.deviceKey(), action, id), codes[id] ? { code: codes[id] } : {}); }
  async function act(id, action, extra) {
    return (await St.api('POST', '/files/' + id + '/' + action, Object.assign(await proof(id, action), extra || {}))).json();
  }
  /* The sender's own copy of the record, sealed under the sender key and left with the keeper. */
  async function savePack(rec) {
    try {
      const key = await C.subKey(C.unb64u(rec.code), rec.id, 'pack');
      await St.api('POST', '/files/' + rec.id + '/pack', { code: rec.code, pack: await C.sealSmall(key, rec.id, 'pack', { rec: rec, box: await St.boxExport(rec.id) }) });
    } catch (e) { /* the send still works from this browser */ }
  }
  async function loadPack(id, code) {
    codes[id] = code;
    const got = await (await St.api('POST', '/files/' + id + '/pack', { code: code })).json();
    const data = await C.openSmall(await C.subKey(C.unb64u(code), id, 'pack'), id, 'pack', got.pack);
    if (data.box) await St.boxImport(id, data.box);
    await St.remember(data.rec);
  }

  /* Show the payment box and wait until the keeper sees the payment on the chain. */
  function payment(id, pay) {
    $('pay').hidden = false;
    $('pay-amount').textContent = St.usdc(pay.amount); $('pay-exact').textContent = pay.amount;
    $('pay-net').textContent = pay.network_name; $('pay-net2').textContent = pay.network_name;
    $('pay-to').textContent = pay.to; $('pay-by').textContent = St.when(pay.pay_by);
    $('pay-wallet').hidden = !window.ethereum; $('pay-wallet').disabled = false; $('pay-tx').value = '';
    St.payWays($('pay-qr'), $('pay-open'), pay);
    say('pay-msg', 'Waiting for the payment…');
    return new Promise(function (ok, bad) {
      let tx = null, stopped = false, t = null;
      function finish(fn, v) { stopped = true; clearTimeout(t); $('pay').hidden = true; stopPay = null; fn(v); }
      async function look() {
        if (stopped) return;
        try {
          const typed = $('pay-tx').value.trim().toLowerCase(), use = tx || (/^0x[0-9a-f]{64}$/.test(typed) ? typed : null);
          const r = await act(id, 'pay', use ? { tx: use } : {});
          if (r.paid) return finish(ok, r);
          if (Date.now() / 1000 > pay.pay_by + 600) return finish(bad, new Error('the price was not paid in time; nothing was sent'));
        } catch (e) { if (e.status === 410 || e.status === 422) return finish(bad, e); say('pay-msg', e.message); }
        t = setTimeout(look, 4000);
      }
      stopPay = function () { finish(bad, new Error('cancelled; nothing was sent')); };
      $('pay-cancel').onclick = stopPay;
      $('pay-check').onclick = function () { if (!/^0x[0-9a-fA-F]{64}$/.test($('pay-tx').value.trim())) return say('pay-msg', 'A transaction hash is 0x followed by 64 characters.', true); say('pay-msg', 'Checking that transaction on the chain…'); clearTimeout(t); look(); };
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
    $('six').hidden = false; $('bar').hidden = false; $('pay').hidden = true; say('work-msg', ''); $('film').hidden = false;
    $('work-title').textContent = 'Sealing on this device';
    $('form').hidden = true; $('work').hidden = false; $('work').scrollIntoView({ block: 'start' });
    // The film: built from this send, its content, its lock, its rules and where each piece goes.
    const F = window.InnernetFilm, L = lock(), fx = o.extras || {};
    const keyPeople = L === 'keys' ? names() : [], pinPeople = L === 'named' ? lines('o-rnames', 20) : [], apprPeople = o.approvers ? lines('o-anames', 10) : [];
    const short = function (list) { const t = list.join(', '); return t.length > 24 ? t.slice(0, 23) + '\u2026' : t; };
    const head = new Uint8Array(await c.blob.slice(0, 48).arrayBuffer());
    const first = F.firstChars(head, c.kind === 'note' || /^text\//.test(c.type));
    const tiles = c.kind === 'file' && /^image\/(png|jpeg|gif|webp)$/.test(c.type) ? await F.imageTiles(c.blob) : null;
    const filmRules = [];
    filmRules.push(o.max_opens === 1 ? 'opens once' : o.max_opens ? 'opens ' + o.max_opens + ' times' : 'opens any number of times');
    if (L === 'pin' && !o.forward && !fx.pin_in_link) filmRules.push('first device only');
    if (L === 'named') filmRules.push(pinPeople.length + ' own PINs' + (o.succession ? ', one after another' : ''));
    if (L === 'keys') filmRules.push((o.need === o.holders ? 'all ' : 'any ' + o.need + ' of ') + o.holders + ' keys together');
    if (o.open_after) filmRules.push('not before ' + St.when(o.open_after));
    if (o.open_until) filmRules.push('not after ' + St.when(o.open_until));
    if (o.checkin_days) filmRules.push('held while you check in every ' + o.checkin_days + ' days');
    if (o.approvers) filmRules.push(o.approvers.need + ' of ' + o.approvers.count + ' approvers release it');
    if (o.pay) filmRules.push(o.pay.mode === 'crowd' ? 'opens at ' + o.pay.target + ' USDC raised' : 'reader pays ' + o.pay.price + ' USDC' + (o.pay.mode === 'period' ? ' per ' + o.pay.period_days + ' days' : ''));
    if (fx.device) filmRules.push('approved device only');
    if (fx.spread) filmRules.push(fx.spread + ' shards, any 4 rebuild it');
    if (o.collect) filmRules.push(o.collect.seats + ' people can add');
    if (o.duress) filmRules.push('duress PIN opens a decoy');
    if (fx.view_only) filmRules.push('screen only');
    if (fx.view_secs) filmRules.push('visible ' + Math.round(fx.view_secs / 60) + ' min');
    if (fx.presence) filmRules.push('only while all are present');
    if (o.receipt) filmRules.push('read receipt');
    if (o.reply) filmRules.push('one sealed reply');
    filmRules.push('kept ' + Math.round(o.keep / 86400) + ' days');
    const filmPlaces = [{ id: 'link', label: L === 'keys' ? 'The link: names only' : 'The link', short: 'Link' }, { id: 'you', label: 'You' }];
    if (keyPeople.length || pinPeople.length) filmPlaces.push({ id: 'people', label: short(keyPeople.length ? keyPeople : pinPeople) });
    if (apprPeople.length) filmPlaces.push({ id: 'appr', label: 'Approvers' });
    if (fx.spread) filmPlaces.push({ id: 'machines', label: 'Machines', state: ((lim.paid.spread || {}).machines || 0) + ' online now' });
    filmPlaces.push({ id: 'keeper', label: 'Keeper' });
    const filmTokens = [{ id: 'a', label: 'link secret', at: 'spawn', slot: 0, to: L === 'keys' ? null : 'link' }];
    if (L !== 'keys') filmTokens.push({ id: 'b', label: 'PIN', at: 'spawn', slot: 1, to: L === 'named' ? null : fx.pin_in_link ? 'link' : 'you' });
    filmTokens.push({ id: 'c', label: 'keeper part', at: 'spawn', slot: 2, to: 'keeper' });
    keyPeople.forEach(function (p, i) { filmTokens.push({ id: 'h' + i, label: p.slice(0, 14), at: 'split', to: 'people', cls: 'person' }); });
    pinPeople.forEach(function (p, i) { filmTokens.push({ id: 'p' + i, label: p.slice(0, 14), at: 'split', to: 'people', cls: 'person' }); });
    apprPeople.forEach(function (p, i) { filmTokens.push({ id: 'r' + i, label: p.slice(0, 14), at: 'later', to: 'appr', cls: 'person' }); });
    filmTokens.push({ id: 'sk', label: 'sender key', at: 'later', to: 'you' });
    if (fx.witness) filmTokens.push({ id: 'wl', label: 'witness link', at: 'later', to: 'you' });
    if (o.duress) filmTokens.push({ id: 'dp', label: 'duress PIN', at: 'later', to: 'you' });
    const film = F.create($('film'), {
      mode: 'seal', label: 'How this send is sealed', keyLabel: L === 'named' ? 'content key' : 'file key',
      content: { kind: tiles ? 'image' : c.kind === 'note' ? 'note' : 'file',
        title: c.kind === 'note' ? 'Note \u00b7 ' + Array.from(new TextDecoder().decode(await c.blob.arrayBuffer())).length + ' characters' : c.name + ' \u00b7 ' + F.typeLabel(c.name, c.type) + ' \u00b7 ' + St.size(c.size) },
      places: filmPlaces, tokens: filmTokens, rules: filmRules, spawnCount: 3 });
    film.plain(tiles ? { tiles: tiles } : { chars: first.chars });
    film.beat('content', c.kind === 'note' ? 'Your note, on this device' : tiles ? 'Your picture, on this device' : c.name + (first.hex ? ': its first bytes, in hex' : ': its first characters'));
    steps.set(0, 'run');
    const id = C.newId(), secret = C.random(32), share = C.random(32), who = names();
    const strong = $('o-strong').checked && !o.holders, pin = o.holders ? await C.jointPin(secret) : C.newPin(strong);
    const device = await St.deviceKey();
    await pause(350);
    steps.set(0, 'done', 'A link secret, a ' + (strong ? '10-sign' : '6-digit') + ' PIN and a keeper part. The first two never reach a server.');
    film.beat('keys', L === 'keys' ? 'A link secret and a keeper part, made here' : 'Three random key pieces, made here');
    if (keyPeople.length) film.beat('split', 'The link secret becomes ' + keyPeople.length + ' keys: ' + (o.need === o.holders ? 'all' : 'any ' + o.need) + ' needed', { from: 'a', into: keyPeople.map(function (p, i) { return 'h' + i; }) });
    if (pinPeople.length) film.beat('split', 'A PIN for each of ' + pinPeople.length + ' people', { from: 'b', into: pinPeople.map(function (p, i) { return 'p' + i; }) });

    steps.set(1, 'run', 'Stretching the PIN 200,000 rounds, so it cannot be guessed quickly…');
    const keys = await C.linkKeys(secret, id);
    const key = await C.fileKey(secret, share, pin, id);
    await pause(250);
    steps.set(1, 'done', 'Built from link secret + PIN + keeper part. Missing any one, there is no key.');
    film.beat('filekey', L === 'named' ? 'One content key, wrapped once for each PIN' : 'Together they make the file key');

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
        let p = C.newPin(strong); while (used[p]) p = C.newPin(strong); used[p] = 1;
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
    const control = C.random(32); o.recover_hash = await C.sha256hex(control);
    if (ex.witness) { const t = C.random(32); o.witness_hash = await C.sha256hex(t); art.witness = base + 'w' + C.b64u(t); }
    if (o.summary) o.summary = await C.sealSmall(keys.preview, id, 'summary', { text: $('o-summary-text').value.trim() });
    if (o.duress) {
      let p2 = C.newPin(strong); while (p2 === pin) p2 = C.newPin(strong);
      const dShare = C.random(32), dKey = await C.fileKey(secret, dShare, p2, id), text = new TextEncoder().encode($('o-decoy').value.trim() || 'Nothing here yet.');
      decoy = await C.sealPart(dKey, id, 0, 1, text); art.duress = p2;
      o.duress = { pin_tag: await C.pinTag(keys, p2), share: C.b64u(dShare), size: decoy.length,
        meta: await C.sealSmall(dKey, id, 'meta', { name: 'Note', type: 'text/plain;charset=utf-8', size: text.length, kind: 'note' }) };
    }
    if (o.collect) {
      const box = o.collect.audience === 'owner' ? await St.boxKey(id, true) : null;
      const pub = box ? C.b64u(new Uint8Array(await crypto.subtle.exportKey('raw', box.publicKey))) : null;
      o.collect = Object.assign({}, o.collect, { pub: pub, form: await C.sealSmall(keys.preview, id, 'form',
        { fields: formRows(), files: Number($('o-files').value) || 0, sign: $('o-sign').checked, anon: o.collect.anon, pub: pub }) });
    }
    const made = await (await St.api('POST', '/files', Object.assign({
      id: id, kind: c.kind, size: c.size + parts * C.TAG, parts: parts, auth_hash: keys.authHash, pin_tag: await C.pinTag(keys, pin),
      owner_pub: await C.publicRaw(device), keeper_share: C.b64u(share),
      preview: await C.sealSmall(keys.preview, id, 'preview', { from: from, note: $('note').value.trim() }),
      meta: await C.sealSmall(contentKey, id, 'meta', { name: c.name, type: c.type, size: c.size, kind: c.kind, mark: from,
        rich: c.kind === 'note' ? fmt() : 0, view_only: ex.view_only || 0, view_secs: ex.view_secs || 0, presence: ex.presence || 0, card: ex.card || '' })
    }, o))).json();
    const link = base + C.b64u(secret) + (ex.pin_in_link ? '.' + pin : '');
    if (ex.origin) art.origin = { domain: ex.origin, line: await C.publicRaw(device) };
    if (ex.qr) art.qr = 1;
    const links = joint ? joint.keys.map(function (k, i) { return { name: who[i], key: k }; }) : null;
    const shared = joint ? base + joint.link : link;
    const rec = { id: id, name: c.name, kind: c.kind, size: c.size, created_at: Math.floor(Date.now() / 1000), expires_at: made.expires_at, link: link, shared: shared, pin: pin,
      parts: parts, rules: o, links: links, art: art, from: from, line: $('note').value.trim(), code: C.b64u(control), manage: location.origin + St.BASE + '/send?m=' + id + '#' + C.b64u(control), recover: null, open_link: !!ex.pin_in_link, named: !!art.pins, paid: made.pay ? made.pay.amount : null };
    await St.remember(rec);
    codes[id] = rec.code; await savePack(rec);
    film.beat('rules', filmRules.length === 1 ? 'Your rule' : 'Your ' + filmRules.length + ' rules');
    film.beat('deposit', 'The keeper gets one key piece and these rules');
    if (made.pay) {
      steps.set(2, 'run', 'Deposited. Waiting for your payment of ' + St.usdc(made.pay.amount) + ' USDC before anything is uploaded…', 0.6);
      await payment(id, made.pay);
    }
    steps.set(2, 'done', commentary(o, made.expires_at).join(' ') + (made.pay ? ' Paid ' + St.usdc(made.pay.amount) + ' USDC.' : ''));
    if (made.pay) film.beat('pay', 'Paid ' + St.usdc(made.pay.amount) + ' USDC on Base, found on the chain', { label: St.usdc(made.pay.amount) + ' USDC', from: 'you' });

    if (decoy) await St.put('/files/' + id + '/decoy', decoy, { 'X-Send-Upload': made.upload, 'Content-Type': 'application/octet-stream' });
    steps.set(3, 'run');
    await pause(250);
    steps.set(3, 'done', parts === 1 ? St.size(c.size) + ' fits in one part.' : St.size(c.size) + ' in ' + parts + ' parts of up to 4 MB.');
    film.beat('cut', parts === 1 ? 'It fits in one part' : 'Cut into ' + parts + ' parts of up to 4 MB', { parts: parts });

    for (let n = 0; n < parts; n++) {
      steps.set(4, 'run', 'Sealing part ' + (n + 1) + ' of ' + parts + '. Each is numbered, so none can be swapped, dropped or cut.', n / parts);
      const plain = new Uint8Array(await c.blob.slice(n * C.PART, (n + 1) * C.PART).arrayBuffer());
      const sealed = await C.sealPart(contentKey, id, n, parts, plain);
      if (n === 0) film.sealed(tiles ? { tiles: F.noiseTiles(sealed.subarray(0, 432)) } : { chars: F.sealedChars(sealed) });
      if (n + 1 === parts && fx.spread) film.beat('seal', tiles ? 'Sealed: the real sealed bytes, drawn as pixels' : 'Sealed: these are the real sealed bytes');
      if (n + 1 === parts && fx.spread) film.beat('shards', 'Coded into ' + fx.spread + ' shards: any 4 rebuild it', { n: fx.spread });
      else if (n + 1 === parts) film.beat('seal', tiles ? 'Sealed: the real sealed bytes, drawn as pixels' : 'Sealed: these are the real sealed bytes');
      steps.set(4, n + 1 === parts ? 'done' : 'run', n + 1 === parts ? (parts === 1 ? 'The part is' : 'All ' + parts + ' parts are') + ' sealed with AES-256-GCM, numbered so none can be swapped, dropped or cut.' : null, (n + 1) / parts);
      steps.set(5, 'run', 'Storing part ' + (n + 1) + ' of ' + parts + ' with the keeper…', n / parts);
      await store(id, n, sealed, made.upload, function (f) { steps.set(5, 'run', null, (n + f) / parts); });
      if (parts > 1) film.beat('progress', null, { text: (n + 1) + ' of ' + parts + ' parts stored' });
    }
    steps.set(5, 'done', 'Stored. The keeper holds sealed bytes and cannot read them.');
    if (fx.spread) film.beat('progress', null, { text: 'holds ' + fx.spread + ' shards' });
    film.beat('store', fx.spread ? 'Held by the keeper; shards move to machines as they join' : keyPeople.length ? 'Stored sealed. A key to each of ' + keyPeople.length + ' people; the file key is kept nowhere'
      : pinPeople.length ? 'Stored sealed. A PIN to each person; the content key is kept nowhere'
      : apprPeople.length ? 'Stored sealed. Approval links to ' + apprPeople.length + ' people; the file key is kept nowhere' : 'Stored sealed. The file key is kept nowhere');
    const when = [o.open_after ? 'after ' + St.when(o.open_after) : '', o.approvers ? 'once approved' : '', o.pay ? 'after payment' : '', o.checkin_days ? 'if you stop checking in' : '', fx.device ? 'on a device you approve' : ''].filter(Boolean);
    await film.end((keyPeople.length ? 'Opens when ' + (o.need === o.holders ? 'all ' + o.holders : o.need + ' of ' + o.holders) + ' keys are added together'
      : pinPeople.length ? 'Each person opens it with their own PIN' : fx.pin_in_link ? 'Anyone with the link can open it' : 'Opens with the link and the PIN') + (when.length ? ', ' + when.join(', ') : ''));
    return { rec: rec, lines: commentary(o, made.expires_at), film: film };
  }

  function showDone(r) {
    $('done-film').textContent = ''; if (r.film) $('done-film').append(r.film.el);
    $('link').textContent = r.rec.shared || r.rec.link; $('pin').textContent = C.showPin(r.rec.pin);
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
    $('manage').textContent = r.rec.manage || '';
    function item(label, value, note) {
      const l = el('label', label, 'label'), row = el('div', null, 'copyable'), b = el('button', 'Copy', 'btn btn-sm'); b.type = 'button';
      b.addEventListener('click', function () { navigator.clipboard.writeText(value).then(function () { b.textContent = 'Copied'; }); });
      row.append(el('code', value), b); box.append(l, row); if (note) box.append(el('p', note, 'note'));
    }
    $('pin-box').hidden = !!r.rec.links || !!r.rec.named || !!r.rec.open_link;
    if (r.rec.open_link) $('done-lede').textContent = 'Anyone who has this link can use it. The PIN is inside the link.';
    (A.pins || []).forEach(function (p) { item('PIN for ' + p.name + (p.from || p.to ? ' (' + (p.from ? 'from ' + St.when(p.from) : 'from now') + (p.to ? ' until ' + St.when(p.to) : '') + ')' : ''), C.showPin(p.pin)); });
    if (A.pins) $('done-lede').textContent = 'Send everyone the same link. Tell each person only their own PIN.';
    (A.approvers || []).forEach(function (p) { item('Approver link for ' + p.name, p.link); });
    if (A.witness) item('Witness link', A.witness, 'Shows what happens to this send and gives the signed record. It cannot open it.');
    if (A.duress) item('Duress PIN', A.duress, 'Opens only the decoy, and tells you it was used.');
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
    const list = await (await St.api('POST', '/files/' + rec.id + '/adds/list', await proof(rec.id, 'adds'))).json(), box = s.collect.audience === 'owner' ? await St.boxKey(rec.id, false) : null, shared = await C.subKey(secret, rec.id, 'adds');
    if (s.collect.audience === 'owner' && !box) throw new Error('The key that opens these is in the browser this was sent from.');
    const table = el('table', null, 'adds');
    for (const e of list.entries) {
      const blob = await St.bytes('POST', '/files/' + rec.id + '/adds/' + e.entry, await proof(rec.id, 'adds'));
      const got = C.unpack(box ? await C.openFrom(box, rec.id, blob) : await C.openWith(shared, rec.id, blob));
      const tr = el('tr'); tr.append(el('th', '#' + e.entry + ' · ' + St.when(e.received_at) + (e.changes ? ' · changed ' + e.changes + '×' : '')));
      const td = await St.entryCell(rec.id, got, null);
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
          const v = await (await St.api('POST', '/files/' + rec.id + '/version', Object.assign(await proof(rec.id, 'version'), { size: file.size + parts * C.TAG, parts: parts, keeper_share: C.b64u(share),
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
    $('sent-card').hidden = !list.length; $('sent-empty').hidden = !!list.length; $('sends-n').textContent = list.length ? '(' + list.length + ')' : '';
    $('sent').textContent = '';
    list.forEach(function (rec) {
      if (rec.code) codes[rec.id] = rec.code;
      const li = el('li');
      const head = el('div', null, 'sent-head');
      const chip = el('span', 'Checking', 'chip');
      head.append(el('strong', rec.name), chip, el('span', St.size(rec.size) + ' · sent ' + St.when(rec.created_at), 'dim'));
      const state = el('p', '', 'msg'), warn = el('p', '', 'msg warn'), reply = el('p', '', 'reply');
      warn.hidden = true; reply.hidden = true;
      const acts = el('div', null, 'row-actions');
      const copy = el('button', rec.links ? 'Copy link and all keys' : 'Copy link', 'btn btn-sm'), alive = el('button', 'Check in now', 'btn btn-sm btn-light'), more = el('button', 'Renew', 'btn btn-sm'), hold = el('button', 'Pause', 'btn btn-sm'), change = el('button', 'Change', 'btn btn-sm'), keyb = el('button', 'Copy sender key', 'btn btn-sm'), back = el('button', 'Delete it now', 'btn btn-sm btn-danger'), forget = el('button', 'Remove from this list', 'btn btn-sm');
      const ext = el('div', null, 'inline ext'); ext.hidden = true;
      const extra = el('div', null, 'row-actions extra');
      ext.append(el('span', 'Add to the end date:'));
      const editor = el('div', null, 'editor'); editor.hidden = true;
      [copy, alive, more, back, forget, hold, change, keyb].forEach(function (b) { b.type = 'button'; });
      copy.hidden = alive.hidden = more.hidden = back.hidden = hold.hidden = change.hidden = true; keyb.hidden = !rec.manage;
      acts.append(alive, copy, more, hold, change, back, keyb, forget);
      li.append(head, state, warn, reply, acts, extra, ext, editor);
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
        copy.hidden = !live; more.hidden = !(live && lim.paid.on); back.hidden = s.state === 'dead' || s.state === 'spent';
        hold.hidden = change.hidden = !live; hold.textContent = s.paused ? 'Resume' : 'Pause';
        if (live && s.paused) { chip.textContent = 'Paused'; state.textContent = 'Paused: nobody can open it until you resume. ' + state.textContent; }
        last = s;
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
        if (s.paylock) moreText += s.paylock.mode === 'crowd' ? ' Raised ' + St.usdc(s.paylock.raised) + ' of ' + St.usdc(s.paylock.target) + ' USDC.' : ' Sold to ' + s.paylock.sold + ' of ' + s.paylock.buyers + '; ' + St.usdc(s.paylock.raised) + ' USDC paid' + (s.paylock.fee_bps ? ' by readers.' : ' to you.');
        if (s.paylock && s.paylock.fee_bps && lim.paid.sale) {
          moreText += ' Readers pay your sales contract ' + s.paylock.to + ': ' + (100 - s.paylock.fee_bps / 100) + '% is yours.';
          tool('Collect sales to your wallet', async function () {
            const sale = lim.paid.sale, W = window.InnernetWallet;
            const acct = await W.connect(sale.chain_id);
            const split = await W.findOrCreate(sale.factory, acct, s.paylock.wallet, function (t) { state.textContent = t; });
            state.textContent = 'Confirm the collection in your wallet…';
            const hash = await W.request('eth_sendTransaction', [{ from: acct, to: split, data: '0x' + W.SEL.release + W.pad(sale.usdc) }]);
            state.textContent = 'Collecting…'; await W.waitReceipt(hash);
            state.textContent = 'Collected: ' + (100 - s.paylock.fee_bps / 100) + '% of the sales so far went to ' + s.paylock.wallet + ', ' + (s.paylock.fee_bps / 100) + '% to INNERNET.';
          });
        }
        if (s.collect) moreText += ' ' + s.collect.count + ' of ' + s.collect.seats + ' have added.' + (s.collect.revealed ? '' : ' Closed to everyone until it opens.');
        if (s.events.some(function (e) { return e.event === 'duress PIN used'; })) moreText += ' The duress PIN was used.';
        if (s.spread) moreText += ' Shards: ' + s.spread.machines.length + ' of ' + s.spread.n + ' on machines' + (s.spread.machines.length ? ' (' + s.spread.machines.map(function (m) { return m.name + (m.region ? ', ' + m.region : ''); }).join('; ') + ')' : '') + (s.spread.keeper_copy ? '; the keeper holds the rest.' : '; the keeper\u2019s copy is removed.');
        if (s.version > 1) moreText += ' Version ' + s.version + '.';
        if (s.origin) moreText += ' Shown as from ' + s.origin + '.';
        state.textContent += moreText;
        (s.claims || []).forEach(function (c) {
          const row = el('p', (c.name || 'Someone') + ' asks to open it on a device. Code ' + c.code + '. ' + (c.approved === 1 ? 'Approved.' : c.approved === -1 ? 'Refused.' : 'Check the code with them before you approve. '), 'claim');
          if (c.approved === 0 && live) [['Approve', true], ['Refuse', false]].forEach(function (x) {
            const b = el('button', x[0], 'btn btn-sm' + (x[1] ? ' btn-light' : '')); b.type = 'button';
            b.addEventListener('click', function () { b.disabled = true; act(rec.id, 'claims', { device: c.device, ok: x[1] }).then(refresh, function (e) { state.textContent = e.message; }); });
            row.append(b, document.createTextNode(' '));
          });
          extra.append(row);
        });
        if ((s.claims || []).some(function (c) { return c.approved === 0; }) && live) { chip.textContent = 'Asked'; setTimeout(refresh, 8000); }
        if (s.collect && s.collect.count && s.collect.revealed) tool('Read what was added', function () { return readAdds(rec, s, extra); });
        if (s.extras.record || s.state === 'dead' || s.state === 'spent') tool('Signed record', async function () { St.download('innernet-record-' + rec.id.slice(0, 8) + '.json', new Blob([JSON.stringify(await act(rec.id, 'record'), null, 2)], { type: 'application/json' })); });
        if (s.origin_pending && live) tool('Check origin', async function () { await act(rec.id, 'origin'); return refresh(); });
        if (s.versions_left > 0 && live) tool('Post a new version (' + s.versions_left + ' left)', function () { return newVersion(rec, refresh); });
        if (s.reply) readReply(rec, s.reply).then(function (t) { reply.textContent = 'Reply: ' + t; reply.hidden = false; }).catch(function () {});
      }
      let last = null;
      hold.addEventListener('click', function () { hold.disabled = true; act(rec.id, 'pause', { on: !(last && last.paused) }).then(refresh, function (e) { state.textContent = e.message; }).finally(function () { hold.disabled = false; }); });
      keyb.addEventListener('click', function () { navigator.clipboard.writeText(rec.manage).then(function () { keyb.textContent = 'Copied'; }); });
      change.addEventListener('click', function () {            // change what can still be changed, while it waits
        editor.hidden = !editor.hidden; if (editor.hidden || !last) return;
        editor.textContent = '';
        const f = {};
        function field(key, label, type, value) { const l = el('label', label, 'label'), i = el('input', null, 'field'); i.type = type; i.value = value; l.append(i); editor.append(l); f[key] = i; }
        if (last.open_after) field('open_after', 'Not before (clear it to remove)', 'datetime-local', local(last.open_after));
        if (last.open_until) field('open_until', 'Not after (clear it to remove)', 'datetime-local', local(last.open_until));
        if (last.max_opens !== 1 && !last.holders && !last.named) field('max_opens', 'Openings allowed (can only be lowered; ' + last.opens + ' used)', 'number', last.max_opens || '');
        if (last.held) field('checkin_days', 'Check in every … days', 'number', Math.round(last.checkin_every / 86400));
        field('line', 'Line shown before opening', 'text', rec.line || '');
        const save = el('button', 'Save changes', 'btn btn-sm btn-light'); save.type = 'button'; editor.append(save);
        save.addEventListener('click', async function () {
          const d = {};
          function stamp(i) { return i.value ? Math.floor(new Date(i.value).getTime() / 1000) : 0; }
          if (f.open_after && stamp(f.open_after) !== last.open_after) d.open_after = stamp(f.open_after);
          if (f.open_until && stamp(f.open_until) !== last.open_until) d.open_until = stamp(f.open_until);
          if (f.max_opens && f.max_opens.value && Number(f.max_opens.value) !== last.max_opens) d.max_opens = Number(f.max_opens.value);
          if (f.checkin_days && Number(f.checkin_days.value) * 86400 !== last.checkin_every) d.checkin_days = Number(f.checkin_days.value);
          if (f.line.value.trim() !== (rec.line || '')) {
            const keys = await C.linkKeys(C.unb64u(rec.link.split('#')[1].split('.')[0]), rec.id);
            d.preview = await C.sealSmall(keys.preview, rec.id, 'preview', { from: rec.from || '', note: f.line.value.trim() });
          }
          if (!Object.keys(d).length) { editor.hidden = true; return; }
          save.disabled = true;
          try { await act(rec.id, 'edit', d); if (d.preview) { rec.line = f.line.value.trim(); await St.remember(rec); savePack(rec); } editor.hidden = true; await refresh(); }
          catch (e) { state.textContent = e.message; }
          save.disabled = false;
        });
      });
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
            $('six').hidden = true; $('bar').hidden = true; $('film').hidden = true; say('work-msg', '');
            $('work-title').textContent = 'Renew “' + rec.name + '” for ' + r.days + ' more days';
            $('form').hidden = true; $('done').hidden = true; $('work').hidden = false; view('new');
            await payment(rec.id, r.pay);
          }
          ext.hidden = true;
        } catch (e) { state.textContent = e.message; }
        $('work').hidden = true; $('form').hidden = false; view('sends');
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
        if (c.kind === 'note' && (c.words > 500 || c.size > lim.note_bytes)) return say('msg', c.size > lim.note_bytes ? 'A note is at most ' + Math.round(lim.note_bytes / 1024) + ' KB. For a bigger page, send it as a file.' : 'A note is at most 500 words.', true), false;
        if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true), false;
      }
      if ($('o-split').checked && names().length < 2) return say('msg', 'Split custody needs at least 2 names.', true), false;
      if (at >= 1 && on('o-pay') && !/^0x[0-9a-fA-F]{40}$/.test($('o-pay-to').value.trim())) return say('msg', 'Add your receiving address for the payment lock (0x and 40 characters).', true), false;
      if (at >= 1 && on('o-pay') && [lim.paid.to, (lim.paid.sale || {}).fee_to].filter(Boolean).map(function (x) { return x.toLowerCase(); }).indexOf($('o-pay-to').value.trim().toLowerCase()) >= 0) return say('msg', 'That is INNERNET\'s own address. Readers pay the address you give here, so give your own wallet.', true), false;
      if (at >= 1 && lock() === 'named' && lines('o-rnames', 20).length < 1) return say('msg', 'Name at least one person who gets a PIN.', true), false;
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
    function noteInfo() {
      const n = words($('text').value), b = new TextEncoder().encode($('text').value.trim()).length;
      say('text-msg', n + ' of 500 words' + (fmt() === 2 ? ', ' + (b / 1024).toFixed(1) + ' of ' + Math.round(lim.note_bytes / 1024) + ' KB' : ''), n > 500 || b > lim.note_bytes);
      $('fmt-help').hidden = fmt() !== 2; $('fmt-preview').hidden = fmt() === 0;
      if (!$('fmt-view').hidden) preview();
    }
    function preview() {
      const v = $('fmt-view'), t = $('text').value; v.textContent = '';
      if (fmt() === 2) v.append(window.InnernetHtml.render(t, document));
      else if (fmt() === 1) { const d = C.rich(t, document); d.className = 'shown rich'; v.append(d); }
      v.hidden = fmt() === 0;
      $('fmt-preview').textContent = 'Hide preview';
    }
    $('text').addEventListener('input', function () { noteInfo(); requote(); });
    document.querySelectorAll('input[name=fmt]').forEach(function (r) { r.addEventListener('change', noteInfo); });
    $('fmt-preview').addEventListener('click', function () {
      if ($('fmt-view').hidden) preview(); else { $('fmt-view').hidden = true; $('fmt-preview').textContent = 'Preview'; }
    });
    $('form').addEventListener('input', requote);
    GROUPS.forEach(function (g) {
      const grid = el('div', null, 'uses');
      USES.forEach(function (u) { if ((INFO[u[0]] || ['send'])[0] !== g[0]) return; const b = el('button', null, 'use'); b.type = 'button'; b.dataset.r = u[0]; b.append(el('strong', u[1]), el('span', u[2])); grid.append(b); });
      $('recipes').append(el('h2', g[1], 'grp'), grid);
    });
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
    setFields(['Your name', 'Remarks']);
    $('o-form-add').addEventListener('click', function () { addRow({}); });
    wizard();
    const use = new URLSearchParams(location.search).get('use');
    window.addEventListener('hashchange', route);
    document.querySelectorAll('a[href="#new"]').forEach(function (a) { a.addEventListener('click', function (e) { e.preventDefault(); choose(null); }); });
    if (use && USES.some(function (u) { return u[0] === use; })) { history.replaceState(null, '', location.pathname); choose(use); }
    else if (location.hash === '#new') choose(null);
    else route();
    $('recipes').addEventListener('click', function (e) { const b = e.target.closest('button'); if (b && !b.disabled) choose(b.dataset.r); });
    if (!lim.paid.on) $('recipes').querySelectorAll('button').forEach(function (b) { b.disabled = ['burn', 'first'].indexOf(b.dataset.r) < 0; });
    $('again').addEventListener('click', function () {
      $('done').hidden = true; $('form').hidden = false; $('form').reset(); $('file-box').hidden = false; $('note-box').hidden = true;
      $('form').reset(); pick(null); say('text-msg', ''); choose(null);
    });
    $('form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) return;
      const c = content();
      if (!c) return say('msg', 'Choose a file first.', true);
      if (!c.size) return say('msg', c.kind === 'note' ? 'Write the note first.' : 'That file is empty.', true);
      if (c.kind === 'note' && (c.words > 500 || c.size > lim.note_bytes)) return say('msg', c.size > lim.note_bytes ? 'A note is at most ' + Math.round(lim.note_bytes / 1024) + ' KB. For a bigger page, send it as a file.' : 'A note is at most 500 words.', true);
      if ($('o-split').checked && names().length < 2) return say('msg', 'Split custody needs at least 2 names.', true);
      if (!$('from').value.trim()) return say('msg', 'Add your name, so the receiver knows who it is from.', true);
      if (quoted.error) return say('msg', quoted.error, true);
      busy = true; $('go').disabled = true;
      send(c, allOpts()).then(function (r) { say('msg', ''); showDone(r); })
        .catch(function (e) { $('work').hidden = true; $('form').hidden = false; say('msg', 'Not sent: ' + e.message, true); })
        .finally(function () { busy = false; $('go').disabled = false; renderSent(); tally(); });
    });
    pick(null);
    const mk = new URLSearchParams(location.search).get('m');
    if (mk && /^[0-9a-f]{32}$/.test(mk) && location.hash.length > 20) {
      if (busy) return;
      try { await loadPack(mk, location.hash.slice(1)); history.replaceState(null, '', location.pathname + '#sends'); say('key-msg', 'Your sender key worked. That send is listed here, with its controls.'); }
      catch (e) { history.replaceState(null, '', location.pathname + '#sends'); say('key-msg', e.status === 403 || e.status === 404 ? 'That sender key does not match a send that is still on record.' : e.message, true); }
    }
    route();
    renderSent();
    tally();
  }
  start().catch(function (e) { $('off').textContent = 'This page could not start: ' + e.message; $('off').hidden = false; });
})();
