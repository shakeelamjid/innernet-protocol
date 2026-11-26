'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function btn(label, fn, danger) {
    const b = el('button', 'btn btn-sm' + (danger ? ' btn-danger' : ''), label); b.type = 'button';
    b.addEventListener('click', async function (ev) {
      ev.stopPropagation();
      b.disabled = true;
      try { await fn(); await refresh(); } catch (err) { say('act-msg', I.friendly(err), true); }
      b.disabled = false;
    });
    return b;
  }
  const short = function (id) { return id ? id.slice(0, 10) + '…' : ''; };
  const pct = function (v) { return v == null ? '–' : (v * 100).toFixed(1) + '%'; };
  const when = function (t) { return t ? I.when(t) : '–'; };
  function versionAtLeast(v, min) {
    const a = String(v).split('.').map(Number), b = min.split('.').map(Number);
    for (let i = 0; i < 3; i++) { if ((a[i] || 0) !== b[i]) return (a[i] || 0) > b[i]; }
    return true;
  }
  function td(tr, text, cls) { const c = el('td', cls, text); tr.append(c); return c; }
  function stateTag(r) { return el('span', 'state ' + r.state, r.state + (r.held ? ' · held' : '')); }
  function qs(o) { return Object.keys(o).filter(function (k) { return o[k] !== '' && o[k] != null; }).map(function (k) { return k + '=' + encodeURIComponent(o[k]); }).join('&'); }

  // ---- sign-in ----
  async function signIn() {
    const token = (location.hash.match(/token=([A-Za-z0-9_-]+)/) || [])[1];
    try {
      if (token) {
        const o = await I.api('/api/admin/enroll/options', { token: token });
        const cred = await I.create(o.options);
        await I.api('/api/admin/enroll/verify', { flow: o.flow, credential: cred, name: 'Admin passkey' });
        history.replaceState(null, '', location.pathname);
      } else {
        const o = await I.api('/api/admin/login/options', {});
        await I.api('/api/admin/login/verify', { flow: o.flow, credential: await I.get(o.options) });
      }
      await start();
    } catch (err) { say('signin-msg', I.friendly(err), true); }
  }
  async function showSignIn() {
    $('panel').hidden = true; $('signin').hidden = false; $('logout').hidden = $('add-admin').hidden = true;
    const cfg = await I.api('/api/admin/config');
    const link = /token=/.test(location.hash);
    $('pw-form').hidden = !cfg.password || link;
    $('signin-btn').hidden = !(cfg.passkey || link);
    if (link) { $('signin-text').textContent = 'Add your admin passkey. The link works once, for 10 minutes.'; $('signin-btn').textContent = 'Add admin passkey'; }
    else if (!cfg.password && !cfg.passkey) $('signin-text').textContent = 'Admin sign-in is not set up. Set INNERNET_ADMIN_USER and INNERNET_ADMIN_PASSWORD (16+ characters) on the registry and redeploy.';
    else $('signin-text').textContent = cfg.password && cfg.passkey ? 'Or sign in with an admin passkey:' : '';
  }

  // ---- state actions ----
  function setState(ids, state) {
    let reason = '';
    if (state === 'suspended' || state === 'removed') {
      reason = prompt('Reason (the owner sees it). Suspend and remove are held by you until you return the machine to automatic:');
      if (!reason) return Promise.resolve();
    }
    if (ids.length === 1) return I.api('/api/admin/machines/' + ids[0] + '/state', { state: state, reason: reason });
    return I.api('/api/admin/bulk', { ids: ids, state: state, reason: reason }).then(function (r) {
      say('act-msg', r.done + ' changed' + (r.failed.length ? ', ' + r.failed.length + ' failed: ' + r.failed.map(function (f) { return f.error; }).join('; ') : '.'), !!r.failed.length);
    });
  }

  // ---- summary and waiting queue ----
  async function loadSummary() {
    const s = await I.api('/api/admin/summary');
    const tiles = $('tiles'); tiles.textContent = '';
    [[s.machines, 'machines'], [s.online, 'online now'], [s.states.listed || 0, 'listed'], [s.waiting_total, 'waiting for approval'],
      [(s.states.suspended || 0) + (s.states.gone || 0), 'suspended or gone'], [s.held, 'held by admin'], [s.owners, 'owners']]
      .forEach(function (t) { const li = el('li'); li.append(el('strong', '', String(t[0])), el('span', '', t[1])); tiles.append(li); });
    $('n-waiting').textContent = s.waiting_total ? '(' + s.waiting_total + ')' : '';
    $('n-machines').textContent = '(' + s.machines + ')';
    $('n-owners').textContent = '(' + s.owners + ')';
    $('n-setups').textContent = s.setups ? '(' + s.setups + ')' : '';
    $('waiting-note').textContent = 'Machines are listed automatically after ' + s.auto_list_hours + ' h of checks at 95% reachability with a valid payout contract. Approve to list one now.';
    const tb = $('waiting'); tb.textContent = '';
    if (!s.waiting.length) { const tr = el('tr'); td(tr, 'Nobody is waiting.', 'dim').colSpan = 8; tb.append(tr); }
    s.waiting.forEach(function (r) {
      const tr = el('tr', 'clickable');
      td(tr, ''); td(tr, r.name).append(el('div', 'mono dim', short(r.id)));
      td(tr, short(r.owner), 'mono'); td(tr, when(r.applied_at)); td(tr, r.online ? 'yes' : 'no'); td(tr, pct(r.uptime_7d));
      td(tr, r.services.join(', '));
      const c = td(tr, ''); c.append(btn('Approve', function () { return setState([r.id], 'listed'); }));
      tr.addEventListener('click', function () { openMachine(r.id); });
      tb.append(tr);
    });
  }

  // ---- machines table ----
  const M = { q: '', state: '', online: '', owner: '', sort: 'applied_at', dir: 'desc', page: 1, size: 50 };
  const selected = new Set();
  async function loadMachines() {
    const d = await I.api('/api/admin/machines?' + qs(M));
    $('m-count').textContent = d.total + ' machines' + (M.owner ? ' of owner ' + short(M.owner) : '');
    const pages = Math.max(1, Math.ceil(d.total / d.size));
    $('m-page').textContent = 'Page ' + d.page + ' of ' + pages;
    $('m-prev').disabled = d.page <= 1; $('m-next').disabled = d.page >= pages;
    const tb = $('machines'); tb.textContent = '';
    if (!d.rows.length) { const tr = el('tr'); td(tr, 'No machines match.', 'dim').colSpan = 9; tb.append(tr); }
    d.rows.forEach(function (r) {
      const tr = el('tr', 'clickable');
      const c0 = td(tr, ''); const cb = el('input'); cb.type = 'checkbox'; cb.checked = selected.has(r.id);
      cb.addEventListener('click', function (ev) { ev.stopPropagation(); cb.checked ? selected.add(r.id) : selected.delete(r.id); bulkbar(); });
      c0.append(cb);
      td(tr, r.name).append(el('div', 'mono dim', short(r.id)));
      const co = td(tr, short(r.owner), 'mono link');
      co.addEventListener('click', function (ev) { ev.stopPropagation(); M.owner = r.owner; M.page = 1; loadMachines(); });
      td(tr, '').append(stateTag(r));
      td(tr, r.online ? (r.path || 'yes') : 'no');
      td(tr, r.services.join(', ')); td(tr, r.region); td(tr, pct(r.uptime_7d)); td(tr, when(r.last_seen));
      tr.addEventListener('click', function () { openMachine(r.id); });
      tb.append(tr);
    });
    bulkbar();
  }
  function bulkbar() {
    $('bulkbar').hidden = !selected.size;
    $('bulk-n').textContent = selected.size + ' selected';
  }

  // ---- machine details drawer ----
  async function openMachine(id) {
    const d = await I.api('/api/admin/machines/' + id);
    $('d-title').textContent = d.name + ' · ' + d.state + (d.held ? ' (held by admin)' : '');
    const b = $('d-body'); b.textContent = '';
    const kv = el('dl', 'kv');
    function add(k, v) { kv.append(el('dt', '', k), el('dd', '', v == null || v === '' ? '–' : String(v))); }
    add('Machine id', d.id); add('Owner', d.owner + ' (' + d.owner_machines.length + ' machines)');
    add('Reason', d.reason); add('Services', d.services.join(', '));
    add('Prices', Object.keys(d.prices).map(function (k) { return k + ' ' + d.prices[k]; }).join(' · '));
    add('Payout', Object.keys(d.payto).map(function (k) { return d.payto[k] + ' (' + k + ')'; }).join('; '));
    const payDd = kv.lastChild;
    add('Listed address', (d.endpoints || []).map(function (e) { return e.host + ':' + e.port; }).join(', '));
    const pr = d.presence && d.presence.record && d.presence.record.payload;
    add('Now', pr ? (d.presence.online ? 'online' : 'offline') + ' · ' + pr.path + ' · ' + pr.endpoint.host + ':' + pr.endpoint.port + ' · ' + pr.software : 'no check-in yet');
    add('Hours', d.availability ? JSON.stringify(d.availability) : 'always on');
    add('Region / type', (d.region || '?') + ' / ' + (d.class || '?'));
    add('Applied / listed', when(d.applied_at) + ' / ' + when(d.listed_at));
    add('Owner signed in', d.sessions + ' sessions');
    b.append(kv);
    (d.payout || []).forEach(function (po) { if (!po.ok) b.append(payoutBox(d, po, payDd)); });
    const acts = el('div', 'admin-row admin-acts');
    if (d.state !== 'listed') acts.append(btn('Approve (list)', function () { return setState([d.id], 'listed'); }));
    if (d.state !== 'suspended') acts.append(btn('Suspend', function () { return setState([d.id], 'suspended'); }));
    if (d.state !== 'removed') acts.append(btn('Remove', function () { return setState([d.id], 'removed'); }, true));
    if (d.held || d.state === 'suspended' || d.state === 'removed') acts.append(btn('Return to automatic', function () { return setState([d.id], 'auto'); }));
    const sw = ((d.presence && d.presence.record && d.presence.record.payload.software) || '').split('/')[1] || '';
    const canAsk = versionAtLeast(sw, '0.6.9');
    const ask = btn('Ask machine to check now', function () {
      return I.api('/api/admin/machines/' + d.id + '/check', { what: 'update,payout' }).then(function () {
        say('act-msg', d.name + ' will check for a new release and its payout contract within about a minute.');
      });
    });
    if (!canAsk) {
      ask.disabled = true;
      ask.title = 'This machine runs ' + (sw || 'an unknown version') + '. Only 0.6.9 or newer can be asked; it updates itself every 6 hours.';
      b.append(el('p', 'dim', 'This machine runs provider ' + (sw || '?') + ', which cannot be asked to check now. It updates itself within 6 hours of its last start; after that, "Ask machine to check now" works.'));
    }
    acts.append(ask);
    acts.append(btn('Log out owner', function () { return I.api('/api/admin/machines/' + d.id + '/logout', {}); }));
    acts.append(btn('Delete machine', function () {
      const typed = prompt('This deletes the machine, its setups, machine code and presence. Its payout contract becomes free. Payment history is kept.\n\nType the first 8 characters of the machine id (' + d.id.slice(0, 8) + ') to confirm:');
      if (!typed) return Promise.resolve();
      return I.api('/api/admin/machines/' + d.id + '/delete', { confirm: typed.trim().toLowerCase() }).then(function () { $('drawer').hidden = true; });
    }, true));
    b.append(acts);
    b.append(el('h3', '', 'Owner passkeys'));
    const pk = el('div', 'admin-keys');
    if (!d.passkeys.length) pk.append(el('p', 'dim', 'None.'));
    d.passkeys.forEach(function (k) {
      const r = el('div', 'admin-row');
      r.append(el('span', '', k.name + ' · added ' + when(k.created_at) + ' · last used ' + when(k.last_used)),
        btn('Delete passkey', function () { return I.api('/api/admin/passkeys/' + encodeURIComponent(k.id) + '/delete', {}); }, true));
      pk.append(r);
    });
    b.append(pk);
    b.append(el('h3', '', 'Recent events'));
    const t = el('table', 'adm'); const tb = el('tbody');
    d.audit.forEach(function (a) { const tr = el('tr'); td(tr, when(a.ts), 'dim'); td(tr, a.event); td(tr, a.detail); tb.append(tr); });
    t.append(tb); b.append(t);
    $('drawer').hidden = false;
  }

  // ---- payout contracts: the admin may create one for a machine and pay its network fee ----
  let netCfg = null;
  async function network(caip2) {
    if (!netCfg) netCfg = await (await fetch(I.BASE + '/v1/config')).json();
    return { cfg: netCfg, net: (netCfg.networks || []).find(function (n) { return n.caip2 === caip2; }) };
  }

  function payoutBox(d, po, payDd) {
    const box = el('div', 'notice pay-box');
    const msg = el('p', 'msg');
    function say2(t, bad) { msg.textContent = t; msg.classList.toggle('error', !!bad); }
    if (po.wallet && po.contract) {
      box.append(el('p', '', 'Payout contract created: ' + po.contract + '. The machine switches to it by itself within about 10 minutes ' +
        '(provider 0.6.8 or newer), then it can be listed again.'));
      return box;
    }
    if (!po.wallet) {
      box.append(el('p', '', 'Payout problem: ' + (po.note || 'unknown') + (po.note && po.note.indexOf('could not') >= 0 ? ' This is checked again every few minutes.' : '')));
      return box;
    }
    box.append(el('p', '', 'No payout contract yet. This machine is paid to the plain wallet ' + po.address + ', so it is not listed ' +
      '(a listed one is suspended). You can create its payout contract and pay the network fee yourself, about $0.01 in ETH on Base. ' +
      'The contract pays that wallet 97.5% and the network 2.5%; nobody can change that. The machine then switches to it by itself.'));
    const qr = el('div', 'qr'); qr.hidden = true;
    const link = el('a', '', 'Open your wallet app'); link.hidden = true;
    async function pay(phone) {
      const W = window.InnernetWallet;
      const n = await network(po.network);
      if (!n.net || !n.net.factory) throw new Error('No payout factory on ' + po.network + ' yet.');
      let account;
      if (phone) {
        say2('Preparing a QR code… scan it with your wallet app.');
        account = await W.connectPhone(I.BASE, n.cfg, n.net, function (uri, svg) {
          qr.innerHTML = svg; qr.hidden = false; link.href = uri; link.hidden = false;
          say2('Scan with your wallet app and approve the connection, then approve the transaction.');
        });
      } else {
        account = await W.connect(n.net.chain_id);
      }
      qr.hidden = true; link.hidden = true;
      const split = await W.findOrCreate(n.net.factory, account, po.address, function (t) {
        say2(t === 'Confirm in your wallet…' ? 'Approve the transaction in your wallet (network fee about $0.01)…' : t);
      });
      say2('Payout contract ready: ' + split + '. Paid by ' + account + '. The machine is asked to switch to it now.');
      await I.api('/api/admin/machines/' + d.id + '/check', { what: 'payout' }).catch(function () {});
    }
    function run(phone) { return pay(phone).catch(function (err) { qr.hidden = true; link.hidden = true; say2(window.InnernetWallet.friendly(err), true); }); }
    const row = el('div', 'admin-row');
    const b1 = el('button', 'btn btn-sm', 'Pay the fee with my phone wallet (QR)'); b1.type = 'button';
    const b2 = el('button', 'btn btn-sm', 'Pay with a browser wallet'); b2.type = 'button';
    b1.addEventListener('click', function () { run(true); });
    b2.addEventListener('click', function () { run(false); });
    row.append(b1, b2);
    box.append(row, qr, link, msg);
    // The payout address itself starts the phone payment.
    if (payDd) {
      payDd.textContent = '';
      const a = el('button', 'linkish mono', po.address + ' · no payout contract: pay the fee'); a.type = 'button';
      a.addEventListener('click', function () { box.scrollIntoView({ behavior: 'smooth', block: 'center' }); run(true); });
      payDd.append(a);
    }
    return box;
  }

  // ---- owners, setups, admins, audit ----
  const O = { q: '', page: 1 };
  async function loadOwners() {
    const d = await I.api('/api/admin/owners?' + qs(O));
    $('o-count').textContent = d.total + ' owners';
    const tb = $('owners'); tb.textContent = '';
    d.rows.forEach(function (o) {
      const tr = el('tr', 'clickable');
      td(tr, short(o.owner), 'mono').append(el('div', 'dim', o.names.slice(0, 3).join(', ') + (o.names.length > 3 ? '…' : '')));
      td(tr, String(o.machines)); td(tr, String(o.online));
      td(tr, Object.keys(o.states).map(function (k) { return o.states[k] + ' ' + k; }).join(', '));
      td(tr, o.payouts.map(short).join(', ') || '–', 'mono'); td(tr, String(o.passkeys)); td(tr, String(o.sessions));
      tr.addEventListener('click', function () { M.owner = o.owner; M.page = 1; tab('machines'); });
      tb.append(tr);
    });
  }
  async function loadSetups() {
    const d = await I.api('/api/admin/setups');
    const tb = $('setups'); tb.textContent = '';
    if (!d.rows.length) { const tr = el('tr'); td(tr, 'None.', 'dim').colSpan = 5; tb.append(tr); }
    d.rows.forEach(function (r) {
      const tr = el('tr');
      td(tr, (r.name || '?')).append(el('div', 'mono dim', short(r.provider)));
      td(tr, r.os || '?'); td(tr, r.status); td(tr, when(r.created_at));
      td(tr, '').append(btn('Delete', function () { return I.api('/api/admin/machines/' + r.provider + '/delete', { confirm: r.provider.slice(0, 8) }); }, true));
      tb.append(tr);
    });
  }
  async function loadAdmins() {
    const d = await I.api('/api/admin/overview');
    const tb = $('admins'); tb.textContent = '';
    d.admins.forEach(function (a) {
      const tr = el('tr');
      td(tr, a.name); td(tr, when(a.created_at)); td(tr, when(a.last_used));
      td(tr, '').append(btn('Delete', function () { return I.api('/api/admin/admins/' + encodeURIComponent(a.id) + '/delete', {}); }, true));
      tb.append(tr);
    });
  }
  const A = { q: '', page: 1 };
  async function loadAudit() {
    const d = await I.api('/api/admin/audit?' + qs(A));
    const pages = Math.max(1, Math.ceil(d.total / d.size));
    $('a-count').textContent = d.total + ' events'; $('a-page').textContent = 'Page ' + d.page + ' of ' + pages;
    $('a-prev').disabled = d.page <= 1; $('a-next').disabled = d.page >= pages;
    const tb = $('audit'); tb.textContent = '';
    d.rows.forEach(function (a) {
      const tr = el('tr');
      td(tr, when(a.ts), 'dim'); td(tr, a.provider === '-' ? 'admin' : short(a.provider), 'mono'); td(tr, a.event); td(tr, a.detail);
      tb.append(tr);
    });
  }

  // ---- tabs ----
  let current = 'waiting';
  const LOAD = { waiting: loadSummary, machines: loadMachines, owners: loadOwners, setups: loadSetups, admins: loadAdmins, audit: loadAudit };
  function tab(name) {
    current = name;
    document.querySelectorAll('[role=tab]').forEach(function (t) { t.setAttribute('aria-selected', String(t.getAttribute('data-tab') === name)); });
    document.querySelectorAll('.tabpanel').forEach(function (p) { p.hidden = p.getAttribute('data-panel') !== name; });
    LOAD[name]().catch(function (err) { say('act-msg', I.friendly(err), true); });
  }
  async function refresh() {
    await loadSummary();
    if (current !== 'waiting') await LOAD[current]();
  }
  async function start() {
    try { await loadSummary(); }
    catch (err) { if (err.status === 401) { await showSignIn(); return; } throw err; }
    $('signin').hidden = true; $('panel').hidden = false; $('logout').hidden = $('add-admin').hidden = false;
    tab(current);
  }

  document.querySelectorAll('[role=tab]').forEach(function (t) { t.addEventListener('click', function () { tab(t.getAttribute('data-tab')); }); });
  let timer = null;
  function debounce(fn) { clearTimeout(timer); timer = setTimeout(fn, 250); }
  $('m-q').addEventListener('input', function () { M.q = this.value; M.page = 1; debounce(loadMachines); });
  $('m-state').addEventListener('change', function () { M.state = this.value; M.page = 1; loadMachines(); });
  $('m-online').addEventListener('change', function () { M.online = this.value; M.page = 1; loadMachines(); });
  $('m-prev').addEventListener('click', function () { M.page--; loadMachines(); });
  $('m-next').addEventListener('click', function () { M.page++; loadMachines(); });
  document.querySelectorAll('[data-sort]').forEach(function (h) {
    h.classList.add('sortable');
    h.addEventListener('click', function () {
      const k = h.getAttribute('data-sort');
      M.dir = M.sort === k && M.dir === 'desc' ? 'asc' : 'desc'; M.sort = k; loadMachines();
    });
  });
  $('m-all').addEventListener('change', function () {
    const on = this.checked;
    document.querySelectorAll('#machines input[type=checkbox]').forEach(function (cb) { cb.checked = on; cb.dispatchEvent(new Event('sync')); });
    I.api('/api/admin/machines?' + qs(M)).then(function (d) { d.rows.forEach(function (r) { on ? selected.add(r.id) : selected.delete(r.id); }); bulkbar(); });
  });
  document.querySelectorAll('[data-bulk]').forEach(function (b) {
    b.addEventListener('click', async function () {
      try { await setState(Array.from(selected), b.getAttribute('data-bulk')); selected.clear(); await refresh(); }
      catch (err) { say('act-msg', I.friendly(err), true); }
    });
  });
  $('o-q').addEventListener('input', function () { O.q = this.value; debounce(loadOwners); });
  $('a-q').addEventListener('input', function () { A.q = this.value; A.page = 1; debounce(loadAudit); });
  $('a-prev').addEventListener('click', function () { A.page--; loadAudit(); });
  $('a-next').addEventListener('click', function () { A.page++; loadAudit(); });
  $('d-close').addEventListener('click', function () { $('drawer').hidden = true; });
  $('check-all').addEventListener('click', async function () {
    try {
      const r = await I.api('/api/admin/check-all', { what: 'update,payout' });
      say('act-msg', r.able + ' of ' + r.machines + ' machines will check within about a minute.' +
        (r.machines > r.able ? ' ' + (r.machines - r.able) + ' run an older provider that cannot be asked; they update themselves within 6 hours.' : ''));
    } catch (err) { say('act-msg', I.friendly(err), true); }
  });
  $('signin-btn').addEventListener('click', signIn);
  $('pw-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try {
      await I.api('/api/admin/login/password', { user: $('pw-user').value.trim(), password: $('pw-pass').value });
      $('pw-pass').value = '';
      await start();
    } catch (err) { say('signin-msg', I.friendly(err), true); }
  });
  $('logout').addEventListener('click', async function () { await I.api('/api/admin/logout', {}); location.reload(); });
  $('add-admin').addEventListener('click', async function () {
    try {
      const o = await I.api('/api/admin/enroll/options', {});
      await I.api('/api/admin/enroll/verify', { flow: o.flow, credential: await I.create(o.options), name: prompt('Name for this passkey:', 'Admin passkey') || 'Admin passkey' });
      tab('admins');
    } catch (err) { say('act-msg', I.friendly(err), true); }
  });
  start().catch(function (err) { say('act-msg', I.friendly(err), true); });
})();
