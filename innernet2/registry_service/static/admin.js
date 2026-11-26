'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function btn(label, fn, danger) {
    const b = el('button', 'btn btn-sm' + (danger ? ' btn-danger' : ''), label); b.type = 'button';
    b.addEventListener('click', async function () {
      b.disabled = true;
      try { await fn(); await load(); } catch (err) { say('act-msg', I.friendly(err), true); }
      b.disabled = false;
    });
    return b;
  }
  const short = function (id) { return id.slice(0, 12) + '…'; };

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
      await load();
    } catch (err) { say('signin-msg', I.friendly(err), true); }
  }

  function machineCard(m) {
    const c = el('section', 'card frame admin-item');
    const top = el('div', 'admin-row');
    top.append(el('strong', '', m.name || '(no name)'), el('span', 'state ' + m.state, m.state), el('span', 'mono dim', short(m.id)));
    c.append(top);
    const kv = el('dl', 'kv');
    function add(k, v) { kv.append(el('dt', '', k), el('dd', '', v)); }
    add('Machine id', m.id);
    add('Services', (m.services || []).join(', ') || '–');
    add('Payout contract', Object.entries(m.payto || {}).map(function (e) { return e[1] + ' (' + e[0] + ')'; }).join('; ') || '–');
    add('Address', (m.endpoints || []).map(function (e) { return e.host + ':' + e.port; }).join(', ') || '–');
    add('Applied', I.when(m.applied_at)); add('Last seen', m.last_seen ? I.when(m.last_seen) : 'never');
    if (m.reason) add('Reason', m.reason);
    add('Web sessions', String(m.sessions));
    c.append(kv);
    const keys = el('div', 'admin-keys');
    (m.passkeys || []).forEach(function (k) {
      const r = el('div', 'admin-row');
      r.append(el('span', '', 'Passkey ' + k.name + ' · added ' + I.when(k.created_at)),
        btn('Delete passkey', function () { return I.api('/api/admin/passkeys/' + encodeURIComponent(k.id) + '/delete', {}); }, true));
      keys.append(r);
    });
    c.append(keys);
    const acts = el('div', 'admin-row admin-acts');
    function setState(state) {
      return function () {
        const reason = state === 'listed' ? '' : prompt('Reason (the owner sees it):');
        if (state !== 'listed' && !reason) return Promise.resolve();
        return I.api('/api/admin/machines/' + m.id + '/state', { state: state, reason: reason || '' });
      };
    }
    if (m.state !== 'listed') acts.append(btn('Approve (list)', setState('listed')));
    if (m.state !== 'suspended') acts.append(btn('Suspend', setState('suspended')));
    if (m.state !== 'removed') acts.append(btn('Remove', setState('removed'), true));
    acts.append(btn('Log out web sessions', function () { return I.api('/api/admin/machines/' + m.id + '/logout', {}); }));
    acts.append(btn('Delete machine', function () {
      const typed = prompt('This deletes the machine, its passkeys, sessions, setups and machine code. Its payout contract becomes free. ' +
        'Payment history is kept.\n\nType the first 8 characters of the machine id (' + m.id.slice(0, 8) + ') to confirm:');
      if (!typed) return Promise.resolve();
      return I.api('/api/admin/machines/' + m.id + '/delete', { confirm: typed.trim().toLowerCase() });
    }, true));
    c.append(acts);
    return c;
  }

  async function load() {
    let d;
    try { d = await I.api('/api/admin/overview'); }
    catch (err) {
      if (err.status === 401) {
        $('panel').hidden = true; $('signin').hidden = false; $('logout').hidden = $('add-admin').hidden = true;
        const cfg = await I.api('/api/admin/config');
        const link = /token=/.test(location.hash);
        $('pw-form').hidden = !cfg.password || link;
        $('signin-btn').hidden = !(cfg.passkey || link);
        if (link) { $('signin-text').textContent = 'Add your admin passkey. The link works once, for 10 minutes.'; $('signin-btn').textContent = 'Add admin passkey'; }
        else if (!cfg.password && !cfg.passkey) $('signin-text').textContent = 'Admin sign-in is not set up. Set INNERNET_ADMIN_USER and INNERNET_ADMIN_PASSWORD (16+ characters) on the registry and redeploy.';
        else $('signin-text').textContent = cfg.password && cfg.passkey ? 'Or sign in with an admin passkey:' : '';
        return;
      }
      throw err;
    }
    $('signin').hidden = true; $('panel').hidden = false; $('logout').hidden = $('add-admin').hidden = false;
    const counts = {};
    d.machines.forEach(function (m) { counts[m.state] = (counts[m.state] || 0) + 1; });
    $('summary').textContent = d.machines.length + ' machines · ' + Object.keys(counts).map(function (k) { return counts[k] + ' ' + k; }).join(' · ');
    const list = $('machines'); list.textContent = '';
    if (!d.machines.length) list.append(el('p', 'msg', 'No machines yet.'));
    d.machines.forEach(function (m) { list.append(machineCard(m)); });
    const pend = $('pending'); pend.textContent = '';
    if (!d.pending.length) pend.append(el('p', 'msg', 'None.'));
    d.pending.forEach(function (p) {
      const r = el('section', 'card frame admin-item admin-row');
      r.append(el('span', '', (p.name || '?') + ' · ' + p.status + ' · ' + I.when(p.created_at)), el('span', 'mono dim', short(p.provider)),
        btn('Delete', function () { return I.api('/api/admin/machines/' + p.provider + '/delete', { confirm: p.provider.slice(0, 8) }); }, true));
      pend.append(r);
    });
    const ad = $('admins'); ad.textContent = '';
    d.admins.forEach(function (a) {
      const r = el('section', 'card frame admin-item admin-row');
      r.append(el('span', '', a.name + ' · added ' + I.when(a.created_at) + (a.last_used ? ' · last used ' + I.when(a.last_used) : '')),
        btn('Delete', function () { return I.api('/api/admin/admins/' + encodeURIComponent(a.id) + '/delete', {}); }, true));
      ad.append(r);
    });
    const au = $('audit'); au.textContent = '';
    d.audit.forEach(function (a) {
      const tr = el('tr');
      tr.append(el('td', 'dim', I.when(a.ts)), el('td', 'mono', a.provider === '-' ? 'admin' : short(a.provider)), el('td', '', a.event), el('td', '', a.detail));
      au.append(tr);
    });
  }

  $('signin-btn').addEventListener('click', signIn);
  $('pw-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try {
      await I.api('/api/admin/login/password', { user: $('pw-user').value.trim(), password: $('pw-pass').value });
      $('pw-pass').value = '';
      await load();
    } catch (err) { say('signin-msg', I.friendly(err), true); }
  });
  $('logout').addEventListener('click', async function () { await I.api('/api/admin/logout', {}); location.reload(); });
  $('add-admin').addEventListener('click', async function () {
    try {
      const o = await I.api('/api/admin/enroll/options', {});
      await I.api('/api/admin/enroll/verify', { flow: o.flow, credential: await I.create(o.options), name: prompt('Name for this passkey:', 'Admin passkey') || 'Admin passkey' });
      await load();
    } catch (err) { say('act-msg', I.friendly(err), true); }
  });
  load().catch(function (err) { say('act-msg', I.friendly(err), true); });
})();
