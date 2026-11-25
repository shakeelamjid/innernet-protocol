'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  const LABELS = { 'STO-1': 'Storage', 'RLY-1': 'Bandwidth', 'CMP-1': 'Compute' };
  const STATES = {
    testing: 'Testing: being checked before listing',
    listed: 'Listed: visible to everyone',
    suspended: 'Suspended: hidden from clients',
    removed: 'Removed'
  };

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }
  function tr(cells) {
    const row = document.createElement('tr');
    cells.forEach(function (c) {
      const td = document.createElement('td');
      if (c instanceof Node) td.append(c); else if (c && c.text !== undefined) { td.textContent = c.text; td.className = c.cls || ''; } else td.textContent = c;
      row.append(td);
    });
    return row;
  }
  function dl(target, key, value) {
    target.append(el('dt', key), el('dd', value));
  }
  function btn(text, onClick) {
    const b = el('button', text, 'btn btn-sm');
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }
  function short(s) { return s.length > 14 ? s.slice(0, 8) + '…' + s.slice(-4) : s; }
  function device(ua) {
    ua = ua || '';
    const os = /iPhone|iPad/.test(ua) ? 'iPhone / iPad' : /Android/.test(ua) ? 'Android' : /Mac OS X|Macintosh/.test(ua) ? 'Mac'
      : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown system';
    const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome'
      : /Safari\//.test(ua) ? 'Safari' : 'browser';
    return br + ' on ' + os;
  }
  const LIMITS = {
    max_storage_gib: function (v) { return 'up to ' + v + ' GiB'; },
    max_gib_per_month: function (v) { return 'up to ' + v + ' GiB a month'; },
    max_cpus: function (v) { return v + (v === 1 ? ' CPU' : ' CPUs'); },
    max_memory_mib: function (v) { return v + ' MiB memory'; }
  };

  async function showLogin() {
    $('dash').hidden = true;
    $('logout').hidden = true;
    $('who').textContent = '';
    $('login').hidden = false;
    if (!I.supported()) {
      $('login-btn').disabled = true;
      $('login-msg').textContent = 'This browser does not support passkeys.';
    }
  }

  $('login-btn').addEventListener('click', async function () {
    const msg = $('login-msg');
    msg.classList.remove('error');
    msg.textContent = 'Waiting for your passkey…';
    try {
      const start = await I.api('/api/login/options', {});
      const credential = await I.get(start.options);
      await I.api('/api/login/verify', { flow: start.flow, credential: credential });
      msg.textContent = '';
      load();
    } catch (err) {
      msg.textContent = I.friendly(err);
      msg.classList.add('error');
    }
  });

  $('logout').addEventListener('click', async function () {
    try { await I.api('/api/logout', {}); } catch (e) { /* ignore */ }
    showLogin();
  });

  $('add-passkey').addEventListener('click', async function () {
    const msg = $('passkey-msg');
    msg.classList.remove('error');
    msg.textContent = 'Waiting for your device…';
    try {
      const start = await I.api('/api/enroll/options', {});
      const credential = await I.create(start.options);
      await I.api('/api/enroll/verify', { flow: start.flow, credential: credential, name: 'Passkey ' + new Date().toISOString().slice(0, 10) });
      msg.textContent = 'Passkey added.';
      load();
    } catch (err) {
      msg.textContent = I.friendly(err);
      msg.classList.add('error');
    }
  });

  function render(d) {
    const e = d.provider;
    $('login').hidden = true;
    $('dash').hidden = false;
    $('logout').hidden = false;
    $('who').textContent = e.name;
    document.title = e.name + ' · Provider dashboard';
    $('name').textContent = e.name;
    $('pid').textContent = e.id;
    $('state').textContent = d.state;
    $('state').className = 'state ' + d.state;
    $('state-text').textContent = STATES[d.state] || d.state;
    $('reason').textContent = d.reason || '–';
    $('applied').textContent = I.when(d.applied_at);
    $('listed').textContent = I.when(d.listed_at);
    $('checked').textContent = I.when(d.checked_at);

    const e30 = d.earnings['30d'];
    $('e-gross').textContent = e30.gross + ' USDC';
    $('e-fee-label').textContent = 'Network fee (' + (d.fee_bps / 100) + '%)';
    $('e-fee').textContent = e30.fee + ' USDC';
    $('e-net').textContent = e30.net + ' USDC';
    $('e-all').textContent = 'All time: ' + d.earnings.all.gross + ' USDC paid, ' + d.earnings.all.net + ' USDC to you.';
    const bars = $('bars');
    bars.replaceChildren();
    const max = Math.max.apply(null, d.daily.map(function (x) { return parseFloat(x.net); }).concat([0.000001]));
    d.daily.forEach(function (x) {
      const i = document.createElement('i');
      i.style.height = Math.max(1, Math.round(parseFloat(x.net) / max * 100)) + '%';
      i.title = x.day + ': ' + x.net + ' USDC to you';
      bars.append(i);
    });
    $('bars-from').textContent = d.daily.length ? d.daily[0].day : '';
    $('bars-to').textContent = d.daily.length ? d.daily[d.daily.length - 1].day : '';

    const health = $('health');
    health.replaceChildren();
    [['Last 24 hours', '24h'], ['Last 7 days', '7d'], ['Last 30 days', '30d']].forEach(function (w) {
      const h = d.health[w[1]];
      health.append(tr([w[0], { text: h.uptime, cls: 'num' }, { text: String(h.probes), cls: 'num' }]));
    });

    const act = $('activity');
    act.replaceChildren();
    Object.keys(d.activity).forEach(function (svc) {
      act.append(tr([LABELS[svc] || svc, d.activity[svc]]));
    });

    const splits = $('splits');
    splits.replaceChildren();
    d.splits.forEach(function (s) {
      const a = el('a', short(s.tx), 'mono');
      a.href = s.explorer;
      a.rel = 'noopener noreferrer';
      a.target = '_blank';
      splits.append(tr([I.when(s.ts), d.networks[s.network] || s.network, { text: s.amount, cls: 'num' },
        { text: s.provider_share, cls: 'num' }, { text: s.fee_share, cls: 'num' }, a]));
    });
    $('splits-empty').hidden = d.splits.length > 0;

    const offer = $('offer');
    offer.replaceChildren();
    e.services.forEach(function (svc) {
      const pr = e.prices[svc];
      let text = pr.amount + ' ' + pr.asset + ' per ' + pr.unit;
      const lim = (e.limits || {})[svc];
      if (lim) text += ', ' + Object.keys(lim).map(function (k) { return LIMITS[k] ? LIMITS[k](lim[k]) : k.replace(/_/g, ' ') + ' ' + lim[k]; }).join(', ');
      dl(offer, LABELS[svc] || svc, text);
    });
    dl(offer, 'Address', e.endpoints.map(function (x) { return x.host + ':' + x.port; }).join(', '));
    dl(offer, 'Region', e.region);
    Object.keys(e.payto).forEach(function (n) {
      offer.append(el('dt', 'Payout, ' + (d.networks[n] || n)), el('dd', e.payto[n], 'mono'));
    });

    const pks = $('passkeys');
    pks.replaceChildren();
    d.passkeys.forEach(function (k) {
      const actions = el('div', null, 'row-actions');
      actions.append(btn('Rename', async function () {
        const name = prompt('New name for this passkey', k.name);
        if (!name) return;
        try { await I.api('/api/passkeys/' + encodeURIComponent(k.id) + '/rename', { name: name }); load(); }
        catch (err) { $('passkey-msg').textContent = I.friendly(err); }
      }));
      actions.append(btn('Remove', async function () {
        if (!confirm('Remove passkey "' + k.name + '"? That device will no longer open this dashboard.')) return;
        try { await I.api('/api/passkeys/' + encodeURIComponent(k.id) + '/delete', {}); load(); }
        catch (err) { $('passkey-msg').textContent = I.friendly(err); }
      }));
      const label = el('div', k.name);
      label.append(el('div', 'Last used ' + I.when(k.last_used), 'note'));
      pks.append(tr([label, actions]));
    });

    const ses = $('sessions');
    ses.replaceChildren();
    d.sessions.forEach(function (s) {
      const ua = device(s.user_agent);
      const cell = s.current ? el('span', 'This device', 'tag') : btn('Sign out', async function () {
        try { await I.api('/api/sessions/' + encodeURIComponent(s.id) + '/revoke', {}); load(); } catch (err) { /* shown on reload */ }
      });
      ses.append(tr([ua, I.when(s.created_at), cell]));
    });

    const audit = $('audit');
    audit.replaceChildren();
    d.audit.slice(0, 30).forEach(function (a) {
      audit.append(tr([I.when(a.ts), a.event.replace(/-/g, ' '), a.detail || '']));
    });
  }

  async function load() {
    try {
      render(await I.api('/api/me'));
    } catch (err) {
      if (err.status === 401) showLogin();
      else if (err.status === 409) location.replace(I.BASE + '/setup');
      else { $('login-msg').textContent = I.friendly(err); showLogin(); }
    }
  }

  load();
  setInterval(function () { if (!$('dash').hidden) load(); }, 60000);
})();
