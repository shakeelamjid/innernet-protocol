'use strict';
(function () {
  const I = window.Innernet, W = window.InnernetWallet;
  const $ = function (id) { return document.getElementById(id); };
  let cfg = null, net = null;

  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  function sync() {
    document.querySelectorAll('[data-for]').forEach(function (el) { el.hidden = !$(el.getAttribute('data-for')).checked; });
  }
  function num(id) { const v = parseInt($(id).value, 10); return isNaN(v) ? 0 : v; }

  function fill(d) {
    const det = d.detected || {}, draft = d.draft, cur = d.current;
    const facts = $('facts');
    [['System', (det.os || '?') + ' / ' + (det.arch || '?')], ['CPUs', String(det.cpus || '?')],
      ['Free disk', det.storage_free_gib ? det.storage_free_gib + ' GiB' : 'unknown'],
      ['Memory', det.memory_mib ? Math.round(det.memory_mib / 1024) + ' GiB' : 'unknown']].forEach(function (r) {
      const dt = document.createElement('dt'); dt.textContent = r[0];
      const dd = document.createElement('dd'); dd.textContent = r[1];
      facts.append(dt, dd);
    });
    if (det.path === 'relay') say('reach', 'Reachability: clients reach this machine through the INNERnet relay (it connects out, so no router settings are needed). Data stays encrypted end to end.');
    else if (det.reachable === true) say('reach', 'Reachability: other machines can reach ' + det.host + ':' + det.port + (det.path === 'router' ? ' (port opened on your router).' : '.'));
    else say('reach', 'Reachability: we could not reach ' + (det.host || 'your machine') + ':' + (det.port || '') +
      ' from the internet. Open this TCP port on your firewall or router, or use a server with a public address.', true);
    const src = draft || {};
    $('name').value = src.name || (cur && cur.name) || det.name || '';
    $('region').value = src.region || (cur && cur.region) || det.region || '';
    $('host').value = src.host || det.host || '';
    $('port').value = src.port || det.port || 9443;
    const freeGib = det.storage_free_gib || 100;
    $('sto-on').checked = draft ? draft.storage_gib > 0 : true;
    $('sto-gib').value = draft && draft.storage_gib ? draft.storage_gib : Math.max(1, Math.min(200, Math.floor(freeGib / 2)));
    $('rly-on').checked = !!(draft && draft.relay_gib > 0);
    $('rly-gib').value = draft && draft.relay_gib ? draft.relay_gib : 500;
    $('cmp-on').checked = !!(draft && draft.compute);
    $('cmp-cpus').value = draft ? draft.cpus : Math.max(1, Math.min(4, (det.cpus || 2) - 1));
    $('cmp-mem').value = draft ? draft.memory_mib : 1024;
    const prices = Object.assign({}, d.defaults.prices, (draft && draft.prices) || {});
    $('sto-price').value = prices['STO-1']; $('rly-price').value = prices['RLY-1']; $('cmp-price').value = prices['CMP-1'];
    $('payout').value = (draft && draft.payout) || (cur && cur.payto && Object.values(cur.payto)[0]) || '';
    $('share-you').textContent = (100 - d.fee_bps / 100) + '%';
    $('share-fee').textContent = (d.fee_bps / 100) + '%';
    sync();
  }

  ['sto-on', 'rly-on', 'cmp-on'].forEach(function (id) { $(id).addEventListener('change', sync); });

  $('connect').addEventListener('click', async function () {
    if (!net || !net.factory) { say('pay-msg', 'Payout contracts open as soon as the split factory is deployed. Check back shortly.', true); return; }
    try {
      const account = await W.connect(net.chain_id);
      say('pay-msg', 'Connected: ' + account);
      const split = await W.findOrCreate(net.factory, account, account, function (t) { say('pay-msg', t); });
      $('payout').value = split;
      say('pay-msg', 'Payout contract ready. It pays ' + account + '.');
    } catch (err) { say('pay-msg', W.friendly(err), true); }
  });

  $('form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const offer = {
      name: $('name').value.trim().toLowerCase(), region: $('region').value.trim().toLowerCase(),
      host: $('host').value.trim(), port: num('port'),
      storage_gib: $('sto-on').checked ? num('sto-gib') : 0, relay_gib: $('rly-on').checked ? num('rly-gib') : 0,
      compute: $('cmp-on').checked, cpus: Math.max(1, num('cmp-cpus')), memory_mib: Math.max(64, num('cmp-mem')),
      prices: { 'STO-1': $('sto-price').value.trim(), 'RLY-1': $('rly-price').value.trim(), 'CMP-1': $('cmp-price').value.trim() },
      network: net ? net.caip2 : 'eip155:84532', payout: $('payout').value.trim()
    };
    $('send').disabled = true;
    say('send-msg', 'Sending…');
    try {
      const r = await I.api('/api/setup', offer);
      say('send-msg', 'Sent. Go back to your terminal and confirm.' + (r.note ? ' (' + r.note + ')' : ''));
    } catch (err) { say('send-msg', I.friendly(err), true); }
    $('send').disabled = false;
  });

  Promise.all([I.api('/api/setup'), fetch(I.BASE + '/v1/config').then(function (r) { return r.json(); })]).then(function (res) {
    const d = res[0]; cfg = res[1];
    net = (cfg.networks || []).find(function (n) { return n.caip2 === 'eip155:84532'; }) || (cfg.networks || [])[0];
    fill(d);
    $('form').hidden = false;
  }).catch(function (err) {
    if (err.status === 401) { location.replace(I.BASE + '/claim'); return; }
    say('err', I.friendly(err), true); $('err').hidden = false;
  });
})();
