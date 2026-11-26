'use strict';
(function () {
  const I = window.Innernet, W = window.InnernetWallet;
  const $ = function (id) { return document.getElementById(id); };
  let cfg = null, net = null;

  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  let machineGiB = 0;
  function sync() {
    document.querySelectorAll('[data-for]').forEach(function (el) { el.hidden = !$(el.getAttribute('data-for')).checked; });
    const compute = $('cmp-on').checked || (!$('gpu-block').hidden && $('gpu-on').checked);
    $('share-fields').hidden = $('share-msg').hidden = !compute;
    if (compute) {
      const left = machineGiB ? Math.max(0, machineGiB - num('reserve-gib')) : 0;
      $('share-msg').textContent = 'Several clients can use this machine at once. Storage always goes first; CPU jobs and GPU sessions ' +
        'share ' + (left ? left + ' GiB of memory' : 'the memory you do not keep') + ', and new work waits while you need the memory yourself. ' +
        'When it is full, clients are told at once and go to another provider.';
    }
  }
  function num(id) { const v = parseInt($(id).value, 10); return isNaN(v) ? 0 : v; }

  function gpuLine(g) {
    const mem = g.vram_mib ? ' · ' + Math.round(g.vram_mib / 1024) + ' GiB' + (g.api === 'metal' ? ' shared' : '') : '';
    const cores = g.cores ? ' · ' + g.cores + ' cores' : '';
    const api = g.api && g.api !== 'none' ? ' · ' + ({ cuda: 'CUDA', metal: 'Metal', rocm: 'ROCm', oneapi: 'oneAPI' }[g.api] || g.api) : ' · display only';
    return g.model + cores + mem + api;
  }
  function gpuText(gpus) {
    if (!gpus) return 'not reported (update the provider)';
    if (!gpus.length) return 'none found';
    const counts = {};
    gpus.forEach(function (g) { const k = gpuLine(g); counts[k] = (counts[k] || 0) + 1; });
    return Object.keys(counts).map(function (k) { return (counts[k] > 1 ? counts[k] + ' × ' : '') + k; }).join('; ');
  }
  function bestGpu(gpus) {
    return (gpus || []).filter(function (g) { return g.api && g.api !== 'none'; })
      .sort(function (a, b) { return (b.vram_mib || 0) - (a.vram_mib || 0) || (b.cores || 0) - (a.cores || 0); })[0] || null;
  }

  function fill(d) {
    const det = d.detected || {}, draft = d.draft, cur = d.current;
    const facts = $('facts');
    [['System', (det.os || '?') + ' / ' + (det.arch || '?')], ['CPUs', String(det.cpus || '?')],
      ['Free disk', det.storage_free_gib ? det.storage_free_gib + ' GiB' : 'unknown'],
      ['Memory', det.memory_mib ? Math.round(det.memory_mib / 1024) + ' GiB' : 'unknown'],
      ['GPU', gpuText(det.gpus)]].forEach(function (r) {
      const dt = document.createElement('dt'); dt.textContent = r[0];
      const dd = document.createElement('dd'); dd.textContent = r[1];
      facts.append(dt, dd);
    });
    if (det.path === 'tunnel') say('reach', 'Reachability: clients reach this machine through the INNERnet HTTPS tunnel (it connects out, so no router settings are needed). Requests stay signed end to end.');
    else if (det.path === 'relay') say('reach', 'Reachability: clients reach this machine through the INNERnet relay (it connects out, so no router settings are needed). Data stays encrypted end to end.');
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
    const g = bestGpu(det.gpus);
    $('gpu-block').hidden = !g;
    if (g) {
      const same = det.gpus.filter(function (x) { return x.model === g.model; }).length;
      $('gpu-name').textContent = gpuLine(g);
      $('gpu-count').max = same;
      $('gpu-count').value = draft && draft.gpu ? draft.gpus : same;
      $('gpu-on').checked = !!(draft && draft.gpu);
      $('gpu-price').value = prices['GPU-1'];
      const m = d.market && d.market['GPU-1'];
      const mm = m && m.by_model && m.by_model[g.model];
      $('gpu-market').textContent = (mm ? 'Others with ' + g.model + ' ask ' + mm.median + ' USDC per GPU-hour (typical ' + mm.low + '–' + mm.high + ', ' + mm.providers + ' listed).'
        : 'No other ' + g.model + ' is listed yet, so there is no market price to compare with.') +
        ' A client\'s model is downloaded to this machine the first time it is used (up to 64 GiB; the oldest are removed past 40 GiB).';
    }
    machineGiB = det.memory_mib ? Math.round(det.memory_mib / 1024) : 0;
    $('reserve-gib').value = draft && draft.reserve_gib != null ? draft.reserve_gib : (det.class === 'server' ? 1 : 4);
    $('per-client').value = draft && draft.per_client ? draft.per_client : 2;
    $('sto-price').value = prices['STO-1']; $('rly-price').value = prices['RLY-1']; $('cmp-price').value = prices['CMP-1'];
    $('payout').value = (draft && draft.payout) || (cur && cur.payto && Object.values(cur.payto)[0]) || '';
    $('share-you').textContent = (100 - d.fee_bps / 100) + '%';
    $('share-fee').textContent = (d.fee_bps / 100) + '%';
    sync();
  }

  ['sto-on', 'rly-on', 'cmp-on', 'gpu-on', 'reserve-gib'].forEach(function (id) { $(id).addEventListener('change', sync); });
  $('reserve-gib').addEventListener('input', sync);

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
      gpu: !$('gpu-block').hidden && $('gpu-on').checked, gpus: Math.max(1, num('gpu-count')),
      reserve_gib: Math.max(0, num('reserve-gib')), per_client: Math.min(64, Math.max(1, num('per-client'))),
      prices: { 'STO-1': $('sto-price').value.trim(), 'RLY-1': $('rly-price').value.trim(), 'CMP-1': $('cmp-price').value.trim(),
        'GPU-1': $('gpu-price').value.trim() },
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
