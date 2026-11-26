'use strict';
(function () {
  const I = window.Innernet, W = window.InnernetWallet;
  const $ = function (id) { return document.getElementById(id); };
  let cfg = null, net = null, setup = null;
  const enc = new TextEncoder();
  function b64u(buf) {
    let s = ''; new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(s) {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(bin, function (c) { return c.charCodeAt(0); });
  }

  // Lock the passphrase to the machine's key (P-256 ECDH, HKDF-SHA256, AES-256-GCM). Only the machine opens it.
  async function sealTo(machineKey, text) {
    const S = crypto.subtle;
    const pub = await S.importKey('raw', unb64u(machineKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const eph = await S.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const bits = await S.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256);
    const hk = await S.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    const key = await S.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('INNERnet/REG-1/setup-seal') },
      hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode('INNERnet backup passphrase') }, key, enc.encode(text));
    return { epk: b64u(await S.exportKey('raw', eph.publicKey)), iv: b64u(iv), ct: b64u(ct) };
  }

  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  let machineGiB = 0;
  function sync() {
    document.querySelectorAll('[data-for]').forEach(function (el) { el.hidden = !$(el.getAttribute('data-for')).checked; });
    $('bw-fields').hidden = !($('rly-on').checked || $('vpn-on').checked);
    const compute = $('cmp-on').checked || (!$('gpu-block').hidden && $('gpu-on').checked);
    $('share-fields').hidden = $('share-msg').hidden = !compute;
    if (compute) {
      const left = machineGiB ? Math.max(0, machineGiB - num('reserve-gib')) : 0;
      $('share-msg').textContent = 'Several clients can use this machine at once. Storage always goes first; CPU and GPU jobs ' +
        'share ' + (left ? left + ' GiB of memory' : 'the memory you do not keep') + ', and new work waits while you need the memory yourself. ' +
        'When it is full, clients are told at once and go to another provider.';
    }
  }
  // ---- reachability: the person decides what happens when the port is closed ----
  let unreachable = false;
  function reachState(det, pending) {
    const port = det.port || 9443;
    unreachable = det.reachable === false;
    let text, err = false;
    if (det.path === 'tunnel') text = 'Clients reach this machine through the INNERnet HTTPS tunnel: it connects out, so no router settings are needed, and requests stay signed end to end. A direct connection is faster: open TCP port ' + port + ' on your router to this machine, then press Test again.';
    else if (det.path === 'relay') text = 'Clients reach this machine through an INNERnet relay: it connects out, and data stays encrypted end to end.';
    else if (!unreachable) text = 'Clients reach ' + det.host + ':' + port + ' directly' + (det.path === 'router' ? ' (port opened on your router).' : '.');
    else {
      err = true;
      text = 'Clients cannot reach ' + (det.host || 'this machine') + ':' + port + ' yet' + (det.reach_note ? ' (' + det.reach_note + ')' : '') +
        '. Open TCP port ' + port + ' on your router to this machine and press Test again, or connect out through INNERnet instead (an INNERnet relay, or the HTTPS tunnel when no relay is available). You can also type r or o in the terminal.';
    }
    say('reach', text, err);
    $('reach-acts').hidden = !(unreachable || det.path === 'tunnel' || det.path === 'relay');
    $('reach-out').hidden = !unreachable;
    $('reach-retest').disabled = $('reach-out').disabled = !!pending;
    say('reach-msg', pending ? (pending === 'retest' ? 'Your machine is testing the port again…' : 'Your machine is connecting out…') : '');
    // VPN exit needs a real path to the machine: say exactly why it is off.
    const why = det.path === 'tunnel'
      ? 'VPN exit is off: clients reach this machine through the HTTPS tunnel, which carries only signed INNERnet requests, not VPN traffic. To offer VPN exit, open TCP port ' + port + ' on your router to this machine and press Test again, or use an INNERnet relay when one is available.'
      : unreachable ? 'VPN exit is off until clients can reach this machine (see Your machine above).' : '';
    $('vpn-why').textContent = why; $('vpn-why').hidden = !why;
    if (why) $('vpn-on').checked = false;
    $('vpn-on').disabled = !!why;
    $('send').disabled = unreachable;
    if (unreachable) say('send-msg', 'Make this machine reachable first (see Your machine above).', true);
    else if ($('send-msg').textContent.indexOf('reachable first') >= 0) say('send-msg', '');
    sync();
  }
  async function reach(action) {
    try {
      await I.api('/api/setup/reach', { action: action });
      reachState(setup.detected, action);
      for (let i = 0; i < 90; i++) {
        await new Promise(function (r) { setTimeout(r, 2000); });
        const d = await I.api('/api/setup');
        if (!d.request) { setup.detected = d.detected; fillFacts(d.detected); reachState(d.detected, null); return; }
      }
      say('reach-msg', 'Your machine did not answer. Is innernet-provider start still running on it?', true);
      reachState(setup.detected, null);
    } catch (err) { say('reach-msg', I.friendly(err), true); }
  }

  function num(id) { const v = parseInt($(id).value, 10); return isNaN(v) ? 0 : v; }

  function gpuLine(g) {
    const mem = g.vram_mib ? ' · ' + Math.round(g.vram_mib / 1024) + ' GiB' + (g.api === 'metal' ? ' shared' : '') : '';
    const cores = g.cores ? ' · ' + g.cores + ' cores' : '';
    const api = g.api && g.api !== 'none' ? ' · ' + ({ cuda: 'NVIDIA', metal: 'Metal', vulkan: 'Vulkan', directx: 'DirectX', rocm: 'ROCm', oneapi: 'oneAPI' }[g.api] || g.api) : ' · no driver';
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

  function fillFacts(det) {
    const facts = $('facts');
    facts.textContent = '';
    [['System', (det.os || '?') + ' / ' + (det.arch || '?')], ['CPUs', String(det.cpus || '?')],
      ['Free disk', det.storage_free_gib ? det.storage_free_gib + ' GiB' : 'unknown'],
      ['Memory', det.memory_mib ? Math.round(det.memory_mib / 1024) + ' GiB' : 'unknown'],
      ['GPU', gpuText(det.gpus)]].forEach(function (r) {
      const dt = document.createElement('dt'); dt.textContent = r[0];
      const dd = document.createElement('dd'); dd.textContent = r[1];
      facts.append(dt, dd);
    });
  }
  function fill(d) {
    const det = d.detected || {}, draft = d.draft, cur = d.current;
    fillFacts(det);
    const src = draft || {};
    $('name').value = src.name || (cur && cur.name) || det.name || '';
    $('region').value = src.region || (cur && cur.region) || det.region || '';
    $('host').value = src.host || det.host || '';
    $('port').value = src.port || det.port || 9443;
    const freeGib = det.storage_free_gib || 100;
    $('sto-on').checked = draft ? draft.storage_gib > 0 : true;
    $('sto-gib').value = draft && draft.storage_gib ? draft.storage_gib : Math.max(1, Math.min(200, Math.floor(freeGib / 2)));
    $('rly-on').checked = !!(draft && draft.relay_gib > 0 && draft.relay !== false);
    $('vpn-on').checked = !!(draft && draft.vpn);
    $('vpn-consent').checked = !!(draft && draft.vpn_consent);
    $('vpn-ports').value = (draft && draft.vpn_ports) || 'web';
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
        ' Programs use WebGPU; the GPU runtime (Deno, about 40 MB) is downloaded and checked the first time.';
    }
    $('backup-block').hidden = !d.can_seal;
    $('backup-old').hidden = !!d.can_seal;
    $('backup-on').checked = !!d.can_seal && d.mode !== 'service';
    $('service-block').hidden = d.mode === 'service';
    machineGiB = det.memory_mib ? Math.round(det.memory_mib / 1024) : 0;
    $('reserve-gib').value = draft && draft.reserve_gib != null ? draft.reserve_gib : (det.class === 'server' ? 1 : 4);
    $('per-client').value = draft && draft.per_client ? draft.per_client : 2;
    $('sto-price').value = prices['STO-1']; $('rly-price').value = prices['RLY-1']; $('vpn-price').value = prices['VPN-1']; $('cmp-price').value = prices['CMP-1'];
    $('payout').value = (draft && draft.payout) || (cur && cur.payto && Object.values(cur.payto)[0]) || '';
    $('share-you').textContent = (100 - d.fee_bps / 100) + '%';
    $('share-fee').textContent = (d.fee_bps / 100) + '%';
    reachState(det, d.request);
  }

  $('reach-retest').addEventListener('click', function () { reach('retest'); });
  $('reach-out').addEventListener('click', function () { reach('outgoing'); });
  ['sto-on', 'rly-on', 'vpn-on', 'cmp-on', 'gpu-on', 'reserve-gib', 'backup-on'].forEach(function (id) { $(id).addEventListener('change', sync); });
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
      storage_gib: $('sto-on').checked ? num('sto-gib') : 0,
      relay_gib: ($('rly-on').checked || $('vpn-on').checked) ? num('rly-gib') : 0, relay: $('rly-on').checked,
      vpn: $('vpn-on').checked, vpn_consent: $('vpn-on').checked && $('vpn-consent').checked, vpn_ports: $('vpn-ports').value,
      compute: $('cmp-on').checked, cpus: Math.max(1, num('cmp-cpus')), memory_mib: Math.max(64, num('cmp-mem')),
      gpu: !$('gpu-block').hidden && $('gpu-on').checked, gpus: Math.max(1, num('gpu-count')),
      reserve_gib: Math.max(0, num('reserve-gib')), per_client: Math.min(64, Math.max(1, num('per-client'))),
      prices: { 'STO-1': $('sto-price').value.trim(), 'RLY-1': $('rly-price').value.trim(), 'CMP-1': $('cmp-price').value.trim(), 'VPN-1': $('vpn-price').value.trim(),
        'GPU-1': $('gpu-price').value.trim() },
      network: net ? net.caip2 : 'eip155:84532', payout: $('payout').value.trim()
    };
    if ($('vpn-on').checked && !$('vpn-consent').checked) { say('send-msg', 'VPN exit needs your consent (the box under VPN exit), or untick VPN exit.', true); return; }
    if (!$('terms-ok').checked) { say('send-msg', 'Read and agree to the provider terms first.', true); return; }
    const wantBackup = !$('backup-block').hidden && $('backup-on').checked;
    if (wantBackup) {
      if ($('pass1').value.length < 12) { say('send-msg', 'The backup passphrase needs at least 12 characters, or untick the key backup.', true); return; }
      if ($('pass1').value !== $('pass2').value) { say('send-msg', 'The two passphrases do not match.', true); return; }
    }
    offer.terms = cfg.terms.provider.sha256;
    offer.service = !$('service-block').hidden && $('service-on').checked;
    $('send').disabled = true;
    try {
      if (wantBackup) offer.backup = await sealTo(setup.detected.seal_key, $('pass1').value);
      say('send-msg', 'Checking the offer…');
      const r = await I.api('/api/setup', offer);
      say('send-msg', 'Confirm with your passkey…');
      const credential = await I.get(r.options);
      await I.api('/api/setup/confirm', { flow: r.flow, credential: credential });
      $('pass1').value = $('pass2').value = '';
      showProgress();
    } catch (err) { say('send-msg', I.friendly(err), true); }
    $('send').disabled = false;
  });

  // ---- live progress after Apply ----
  const MARK = { ok: '✓', warn: '!', fail: '✗', skip: '–', run: '…' };
  const LISTING = {
    testing: 'The registry is checking your machine. It is listed once the checks pass; this usually takes a few minutes.',
    listed: 'Listed. Clients can use your machine now.',
    paused: 'Paused: no new work, existing files are still served.',
    suspended: 'Suspended by the registry: ', leaving: 'Leaving: clients are moving their files away.',
    gone: 'Not heard from for a long time.', removed: 'Removed by the operator.'
  };
  let timer = null, started = 0;
  function showProgress() {
    $('form').hidden = true; $('waiting').hidden = true; $('progress').hidden = false;
    started = Date.now();
    pollProgress();
  }
  function row(st) {
    const li = document.createElement('li'); li.className = st.state;
    const mk = document.createElement('span'); mk.className = 'mk'; mk.textContent = MARK[st.state] || '·';
    const lb = document.createElement('span'); lb.className = 'lb'; lb.textContent = st.label;
    const tx = document.createElement('span'); tx.className = 'tx'; tx.textContent = st.text;
    li.append(mk, lb, tx); return li;
  }
  async function pollProgress() {
    clearTimeout(timer);
    let p = null;
    try { p = await I.api('/api/setup/progress'); } catch (err) { if (err.status !== 404) say('prog-listing', I.friendly(err), true); }
    let again = Date.now() - started < 30 * 60 * 1000;
    if (p) {
      const list = $('prog-steps'); list.textContent = '';
      if (!p.steps.length) list.append(row({ state: 'run', label: 'Machine', text: setup && !setup.can_seal
        ? 'Your machine runs an older provider: go to its terminal and confirm there. (Update it with: innernet-provider update)'
        : 'Your machine received the offer and is checking your passkey…' }));
      p.steps.forEach(function (st) { list.append(row(st)); });
      const failed = p.steps.some(function (st) { return st.state === 'fail'; });
      if (failed) {
        $('prog-title').textContent = 'Not applied';
        say('prog-listing', 'Nothing was changed. Fix the step marked ✗ and apply again.', true);
        $('form').hidden = false; again = false;
      } else if (p.listing) {
        const l = p.listing;
        $('prog-title').textContent = p.status === 'done' ? 'Applied' : 'Applying on your machine…';
        say('prog-listing', (LISTING[l.state] || l.state) + (l.state === 'suspended' && l.reason ? l.reason : '') +
          (l.services && l.services.length ? ' Offering: ' + l.services.join(', ') + '.' : ''));
        $('prog-done').hidden = p.status !== 'done';
        if (l.state === 'listed' && p.status === 'done') again = false;
      } else if (p.status === 'done') {
        $('prog-title').textContent = 'Applied';
        say('prog-listing', 'Waiting for the registry to receive the signed offer…');
        $('prog-done').hidden = false;
      }
    }
    if (again) timer = setTimeout(pollProgress, 2000);
  }

  function load() {
    return I.api('/api/setup').then(function (d) {
      setup = d;
      if (d.waiting_for_machine) {
        $('waiting').hidden = false; $('form').hidden = true;
        setTimeout(load, 2000);
        return;
      }
      $('waiting').hidden = true;
      if (d.status === 'submitted') { showProgress(); return; }
      fill(d);
      if (cfg.terms) $('terms-version').textContent = 'Version ' + cfg.terms.provider.version + '. Your machine signs this version into its listing.';
      $('form').hidden = false;
    });
  }

  fetch(I.BASE + '/v1/config').then(function (r) { return r.json(); }).then(function (c) {
    cfg = c;
    net = (cfg.networks || []).find(function (n) { return n.caip2 === 'eip155:84532'; }) || (cfg.networks || [])[0];
    return load();
  }).catch(function (err) {
    if (err.status === 401) { location.replace(I.BASE + '/claim'); return; }
    say('err', I.friendly(err), true); $('err').hidden = false;
  });
})();
