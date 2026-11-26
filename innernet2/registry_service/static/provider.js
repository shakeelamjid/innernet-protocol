'use strict';
(function () {
  const pid = location.pathname.split('/').pop().toLowerCase();
  const base = location.pathname.replace(/\/providers\/[^/]*$/, '');
  const $ = function (id) { return document.getElementById(id); };
  const LABELS = { 'STO-1': 'Storage', 'RLY-1': 'Relay', 'VPN-1': 'VPN exit', 'CMP-1': 'CPU', 'GPU-1': 'GPU' };

  function row(dl, key, value) {
    const dt = document.createElement('dt'); dt.textContent = key;
    const dd = document.createElement('dd'); dd.textContent = value;
    dl.append(dt, dd);
  }

  Promise.all([
    fetch(base + '/v1/providers/' + encodeURIComponent(pid)).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }),
    fetch(base + '/v1/providers/' + encodeURIComponent(pid) + '/status').then(function (r) { return r.json(); })
  ]).then(function (res) {
    const p = res[0], s = res[1], e = p.entry;
    document.title = e.name + ' · INNERNET provider';
    $('name').textContent = e.name;
    $('pid').textContent = e.id;
    $('state').textContent = p.state;
    $('state').className = 'state ' + p.state;
    const offer = $('offer');
    e.services.forEach(function (svc) {
      const pr = e.prices[svc];
      row(offer, LABELS[svc] || svc, (svc === 'GPU-1' && e.hardware ? e.hardware.gpu_model + (e.hardware.gpu_vram_mib ? ' (' + Math.round(e.hardware.gpu_vram_mib / 1024) + ' GiB)' : '') + ', ' : '') + pr.amount + ' ' + pr.asset + ' per ' + pr.unit);
    });
    row(offer, 'Region', e.region);
    row(offer, 'Payment', Object.keys(p.networks).map(function (n) { return p.networks[n]; }).join(', '));
    const st = $('status');
    row(st, 'Reachable, 7 days', s.health.uptime_7d);
    row(st, 'Paid by clients, 30 days', s.earnings.gross_30d + ' USDC');
    if (s.reason) row(st, 'Note', s.reason);
    $('body').hidden = false;
  }).catch(function () {
    $('err').textContent = 'No provider with this id.';
    $('err').hidden = false;
  });
})();
