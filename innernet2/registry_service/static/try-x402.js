(function () {
  'use strict';
  const $ = function (id) { return document.getElementById(id); };
  const BASE = location.pathname.replace(/\/try-x402\/?$/, '');
  const ECHO_WASM = 'AGFzbQEAAAABDAJgBH9/f38Bf2AAAAJEAhZ3YXNpX3NuYXBzaG90X3ByZXZpZXcxB2ZkX3JlYWQAABZ3YXNpX3NuYXBzaG90X3ByZXZpZXcxCGZkX3dyaXRlAAADAgEBBQMBAAIHEwIGbWVtb3J5AgAGX3N0YXJ0AAIKSQFHAQF/AkADQEEAQYAINgIAQQRBgIAENgIAQQBBAEEBQRAQAA0BQRAoAgAhACAARQ0BQQQgADYCAEEBQQBBAUEUEAEaDAALCwsANQRuYW1lARQCAAdmZF9yZWFkAQhmZF93cml0ZQIGAQIBAAFuAxABAgIABGRvbmUBBWFnYWlu';
  let required = null;

  function say(t, bad) { $('msg').textContent = t; $('msg').classList.toggle('error', !!bad); }
  function job() {
    return { wasm: ECHO_WASM, input: btoa(unescape(encodeURIComponent($('input').value))), max_seconds: 10 };
  }
  function b64json(o) { return btoa(unescape(encodeURIComponent(JSON.stringify(o)))); }
  function usdc(units) { return (Number(units) / 1e6).toString(); }

  async function quote() {
    try {
      const r = await fetch(BASE + '/x402/cpu', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(job()) });
      if (r.status !== 402) { const e = await r.json().catch(function () { return {}; }); throw new Error(e.error || e.detail || ('status ' + r.status)); }
      required = JSON.parse(atob(r.headers.get('PAYMENT-REQUIRED')));
      const a = required.accepts[0];
      $('quote').textContent = 'Price: ' + usdc(a.amount) + ' USDC on Base, paid to the payout contract ' + a.payTo + ' (97.5% provider, 2.5% INNERNET).';
    } catch (err) { $('quote').textContent = 'Could not get a price: ' + err.message; $('quote').classList.add('error'); }
  }

  async function pay(phone) {
    const W = window.InnernetWallet;
    try {
      if (!required) await quote();
      const a = required.accepts[0];
      let account;
      if (phone) {
        const cfg = await (await fetch(BASE + '/v1/config')).json();
        const net = (cfg.networks || []).find(function (n) { return n.caip2 === a.network; });
        say('Preparing a QR code…');
        account = await W.connectPhone(BASE, cfg, net, function (uri, svg) {
          $('wc-qr').innerHTML = svg; $('wc-link').href = uri; $('wc-box').hidden = false;
          say('Scan with your wallet app and approve the connection.');
        });
        $('wc-box').hidden = true;
      } else {
        account = await W.connect(8453);
      }
      const now = Math.floor(Date.now() / 1000);
      const nonce = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      const auth = { from: account, to: a.payTo, value: a.amount, validAfter: '0', validBefore: String(now + a.maxTimeoutSeconds), nonce: nonce };
      const typed = {
        types: {
          EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
          TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
            { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }]
        },
        primaryType: 'TransferWithAuthorization',
        domain: { name: a.extra.name, version: a.extra.version, chainId: 8453, verifyingContract: a.asset },
        message: auth
      };
      say('Approve the signature in your wallet (' + usdc(a.amount) + ' USDC to ' + a.payTo + ')…');
      const signature = await W.request('eth_signTypedData_v4', [account, JSON.stringify(typed)]);
      const payment = { x402Version: 2, resource: required.resource, accepted: a, payload: { signature: signature, authorization: auth } };
      say('Paid. Running the job and collecting only if it runs…');
      const r = await fetch(BASE + '/x402/cpu', { method: 'POST', headers: { 'Content-Type': 'application/json', 'PAYMENT-SIGNATURE': b64json(payment) }, body: JSON.stringify(job()) });
      const body = await r.json().catch(function () { return {}; });
      if (r.status !== 200) {
        const why = body.error || (body.x402Version ? body.error : '') || ('status ' + r.status);
        required = null;
        throw new Error(why + (r.status === 402 ? '' : ' Nothing was charged.'));
      }
      let text;
      try { text = decodeURIComponent(escape(atob(body.output))); } catch (e) { text = body.output; }
      $('out').textContent = text;
      const facts = $('facts'); facts.textContent = '';
      [['Provider', body.provider.name + ' (' + body.provider.id.slice(0, 16) + '…)'], ['Time', body.seconds + ' s'],
       ['Paid', body.paid.usdc + ' USDC'], ['Transaction', body.paid.transaction], ['Paid to', body.paid.pay_to],
       ['Receipt', 'signed by the provider: ' + JSON.stringify(body.receipt.payload || body.receipt).slice(0, 160) + '…']].forEach(function (kv) {
        const dt = document.createElement('dt'); dt.textContent = kv[0];
        const dd = document.createElement('dd');
        if (kv[0] === 'Transaction') { const l = document.createElement('a'); l.href = 'https://basescan.org/tx/' + kv[1]; l.textContent = kv[1]; l.target = '_blank'; l.rel = 'noopener'; dd.append(l); }
        else dd.textContent = kv[1];
        facts.append(dt, dd);
      });
      $('result').hidden = false;
      say('Done.');
    } catch (err) { $('wc-box').hidden = true; say(W.friendly(err), true); }
  }

  document.addEventListener('DOMContentLoaded', function () {
    quote();
    $('input').addEventListener('change', quote);
    $('phone').addEventListener('click', function () { pay(true); });
    $('browser').addEventListener('click', function () { pay(false); });
  });
})();
