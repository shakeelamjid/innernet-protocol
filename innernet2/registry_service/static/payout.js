'use strict';
// Create or find a provider's INNERnet payout split with the user's own browser wallet.
// No keys ever reach the server: transactions are signed in the wallet.
(function () {
  const $ = function (id) { return document.getElementById(id); };
  const BASE = location.pathname.replace(/\/payout\/?$/, '');
  const SEL = { splitOf: '41890891', create: '9ed93318', preview: '13a69df9', release: '19165587', isSplit: '8b8f5031' };
  const ZERO = '0x0000000000000000000000000000000000000000';
  let cfg = null, net = null, account = null, split = null;

  function say(id, text, isError) { const el = $(id); el.textContent = text; el.classList.toggle('error', !!isError); }
  function pad(addr) { return '0'.repeat(24) + addr.slice(2).toLowerCase(); }
  function isAddr(a) { return /^0x[0-9a-fA-F]{40}$/.test(a); }
  function word(hex, i) { return '0x' + hex.slice(2 + 64 * i + 24, 2 + 64 * (i + 1)); }
  function num(hex, i) { return BigInt('0x' + hex.slice(2 + 64 * i, 2 + 64 * (i + 1))); }
  function usdc(units) { const s = units.toString().padStart(7, '0'); return s.slice(0, -6) + '.' + s.slice(-6, -4); }
  function eth() { return window.ethereum; }
  async function call(to, data) { return eth().request({ method: 'eth_call', params: [{ to: to, data: data }, 'latest'] }); }

  async function waitReceipt(hash) {
    for (let i = 0; i < 120; i++) {
      const r = await eth().request({ method: 'eth_getTransactionReceipt', params: [hash] });
      if (r) { if (r.status !== '0x1') throw new Error('The transaction failed on-chain.'); return r; }
      await new Promise(function (res) { setTimeout(res, 2000); });
    }
    throw new Error('Still waiting for the transaction. Check your wallet, then reload this page.');
  }

  async function ensureChain() {
    const want = '0x' + net.chain_id.toString(16);
    const have = await eth().request({ method: 'eth_chainId' });
    if (have === want) return;
    try {
      await eth().request({ method: 'wallet_switchEthereumChain', params: [{ chainId: want }] });
    } catch (err) {
      if (err && err.code === 4902 && net.chain_id === 84532) {
        await eth().request({ method: 'wallet_addEthereumChain', params: [{ chainId: want, chainName: 'Base Sepolia',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: ['https://sepolia.base.org'],
          blockExplorerUrls: ['https://sepolia.basescan.org'] }] });
      } else { throw err; }
    }
  }

  function friendly(err) {
    if (err && err.code === 4001) return 'You cancelled in the wallet.';
    return (err && (err.message || err.reason)) || 'Something went wrong. Try again.';
  }

  async function showSplit(addr) {
    split = addr;
    $('split-addr').textContent = addr;
    $('cmd').textContent = 'innernet-provider wallet set ' + addr;
    $('split-link').href = net.explorer_address + addr;
    $('step-done').hidden = false;
    $('step-release').hidden = false;
    await refreshPreview();
  }

  async function refreshPreview() {
    const out = await call(split, '0x' + SEL.preview + pad(net.usdc));
    const dl = $('preview');
    dl.replaceChildren();
    [['Waiting to be collected', usdc(num(out, 0) + num(out, 1)) + ' USDC'], ['Goes to you', usdc(num(out, 0)) + ' USDC'],
      ['Goes to the network', usdc(num(out, 1)) + ' USDC']].forEach(function (r) {
      const dt = document.createElement('dt'); dt.textContent = r[0];
      const dd = document.createElement('dd'); dd.textContent = r[1];
      dl.append(dt, dd);
    });
    $('release').disabled = num(out, 0) + num(out, 1) === 0n;
  }

  function copy(btn, textEl) {
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText($(textEl).textContent).then(function () {
        btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
      });
    });
  }
  copy($('copy-addr'), 'split-addr');
  copy($('copy-cmd'), 'cmd');

  $('connect').addEventListener('click', async function () {
    if (!eth()) { say('connect-msg', 'No browser wallet found. Install MetaMask, Coinbase Wallet or Trust Wallet, then reload.', true); return; }
    try {
      const accounts = await eth().request({ method: 'eth_requestAccounts' });
      account = accounts[0];
      await ensureChain();
      say('connect-msg', 'Connected: ' + account);
      const pre = new URLSearchParams(location.hash.slice(1)).get('receiver');
      $('receiver').value = pre && /^0x[0-9a-fA-F]{40}$/.test(pre) ? pre : account;
      $('step-create').hidden = !net.factory;
      $('operator').hidden = !(location.hash === '#operator' && !net.factory);
    } catch (err) { say('connect-msg', friendly(err), true); }
  });

  $('create').addEventListener('click', async function () {
    const receiver = $('receiver').value.trim();
    if (!isAddr(receiver)) { say('create-msg', 'Enter a wallet address: 0x followed by 40 characters.', true); return; }
    try {
      await ensureChain();
      let existing = word(await call(net.factory, '0x' + SEL.splitOf + pad(receiver)), 0);
      if (existing === ZERO) {
        say('create-msg', 'Confirm in your wallet…');
        const hash = await eth().request({ method: 'eth_sendTransaction', params: [{ from: account, to: net.factory, data: '0x' + SEL.create + pad(receiver) }] });
        say('create-msg', 'Creating your contract…');
        await waitReceipt(hash);
        existing = word(await call(net.factory, '0x' + SEL.splitOf + pad(receiver)), 0);
        say('create-msg', 'Created.');
      } else {
        say('create-msg', 'You already have a payout contract for this wallet.');
      }
      await showSplit(existing);
    } catch (err) { say('create-msg', friendly(err), true); }
  });

  $('release').addEventListener('click', async function () {
    try {
      await ensureChain();
      say('release-msg', 'Confirm in your wallet…');
      const hash = await eth().request({ method: 'eth_sendTransaction', params: [{ from: account, to: split, data: '0x' + SEL.release + pad(net.usdc) }] });
      say('release-msg', 'Sending…');
      await waitReceipt(hash);
      say('release-msg', 'Collected.');
      await refreshPreview();
    } catch (err) { say('release-msg', friendly(err), true); }
  });

  $('deploy-factory').addEventListener('click', async function () {
    try {
      await ensureChain();
      const art = await (await fetch(BASE + '/static/split-factory.json')).json();
      const args = pad(net.fee_wallet) + cfg.fee_bps.toString(16).padStart(64, '0');
      say('deploy-msg', 'Confirm in your wallet…');
      const hash = await eth().request({ method: 'eth_sendTransaction', params: [{ from: account, data: art.bytecode + args }] });
      say('deploy-msg', 'Deploying…');
      const r = await waitReceipt(hash);
      say('deploy-msg', 'Factory deployed at ' + r.contractAddress + '. In Coolify set INNERNET_SPLIT_FACTORY_BASE_SEPOLIA=' + r.contractAddress + ' on the registry and redeploy.');
    } catch (err) { say('deploy-msg', friendly(err), true); }
  });

  fetch(BASE + '/v1/config').then(function (r) { return r.json(); }).then(function (c) {
    cfg = c;
    net = (c.networks || []).find(function (n) { return n.caip2 === 'eip155:84532'; }) || (c.networks || [])[0];
    if (!net) { say('unavailable', 'Payouts are not open yet.', true); $('unavailable').hidden = false; $('step-connect').hidden = true; return; }
    $('share-provider').textContent = (100 - c.fee_bps / 100) + '%';
    $('share-fee').textContent = (c.fee_bps / 100) + '%';
    $('net-name').textContent = net.name;
    $('op-fee').textContent = net.fee_wallet;
    $('op-bps').textContent = c.fee_bps + ' bps';
    if (!net.factory) {
      $('unavailable').textContent = 'Payout contracts open as soon as the split factory is deployed on ' + net.name + '. Check back shortly.';
      $('unavailable').classList.remove('error');
      $('unavailable').hidden = false;
      if (location.hash !== '#operator') $('step-connect').hidden = true;
    }
  });
})();
