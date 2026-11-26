'use strict';
// Browser-wallet helpers (EIP-1193). Transactions are signed in the user's wallet; no keys reach the server.
(function () {
  const SEL = { splitOf: '41890891', create: '9ed93318', preview: '13a69df9', release: '19165587' };
  const ZERO = '0x0000000000000000000000000000000000000000';
  let prov = null;                       // a phone wallet over WalletConnect, when the owner chose that
  function eth() { return prov || window.ethereum; }
  function pad(addr) { return '0'.repeat(24) + addr.slice(2).toLowerCase(); }
  function word(hex, i) { return '0x' + hex.slice(2 + 64 * i + 24, 2 + 64 * (i + 1)); }
  async function call(to, data) { return eth().request({ method: 'eth_call', params: [{ to: to, data: data }, 'latest'] }); }
  async function waitReceipt(hash) {
    for (let i = 0; i < 120; i++) {
      const r = await eth().request({ method: 'eth_getTransactionReceipt', params: [hash] });
      if (r) { if (r.status !== '0x1') throw new Error('The transaction failed on-chain.'); return r; }
      await new Promise(function (res) { setTimeout(res, 2000); });
    }
    throw new Error('Still waiting for the transaction. Check your wallet, then try again.');
  }
  async function ensureChain(chainId) {
    if (prov) return;                    // the phone wallet was paired for this network
    const want = '0x' + chainId.toString(16);
    if (await eth().request({ method: 'eth_chainId' }) === want) return;
    try {
      await eth().request({ method: 'wallet_switchEthereumChain', params: [{ chainId: want }] });
    } catch (err) {
      if (err && err.code === 4902 && (chainId === 84532 || chainId === 8453)) {
        const main = chainId === 8453;
        await eth().request({ method: 'wallet_addEthereumChain', params: [{ chainId: want, chainName: main ? 'Base' : 'Base Sepolia',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: [main ? 'https://mainnet.base.org' : 'https://sepolia.base.org'],
          blockExplorerUrls: [main ? 'https://basescan.org' : 'https://sepolia.basescan.org'] }] });
      } else { throw err; }
    }
  }
  function loadWC(base) {
    if (window.InnernetWC) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      const s = document.createElement('script');
      s.src = base + '/static/walletconnect.js';
      s.onload = resolve;
      s.onerror = function () { reject(new Error('Could not load the phone wallet module. Reload and try again.')); };
      document.head.append(s);
    });
  }
  // Pair a phone wallet app by QR code (or a link on phones). onUri(uri, svg) shows the code.
  async function connectPhone(base, cfg, net, onUri) {
    if (!cfg.walletconnect) throw new Error('Phone wallets are not switched on yet. Use a browser wallet for now.');
    await loadWC(base);
    const rpcMap = {};
    rpcMap[net.chain_id] = (cfg.rpc || {})[net.caip2] || (net.chain_id === 8453 ? 'https://mainnet.base.org' : 'https://sepolia.base.org');
    prov = await window.InnernetWC.connect({ projectId: cfg.walletconnect.project_id, chainId: net.chain_id, rpcMap: rpcMap, onUri: onUri });
    return (await prov.request({ method: 'eth_accounts' }))[0];
  }
  async function connect(chainId) {
    prov = null;
    if (!eth()) throw new Error('No browser wallet here. Use the wallet app on your phone instead, or install MetaMask, Rabby or Trust Wallet in this browser and reload.');
    const accounts = await eth().request({ method: 'eth_requestAccounts' });
    await ensureChain(chainId);
    return accounts[0];
  }
  async function splitOf(factory, receiver) {
    const a = word(await call(factory, '0x' + SEL.splitOf + pad(receiver)), 0);
    return a === ZERO ? null : a;
  }
  async function findOrCreate(factory, account, receiver, onStatus) {
    let split = await splitOf(factory, receiver);
    if (split) return split;
    onStatus('Confirm in your wallet…');
    const hash = await eth().request({ method: 'eth_sendTransaction', params: [{ from: account, to: factory, data: '0x' + SEL.create + pad(receiver) }] });
    onStatus('Creating your payout contract…');
    await waitReceipt(hash);
    split = await splitOf(factory, receiver);
    if (!split) throw new Error('The contract was not found after creation. Reload and try again.');
    return split;
  }
  function friendly(err) {
    if (err && err.code === 4001) return 'You cancelled in the wallet.';
    return (err && (err.message || err.reason)) || 'Something went wrong. Try again.';
  }
  window.InnernetWallet = { SEL: SEL, connect: connect, connectPhone: connectPhone, ensureChain: ensureChain, splitOf: splitOf, findOrCreate: findOrCreate,
    waitReceipt: waitReceipt, call: call, pad: pad, friendly: friendly };
})();
