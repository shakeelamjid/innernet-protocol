'use strict';
// Browser-wallet helpers (EIP-1193). Transactions are signed in the user's wallet; no keys reach the server.
(function () {
  const SEL = { splitOf: '41890891', create: '9ed93318', preview: '13a69df9', release: '19165587' };
  const ZERO = '0x0000000000000000000000000000000000000000';
  function eth() { return window.ethereum; }
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
    const want = '0x' + chainId.toString(16);
    if (await eth().request({ method: 'eth_chainId' }) === want) return;
    try {
      await eth().request({ method: 'wallet_switchEthereumChain', params: [{ chainId: want }] });
    } catch (err) {
      if (err && err.code === 4902 && chainId === 84532) {
        await eth().request({ method: 'wallet_addEthereumChain', params: [{ chainId: want, chainName: 'Base Sepolia',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: ['https://sepolia.base.org'],
          blockExplorerUrls: ['https://sepolia.basescan.org'] }] });
      } else { throw err; }
    }
  }
  async function connect(chainId) {
    if (!eth()) throw new Error('No browser wallet found. Install MetaMask, Coinbase Wallet or Trust Wallet, then reload.');
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
  window.InnernetWallet = { SEL: SEL, connect: connect, ensureChain: ensureChain, splitOf: splitOf, findOrCreate: findOrCreate,
    waitReceipt: waitReceipt, call: call, pad: pad, friendly: friendly };
})();
