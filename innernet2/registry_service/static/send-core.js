/* INNERNET Send (SEND-1): sealing in the browser. No dependencies; WebCrypto only.
   The same file runs in Node for the tests (module.exports) and in the page (window.InnernetSend).

   file key = HKDF( link secret || keeper share || PBKDF2(PIN) )
   - link secret  32 random bytes, kept in the link's #fragment (never sent to a server)
   - keeper share 32 random bytes, deposited with the keeper, released only while the rules allow
   - PIN          told to the receiver by another channel
   The file is cut into 4 MiB parts, each sealed with AES-256-GCM; the part number and a last-part
   flag are bound into each part, so parts cannot be reordered, dropped or cut short unnoticed. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(globalThis.crypto);
  else root.InnernetSend = factory(root.crypto);
})(typeof self !== 'undefined' ? self : this, function (crypto) {
  'use strict';
  const S = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
  const DOMAIN = 'INNERNET/SEND-1', PART = 4 << 20, TAG = 16;

  function b64u(buf) {
    const a = new Uint8Array(buf); let s = '';
    for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(t) {
    const s = atob(String(t).replace(/-/g, '+').replace(/_/g, '/')); const a = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
  function unhex(t) { const a = new Uint8Array(t.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(t.substr(2 * i, 2), 16); return a; }
  function concat() {
    let n = 0; for (let i = 0; i < arguments.length; i++) n += arguments[i].length;
    const out = new Uint8Array(n); let o = 0;
    for (let i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; }
    return out;
  }
  function random(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function newPin() {                       // 6 digits, each uniformly random
    const a = random(12); let s = '';
    for (let i = 0; i < a.length && s.length < 6; i++) if (a[i] < 250) s += String(a[i] % 10);
    return s.length === 6 ? s : newPin();
  }

  async function hkdf(ikm, salt, info, bytes) {
    const k = await S.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await S.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode(DOMAIN + '/' + info) }, k, bytes * 8));
  }
  async function aes(raw) { return S.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); }

  /* Everything that can be made from the link secret alone (so a receiver can ask about a file and
     read the sender's note before entering the PIN). */
  async function linkKeys(secret, id) {
    const salt = unhex(id);
    const auth = await hkdf(secret, salt, 'auth', 32);
    const pinKey = await S.importKey('raw', await hkdf(secret, salt, 'pin', 32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return { auth: auth, authHash: hex(await S.digest('SHA-256', auth)), pinKey: pinKey, preview: await aes(await hkdf(secret, salt, 'preview', 32)) };
  }
  async function pinTag(keys, pin) { return hex(await S.sign('HMAC', keys.pinKey, enc.encode(String(pin)))); }

  async function fileKey(secret, share, pin, id) {
    const salt = unhex(id);
    const p = await S.importKey('raw', enc.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
    const stretched = new Uint8Array(await S.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: concat(enc.encode(DOMAIN + '/pin'), salt), iterations: 200000 }, p, 256));
    return aes(await hkdf(concat(secret, share, stretched), salt, 'file', 32));
  }

  function nonce(n) { const iv = new Uint8Array(12); new DataView(iv.buffer).setUint32(8, n); return iv; }
  function aad(id, kind, n, last) { return enc.encode(DOMAIN + '/' + kind + '/' + id + '/' + n + '/' + (last ? 1 : 0)); }

  async function sealSmall(key, id, kind, obj) {       // a small JSON object, sealed with a random nonce
    const iv = random(12);
    return b64u(concat(iv, new Uint8Array(await S.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad(id, kind, 0, true) }, key, enc.encode(JSON.stringify(obj))))));
  }
  async function openSmall(key, id, kind, text) {
    const raw = unb64u(text);
    return JSON.parse(dec.decode(await S.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12), additionalData: aad(id, kind, 0, true) }, key, raw.subarray(12))));
  }
  function partCount(size) { return Math.max(1, Math.ceil(size / PART)); }
  async function sealPart(key, id, n, parts, bytes) {
    return new Uint8Array(await S.encrypt({ name: 'AES-GCM', iv: nonce(n), additionalData: aad(id, 'part', n, n === parts - 1) }, key, bytes));
  }
  async function openPart(key, id, n, parts, bytes) {
    return new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: nonce(n), additionalData: aad(id, 'part', n, n === parts - 1) }, key, bytes));
  }

  /* Device keys (ECDSA P-256). In the page they are made non-extractable and kept in IndexedDB. */
  async function newDeviceKey(extractable) { return S.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, !!extractable, ['sign', 'verify']); }
  async function publicRaw(pair) { return b64u(await S.exportKey('raw', pair.publicKey)); }
  async function signRequest(pair, action, id) {
    const ts = Math.floor(Date.now() / 1000);
    const sig = await S.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, enc.encode(DOMAIN + '/' + action + '\n' + id + '\n' + ts));
    return { ts: ts, sig: b64u(sig) };
  }

  return { PART: PART, TAG: TAG, b64u: b64u, unb64u: unb64u, hex: hex, random: random, newPin: newPin, linkKeys: linkKeys, pinTag: pinTag,
    fileKey: fileKey, sealSmall: sealSmall, openSmall: openSmall, partCount: partCount, sealPart: sealPart, openPart: openPart,
    newDeviceKey: newDeviceKey, publicRaw: publicRaw, signRequest: signRequest, newId: function () { return hex(random(16)); } };
});
