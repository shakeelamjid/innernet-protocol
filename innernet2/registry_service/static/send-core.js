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
  const STRONG = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';   // 32 signs, none that look alike (no 0/O, 1/I/L)
  function newPin(strong) {                 // 6 digits; or, strong, 10 signs from STRONG (50 bits), each uniformly random
    if (strong) { let s = ''; random(10).forEach(function (b) { s += STRONG[b & 31]; }); return s; }
    const a = random(12); let s = '';
    for (let i = 0; i < a.length && s.length < 6; i++) if (a[i] < 250) s += String(a[i] % 10);
    return s.length === 6 ? s : newPin();
  }
  function showPin(p) { p = String(p); return p.length === 10 ? p.slice(0, 5) + '-' + p.slice(5) : p; }
  function readPin(text) {                  // what the receiver typed: 6 digits, or 10 signs with any dashes or spaces
    const a = String(text).toUpperCase().replace(/[^0-9A-Z]/g, '');
    return a.length === 10 ? a : String(text).replace(/\D/g, '');
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

  async function verifyRequest(pubRaw, action, id, ts, sig) {
    try {
      const key = await S.importKey('raw', unb64u(pubRaw), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await S.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unb64u(sig), enc.encode(DOMAIN + '/' + action + '\n' + id + '\n' + ts));
    } catch (e) { return false; }
  }
  /* Formatted text without HTML: "# heading", "- item", "**bold**", "*italic*", bare links, "---".
     It is turned into page elements one by one, so nothing a sender writes can become markup or script. */
  function rich(text, doc) {
    const root = doc.createElement('div'); let list = null;
    function inline(parent, line) {
      line.split(/(\*\*[^*]+\*\*|\*[^*]+\*|https:\/\/[^\s<>"]+)/).forEach(function (bit) {
        if (!bit) return;
        let n;
        if (/^\*\*[^*]+\*\*$/.test(bit)) { n = doc.createElement('strong'); n.textContent = bit.slice(2, -2); }
        else if (/^\*[^*]+\*$/.test(bit)) { n = doc.createElement('em'); n.textContent = bit.slice(1, -1); }
        else if (/^https:\/\//.test(bit)) { n = doc.createElement('a'); n.textContent = bit; n.href = bit; n.rel = 'noopener noreferrer'; n.target = '_blank'; }
        else n = doc.createTextNode(bit);
        parent.appendChild(n);
      });
    }
    String(text).split(/\r?\n/).forEach(function (line) {
      const h = line.match(/^(#{1,3})\s+(.*)$/), li = line.match(/^[-*]\s+(.*)$/);
      if (li) { if (!list) { list = doc.createElement('ul'); root.appendChild(list); } const it = doc.createElement('li'); inline(it, li[1]); list.appendChild(it); return; }
      list = null;
      if (h) { const e = doc.createElement('h' + (h[1].length + 2)); inline(e, h[2]); root.appendChild(e); }
      else if (/^-{3,}$/.test(line.trim())) root.appendChild(doc.createElement('hr'));
      else if (line.trim()) { const e = doc.createElement('p'); inline(e, line); root.appendChild(e); }
    });
    return root;
  }

  /* Split custody (Shamir, GF(2^8)): a secret cut into n parts, any k of which rebuild it; fewer than k
     reveal nothing. Done here, on the sender's device; no server ever sees a part. */
  const EXP = new Uint8Array(510), LOG = new Uint8Array(256);
  (function () { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = EXP[i + 255] = x; LOG[x] = i; x ^= (x << 1) ^ (x & 0x80 ? 0x11b : 0); x &= 0xff; } })();
  function mul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }
  function div(a, b) { return a ? EXP[LOG[a] + 255 - LOG[b]] : 0; }
  function split(secret, n, k) {
    if (!(k >= 2 && n >= k && n <= 255)) throw new Error('split: 2 <= k <= n <= 255');
    const shares = []; for (let i = 1; i <= n; i++) shares.push({ x: i, y: new Uint8Array(secret.length) });
    for (let b = 0; b < secret.length; b++) {
      const c = random(k - 1);                               // the polynomial's random coefficients
      for (let i = 0; i < n; i++) { let y = 0; for (let j = k - 2; j >= 0; j--) y = mul(y, shares[i].x) ^ c[j]; shares[i].y[b] = mul(y, shares[i].x) ^ secret[b]; }
    }
    return shares.map(function (sh) { return 'k' + k + '.' + sh.x + '.' + b64u(sh.y); });
  }
  function parsePart(text) {
    const m = String(text).trim().match(/(?:#|^)k(\d+)\.(\d+)\.([A-Za-z0-9_-]+)$/);
    return m ? { k: Number(m[1]), x: Number(m[2]), y: unb64u(m[3]) } : null;
  }
  function combine(parts) {
    const len = parts[0].y.length, out = new Uint8Array(len);
    for (let b = 0; b < len; b++) {
      let v = 0;
      for (let i = 0; i < parts.length; i++) {
        let num = 1, den = 1;
        for (let j = 0; j < parts.length; j++) if (j !== i) { num = mul(num, parts[j].x); den = mul(den, parts[i].x ^ parts[j].x); }
        v ^= mul(parts[i].y[b], div(num, den));
      }
      out[b] = v;
    }
    return out;
  }

  /* With split custody the holders' keys replace the PIN: the PIN the key schedule needs is made from the secret. */
  async function jointPin(secret) {
    const d = new Uint8Array(await S.digest('SHA-256', concat(enc.encode(DOMAIN + '/joint-pin'), secret)));
    return String(((d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]) >>> 0) % 1000000).padStart(6, '0');
  }
  function jointLink(k, names, room) { return 'j' + b64u(enc.encode(JSON.stringify({ k: k, names: names, r: b64u(room) }))); }
  /* The opening room. Everyone with the link holds the room secret; the keeper does not. A holder's key is
     sent to the keeper sealed under the room secret (key XOR a pad made for that seat). The keeper knows
     the hash of each sealed key from the start, so it can check a key is the right person's without being
     able to read it, and it hands the sealed keys out only when enough are in. */
  async function room(roomSecret, id) {
    const salt = unhex(id), auth = await hkdf(roomSecret, salt, 'room-auth', 32);
    return { auth: b64u(auth), authHash: hex(await S.digest('SHA-256', auth)),
      seal: async function (part) { const pad = await hkdf(roomSecret, salt, 'room-seat-' + part.x, part.y.length), out = new Uint8Array(pad.length); for (let i = 0; i < pad.length; i++) out[i] = pad[i] ^ part.y[i]; return out; },
      open: async function (x, k, sealed) { const pad = await hkdf(roomSecret, salt, 'room-seat-' + x, sealed.length), y = new Uint8Array(pad.length); for (let i = 0; i < pad.length; i++) y[i] = pad[i] ^ sealed[i]; return { k: k, x: x, y: y }; } };
  }
  async function sha256hex(bytes) { return hex(await S.digest('SHA-256', bytes)); }
  function parseJoint(hash) {
    const m = String(hash).match(/^#?j([A-Za-z0-9_-]+)$/);
    if (!m) return null;
    try { const o = JSON.parse(dec.decode(unb64u(m[1]))); if (!(o && o.k >= 2 && Array.isArray(o.names) && o.names.length >= o.k && o.r)) return null; o.room = unb64u(o.r); return o; } catch (e) { return null; }
  }

  /* Named recipients: the content is sealed once with a random content key; each recipient's own PIN
     opens a wrapped copy of that key. */
  async function wrapKey(pinKey, id, raw) { return sealSmall(pinKey, id, 'wrap', { k: b64u(raw) }); }
  async function unwrapKey(pinKey, id, wrapped) { return aes(unb64u((await openSmall(pinKey, id, 'wrap', wrapped)).k)); }
  async function subKey(secret, id, label) { return aes(await hkdf(secret, unhex(id), label, 32)); }
  /* Contributions by others. sealWith: under a key everyone with the link has. sealTo: to the sender's
     public key (ECDH P-256 with a fresh key, then AES-256-GCM), so only the sender can read it. */
  async function sealWith(key, id, bytes) {
    const iv = random(12);
    return concat(iv, new Uint8Array(await S.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad(id, 'add', 0, true) }, key, bytes)));
  }
  async function openWith(key, id, blob) {
    return new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, 12), additionalData: aad(id, 'add', 0, true) }, key, blob.subarray(12)));
  }
  async function newBoxKey(extractable) { return S.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, !!extractable, ['deriveBits']); }
  async function boxKey(mine, theirRaw, id) {
    const pub = await S.importKey('raw', theirRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return aes(await hkdf(new Uint8Array(await S.deriveBits({ name: 'ECDH', public: pub }, mine, 256)), unhex(id), 'box', 32));
  }
  async function sealTo(pubRaw, id, bytes) {
    const eph = await newBoxKey(true), ephPub = new Uint8Array(await S.exportKey('raw', eph.publicKey));
    return concat(ephPub, await sealWith(await boxKey(eph.privateKey, pubRaw, id), id, bytes));
  }
  async function openFrom(pair, id, blob) { return openWith(await boxKey(pair.privateKey, blob.subarray(0, 65), id), id, blob.subarray(65)); }
  /* One contribution: the answers (JSON) and at most one attached file, in one byte string. */
  function pack(obj, fileBytes) {
    const head = enc.encode(JSON.stringify(obj)), out = new Uint8Array(4 + head.length + (fileBytes ? fileBytes.length : 0));
    new DataView(out.buffer).setUint32(0, head.length); out.set(head, 4); if (fileBytes) out.set(fileBytes, 4 + head.length);
    return out;
  }
  function unpack(bytes) {
    const n = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
    return { obj: JSON.parse(dec.decode(bytes.subarray(4, 4 + n))), file: bytes.subarray(4 + n) };
  }

  return { verifyRequest: verifyRequest, rich: rich, aesKey: aes, wrapKey: wrapKey, unwrapKey: unwrapKey, subKey: subKey, sealWith: sealWith, openWith: openWith, newBoxKey: newBoxKey,
    sealTo: sealTo, openFrom: openFrom, pack: pack, unpack: unpack, concat: concat,
    room: room, sha256hex: sha256hex, jointPin: jointPin, jointLink: jointLink, parseJoint: parseJoint, split: split, combine: combine, parsePart: parsePart, PART: PART, TAG: TAG, b64u: b64u, unb64u: unb64u, hex: hex, random: random, newPin: newPin, showPin: showPin, readPin: readPin, linkKeys: linkKeys, pinTag: pinTag,
    fileKey: fileKey, sealSmall: sealSmall, openSmall: openSmall, partCount: partCount, sealPart: sealPart, openPart: openPart,
    newDeviceKey: newDeviceKey, publicRaw: publicRaw, signRequest: signRequest, newId: function () { return hex(random(16)); } };
});
