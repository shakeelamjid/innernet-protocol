/* INNERNET Send: a QR code for printing a link (byte mode, error correction M, versions 1-15, mask 0).
   No dependencies. qr(text) returns the square matrix; svg(text) returns an <svg> element. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.InnernetQR = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  // version: [error-correction codewords per block, [blocks, data codewords per block], ...]
  const V = [null, [10, [1, 16]], [16, [1, 28]], [26, [1, 44]], [18, [2, 32]], [24, [2, 43]], [16, [4, 27]], [18, [4, 31]],
    [22, [2, 38], [2, 39]], [22, [3, 36], [2, 37]], [26, [4, 43], [1, 44]], [30, [1, 50], [4, 51]], [22, [6, 36], [2, 37]],
    [22, [8, 37], [1, 38]], [24, [4, 40], [5, 41]], [24, [5, 41], [5, 42]]];
  const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
    [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70]];
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = EXP[i + 255] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; } })();
  function mul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }
  function ecc(data, n) {                                  // Reed-Solomon remainder
    let gen = [1];
    for (let i = 0; i < n; i++) { const next = new Array(gen.length + 1).fill(0); for (let j = 0; j < gen.length; j++) { next[j] ^= gen[j]; next[j + 1] ^= mul(gen[j], EXP[i]); } gen = next; }
    const rem = new Array(n).fill(0);
    for (let i = 0; i < data.length; i++) {
      const f = data[i] ^ rem.shift(); rem.push(0);
      for (let j = 0; j < n; j++) rem[j] ^= mul(gen[j + 1], f);
    }
    return rem;
  }
  function capacity(v) { let n = 0; for (let i = 1; i < V[v].length; i++) n += V[v][i][0] * V[v][i][1]; return n; }
  function qr(text) {
    const bytes = Array.prototype.slice.call(new TextEncoder().encode(text));
    let v = 1;
    while (v <= 15 && bytes.length + (v < 10 ? 2 : 3) > capacity(v)) v++;
    if (v > 15) throw new Error('too long for a QR code');
    const cap = capacity(v), bits = [];
    function put(val, len) { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); }
    put(4, 4); put(bytes.length, v < 10 ? 8 : 16); bytes.forEach(function (b) { put(b, 8); });
    put(0, Math.min(4, cap * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) { let b = 0; for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]; data.push(b); }
    for (let i = 0; data.length < cap; i++) data.push(i % 2 ? 0x11 : 0xec);
    const blocks = [], eccs = [];
    let at = 0;
    for (let g = 1; g < V[v].length; g++) for (let k = 0; k < V[v][g][0]; k++) { const d = data.slice(at, at + V[v][g][1]); at += d.length; blocks.push(d); eccs.push(ecc(d, V[v][0])); }
    const out = [];
    for (let i = 0; i < blocks[blocks.length - 1].length; i++) blocks.forEach(function (b) { if (i < b.length) out.push(b[i]); });
    for (let i = 0; i < V[v][0]; i++) eccs.forEach(function (e) { out.push(e[i]); });
    const n = 17 + 4 * v, m = [], fixed = [];
    for (let r = 0; r < n; r++) { m.push(new Array(n).fill(0)); fixed.push(new Array(n).fill(false)); }
    function set(r, c, val) { if (r >= 0 && r < n && c >= 0 && c < n) { m[r][c] = val ? 1 : 0; fixed[r][c] = true; } }
    function finder(r0, c0) { for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) set(r0 + r, c0 + c, r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))); }
    finder(0, 0); finder(0, n - 7); finder(n - 7, 0);
    ALIGN[v].forEach(function (r) { ALIGN[v].forEach(function (c) { if (fixed[r][c]) return; for (let y = -2; y <= 2; y++) for (let x = -2; x <= 2; x++) set(r + y, c + x, Math.max(Math.abs(x), Math.abs(y)) !== 1); }); });
    for (let i = 8; i < n - 8; i++) { if (!fixed[6][i]) set(6, i, i % 2 === 0); if (!fixed[i][6]) set(i, 6, i % 2 === 0); }
    set(n - 8, 8, 1);
    for (let i = 0; i < 9; i++) { if (!fixed[8][i]) set(8, i, 0); if (!fixed[i][8]) set(i, 8, 0); }      // format areas, filled below
    for (let i = 0; i < 8; i++) { if (!fixed[8][n - 1 - i]) set(8, n - 1 - i, 0); if (!fixed[n - 1 - i][8]) set(n - 1 - i, 8, 0); }
    if (v >= 7) {
      let rem = v; for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
      const info = (v << 12) | rem;
      for (let i = 0; i < 18; i++) { const bit = (info >> i) & 1, a = n - 11 + (i % 3), b = Math.floor(i / 3); set(a, b, bit); set(b, a, bit); }
    }
    let i = 0, up = true;
    for (let c = n - 1; c > 0; c -= 2) {
      if (c === 6) c--;
      for (let k = 0; k < n; k++) {
        const r = up ? n - 1 - k : k;
        for (let x = 0; x < 2; x++) {
          const cc = c - x;
          if (fixed[r][cc]) continue;
          const bit = i < out.length * 8 ? (out[i >> 3] >> (7 - (i & 7))) & 1 : 0; i++;
          m[r][cc] = bit ^ ((r + cc) % 2 === 0 ? 1 : 0);                 // mask 0
        }
      }
      up = !up;
    }
    let f = 0; let rem = f;                                             // format: level M (00), mask 0
    for (let k = 0; k < 10; k++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    const fmt = ((f << 10) | rem) ^ 0x5412;
    function fb(k) { return (fmt >> k) & 1; }
    for (let k = 0; k <= 5; k++) m[k][8] = fb(k);
    m[7][8] = fb(6); m[8][8] = fb(7); m[8][7] = fb(8);
    for (let k = 9; k < 15; k++) m[8][14 - k] = fb(k);
    for (let k = 0; k < 8; k++) m[8][n - 1 - k] = fb(k);
    for (let k = 8; k < 15; k++) m[n - 15 + k][8] = fb(k);
    return m;
  }
  function svg(text, px) {
    const m = qr(text), n = m.length, q = 4, ns = 'http://www.w3.org/2000/svg';
    const el = document.createElementNS(ns, 'svg');
    el.setAttribute('viewBox', '0 0 ' + (n + 2 * q) + ' ' + (n + 2 * q)); el.setAttribute('width', px || 220); el.setAttribute('height', px || 220);
    el.setAttribute('role', 'img'); el.setAttribute('aria-label', 'QR code of the link');
    const bg = document.createElementNS(ns, 'rect'); bg.setAttribute('width', '100%'); bg.setAttribute('height', '100%'); bg.setAttribute('fill', '#fff'); el.append(bg);
    let d = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (m[r][c]) d += 'M' + (c + q) + ' ' + (r + q) + 'h1v1h-1z';
    const p = document.createElementNS(ns, 'path'); p.setAttribute('d', d); p.setAttribute('fill', '#000'); el.append(p);
    return el;
  }
  return { qr: qr, svg: svg };
});
