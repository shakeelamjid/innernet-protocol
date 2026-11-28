/* INNERNET Send: the film. It shows what is really happening to this send, built from this send:
   the user's own content in its own form (the text itself, the picture itself cut into tiles, or a
   file's real first bytes), the real sealed bytes, the key pieces this send really has (a PIN, a key
   per named person, approver links, a sender key...), the rules the sender really chose, and where
   each piece really ends up. Steps appear only when the work behind them is done; each is held long
   enough to follow. It plays once.
   create(holder, spec) -> { plain(x), sealed(x), title(t), beat(name, caption, data), end(caption) } */
(function (root) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const PACE = { content: 1600, keys: 1400, split: 1800, filekey: 1600, rules: 2000, pay: 1700, deposit: 1500, cut: 1300,
    seal: 1900, store: 2200, start: 1400, combine: 1700, prove: 1400, check: 2100, release: 1500, rebuild: 1600, fetch: 1500,
    unseal: 2000, destroy: 2000, kept: 1500, progress: 0, shards: 1900, gather: 2000, end: 2400 };
  const N = 12, CW = 32, GAP = 4, TILE = 36, TGAP = 4;

  function el(tag, attrs, text) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (text != null) n.textContent = text;
    return n;
  }
  function at(node, x, y, s) { node.style.transform = 'translate(' + x + 'px,' + y + 'px)' + (s && s !== 1 ? ' scale(' + s + ')' : ''); }
  function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function cut(t, n) { t = String(t); return t.length > n ? t.slice(0, n - 1) + '…' : t; }

  /* The first characters of what is sent: text as text, anything else as hex. */
  function firstChars(bytes, isText) {
    const b = bytes.subarray(0, N);
    const printable = b.length > 0 && Array.prototype.every.call(b, function (x) { return x >= 32 && x < 127; });
    if (isText || printable) return { chars: Array.from(new TextDecoder().decode(bytes.subarray(0, 48)).replace(/\r?\n/g, '↵')).slice(0, N), hex: false };
    return { chars: Array.from(Array.prototype.map.call(bytes.subarray(0, N / 2), function (x) { return x.toString(16).padStart(2, '0'); }).join('').toUpperCase()), hex: true };
  }
  function sealedChars(bytes) {                // the real sealed bytes, written in base64
    return Array.from(btoa(String.fromCharCode.apply(null, bytes.subarray(0, 9))).replace(/\+/g, '-').replace(/\//g, '_')).slice(0, N);
  }
  /* A picture, cut into 12 tiles (4 x 3), centre-cropped. Null if it cannot be drawn here. */
  async function imageTiles(blob) {
    try {
      const bmp = await createImageBitmap(blob), W = 4 * TILE, H = 3 * TILE, r = Math.max(W / bmp.width, H / bmp.height);
      const whole = document.createElement('canvas'); whole.width = W; whole.height = H;
      whole.getContext('2d').drawImage(bmp, (W - bmp.width * r) / 2, (H - bmp.height * r) / 2, bmp.width * r, bmp.height * r);
      const out = [];
      for (let i = 0; i < N; i++) {
        const t = document.createElement('canvas'); t.width = t.height = TILE;
        t.getContext('2d').drawImage(whole, (i % 4) * TILE, Math.floor(i / 4) * TILE, TILE, TILE, 0, 0, TILE, TILE);
        out.push(t.toDataURL('image/png'));
      }
      return out;
    } catch (e) { return null; }
  }
  /* The real sealed bytes of the picture, drawn as grey pixels: 6 x 6 blocks per tile. */
  function noiseTiles(bytes) {
    const out = [];
    for (let i = 0; i < N; i++) {
      const t = document.createElement('canvas'); t.width = t.height = TILE;
      const g = t.getContext('2d');
      for (let k = 0; k < 36; k++) { const v = bytes[(i * 36 + k) % bytes.length]; g.fillStyle = 'rgb(' + v + ',' + v + ',' + v + ')'; g.fillRect((k % 6) * 6, Math.floor(k / 6) * 6, 6, 6); }
      out.push(t.toDataURL('image/png'));
    }
    return out;
  }
  function typeLabel(name, type) {
    if (/^image\//.test(type)) return 'picture';
    if (type === 'application/pdf') return 'PDF';
    if (/^text\//.test(type)) return 'text';
    const ext = (String(name).match(/\.([a-z0-9]{1,5})$/i) || [])[1];
    return ext ? ext.toUpperCase() : 'file';
  }

  function create(holder, spec) {
    const calm = root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const grid = spec.content.kind === 'image' || spec.content.reserve;
    const CY = 62, CH = grid ? 3 * TILE + 2 * TGAP : CW, TY = CY + CH + 44, RY = TY + 48, BY = RY + 48, BH = 106, H = BY + BH + 30;
    const wrap = document.createElement('div'); wrap.className = 'film';
    const svg = el('svg', { viewBox: '0 0 560 ' + H, role: 'img', 'aria-label': spec.label || 'What happens to this send' });
    const step = el('text', { 'class': 'dia-step', x: 20, y: 22 }, '');
    const title = el('text', { 'class': 'content-label', x: 280, y: CY - 12 }, spec.content.title || '');
    svg.append(step, title);
    const live = document.createElement('p'); live.className = 'sr'; live.setAttribute('aria-live', 'polite');

    // places, left to right; the keeper is always the last
    const places = {}, n = spec.places.length, bw = (520 - (n - 1) * 12) / n;
    spec.places.forEach(function (p, i) {
      const x = 20 + i * (bw + 12), g = el('g', { 'class': 'server' });
      g.append(el('path', { 'class': 'link', d: 'M280 ' + (RY + 26) + 'V' + (BY - 14) + 'H' + (x + bw / 2) + 'V' + BY }),
        el('rect', { 'class': 'node', x: x, y: BY, width: bw, height: BH }),
        el('path', { 'class': 'node-frame', d: 'M' + (x + 12) + ' ' + BY + 'H' + x + 'V' + (BY + BH) + 'H' + (x + 12) + 'M' + (x + bw - 12) + ' ' + BY + 'H' + (x + bw) + 'V' + (BY + 12) }),
        el('text', { 'class': 'node-label', x: x, y: BY + BH + 20 }, cut(n >= 5 && p.short ? p.short : p.label, Math.floor(bw / 7.4))));
      const st = el('text', { 'class': 'node-state', x: x + 8, y: BY + BH - 9 }, p.state || '');
      g.append(st); svg.append(g);
      places[p.id] = { x: x, g: g, link: g.querySelector('.link'), state: st, label: g.querySelector('.node-label'), keeper: i === n - 1, held: [] };
    });
    const keeper = places[spec.places[n - 1].id];

    // the content: 12 cells, each a character or a picture tile
    const cells = [], parts = [];
    for (let i = 0; i < N; i++) {
      const g = el('g', { 'class': 'cell' }), r = el('rect', { x: 0, y: 0, width: CW, height: CW }), t = el('text', { x: CW / 2, y: 22 }, ''), im = el('image', { x: 0, y: 0, width: TILE, height: TILE });
      im.style.display = 'none'; g.append(r, im, t); svg.append(g); cells.push({ g: g, r: r, t: t, im: im });
    }
    for (let c = 0; c < 3; c++) { const l = el('text', { 'class': 'chunk-no', x: 0, y: 0 }, ''); l.style.opacity = 0; svg.append(l); parts.push(l); }

    // key pieces and other tokens
    const toks = {};
    function token(id, label, cls, width) {
      const w = width || Math.min(150, Math.max(62, label.length * 6.7 + 16)), g = el('g', { 'class': 'tok' + (cls ? ' ' + cls : '') });
      const t = el('text', { x: w / 2, y: 17 }, label);
      g.append(el('rect', { x: 0, y: 0, width: w, height: 26 }), t); g.style.opacity = 0; svg.append(g);
      return (toks[id] = { id: id, g: g, t: t, w: w, place: null });
    }
    (spec.tokens || []).forEach(function (t) { token(t.id, t.label, t.cls); });
    token('k', spec.keyLabel || 'file key', 'key');

    // the rules, as written by the sender (or as checked by the keeper)
    const rules = [];
    (function () {
      let x = 20, line = 0, shown = 0;
      (spec.rules || []).forEach(function (txt, i) {
        const w = txt.length * 6.1 + 22;
        if (x + w > 540) { line++; x = 20; }
        if (line > 1) return;
        const g = el('g', { 'class': 'rule' }), t = el('text', { x: 0, y: 0 }, txt);
        g.append(t); g.style.opacity = 0; at(g, x, RY + line * 18); g.style.transitionDelay = (i * 120) + 'ms'; svg.append(g);
        rules.push({ g: g, t: t, txt: txt }); x += w; shown++;
      });
      if (shown < (spec.rules || []).length) {
        const g = el('g', { 'class': 'rule' }); g.append(el('text', { x: 0, y: 0 }, '+' + ((spec.rules || []).length - shown) + ' more'));
        g.style.opacity = 0; at(g, x, RY + Math.min(line, 1) * 18); svg.append(g); rules.push({ g: g, t: g.firstChild, txt: '' });
      }
    })();

    const skip = document.createElement('button'); skip.type = 'button'; skip.className = 'btn btn-sm film-skip'; skip.textContent = 'Skip';
    wrap.append(svg, skip, live);
    holder.textContent = ''; holder.append(wrap);

    let plain = { chars: [] }, sealed = { chars: [] }, nparts = 1, fast = calm, count = 0, playing = Promise.resolve(), ended = false;
    function say(text) { step.textContent = text || ''; live.textContent = text || ''; }
    function layoutGrid(tiles) { return tiles && tiles.length === N; }
    function lay(split) {                      // the content, in a row of characters or a grid of tiles
      const tiles = cells[0].im.style.display !== 'none';
      if (tiles) {
        const x0 = 280 - (4 * TILE + 3 * TGAP) / 2 - (split ? 6 : 0);
        cells.forEach(function (c, i) { at(c.g, x0 + (i % 4) * (TILE + TGAP) + (split ? (i % 4) * 4 : 0), CY + Math.floor(i / 4) * (TILE + TGAP)); c.g.style.opacity = 1; });
        parts.forEach(function (l) { l.style.opacity = 0; });
        return;
      }
      const groups = split ? Math.min(nparts, 3) : 1, per = Math.ceil(N / groups), width = N * CW + (N - 1) * GAP + (groups - 1) * 22, x0 = 280 - width / 2, y = CY + (CH - CW) / 2;
      cells.forEach(function (c, i) { at(c.g, x0 + i * (CW + GAP) + Math.floor(i / per) * 22, y); c.g.style.opacity = 1; });
      parts.forEach(function (l, gi) {
        const a = gi * per, b = Math.min(N, a + per) - 1;
        l.setAttribute('x', x0 + ((a + b) / 2) * (CW + GAP) + CW / 2 + gi * 22); l.setAttribute('y', y + CW + 16);
        l.textContent = nparts === 1 ? 'one part' : gi === 2 && nparts > 3 ? 'parts 3–' + nparts : 'part ' + (gi + 1);
        l.style.opacity = split && gi < groups ? 1 : 0;
      });
    }
    function paint(x, isSealed) {
      const tiles = layoutGrid(x.tiles);
      cells.forEach(function (c, i) {
        c.im.style.display = tiles ? '' : 'none'; c.r.style.display = tiles ? 'none' : ''; c.t.style.display = tiles ? 'none' : '';
        if (tiles) c.im.setAttribute('href', x.tiles[i]); else c.t.textContent = (x.chars || [])[i] || '';
        c.g.classList.toggle('sealed', !!isSealed); c.g.classList.toggle('empty', !tiles && !((x.chars || [])[i]));
      });
    }
    function intoKeeper() { cells.forEach(function (c, i) { at(c.g, keeper.x + 10 + (i % 6) * 19, BY + 8 + Math.floor(i / 6) * 18, 0.46); }); parts.forEach(function (l) { l.style.opacity = 0; }); }
    function spawnX(i, count) { return 280 - (count * 118 - 18) / 2 + i * 118; }
    function put(tok, where, opts) {           // where: 'spawn', 'mid', a place id, or [x, y]
      opts = opts || {};
      if (tok.place) { const h = places[tok.place].held; h.splice(h.indexOf(tok.id), 1); tok.place = null; }
      tok.g.classList.toggle('dim', !!opts.dim);
      if (where === 'mid') return at(tok.g, 280 - tok.w / 2, TY);
      if (Array.isArray(where)) return at(tok.g, where[0], where[1]);
      const p = places[where]; if (!p) { tok.g.style.opacity = 0; return; }
      tok.place = where; p.held.push(tok.id);
      const j = p.held.length - 1, top = p.keeper ? BY + 48 : BY + 10, s = Math.min(1, (bw - 12) / tok.w);
      if (j > 2) { tok.g.style.opacity = 0; p.state.textContent = '+' + (j - 2) + ' more'; return; }
      at(tok.g, p.x + (bw - tok.w * s) / 2, top + j * 30, s); tok.g.style.opacity = 1;
    }
    function pulse(ids) { Object.keys(places).forEach(function (k) { places[k].link.classList.toggle('live', ids.indexOf(k) >= 0); }); }
    function shown(id) { return toks[id] && toks[id].g.style.opacity !== '0' && toks[id].g.style.opacity !== ''; }

    let shardToks = [];
    function shardAt(t, i, place) {           // a shard's spot: in a row under the content, or in a box
      if (!place) return at(t.g, 280 - (Math.min(shardToks.length, 16) * 30) / 2 + (i % 16) * 30, CY + CH + 9 + Math.floor(i / 16) * 30, i >= 16 ? 0.001 : 1);
      const p = places[place], cols = Math.max(1, Math.floor((bw - 12) / 17));
      at(t.g, p.x + 8 + (i % cols) * 17, BY + 10 + Math.floor(i / cols) * 17, 0.55);
    }
    const ACT = {
      reset: function () {
        paint(spec.mode === 'open' ? { chars: [] } : plain, false); lay(false);
        (spec.tokens || []).forEach(function (t, i) {
          const tok = toks[t.id];
          if (t.at && places[t.at]) { put(tok, t.at); tok.g.style.opacity = 1; }
          else { at(tok.g, spawnX(t.slot != null ? t.slot : i, spec.spawnCount || 3), TY); tok.g.style.opacity = 0; }
        });
        at(toks.k.g, 280 - toks.k.w / 2, TY); toks.k.g.style.opacity = 0;
        if (spec.mode === 'open') keeper.state.textContent = 'sealed parts';
      },
      content: function () { paint(plain, false); lay(false); },
      keys: function () { (spec.tokens || []).forEach(function (t) { if (t.at === 'spawn') toks[t.id].g.style.opacity = 1; }); },
      split: function (d) {                    // one piece becomes one per person
        const src = toks[d.from], sx = parseFloat((src.g.style.transform.match(/translate\(([-\d.]+)px/) || [0, 280])[1]);
        d.into.forEach(function (id, i) {
          const t = toks[id], col = i % 4, row = Math.floor(i / 4);
          if (row > 1) return;
          at(t.g, 20 + col * 54, TY - 4 + row * 26, 0.8); t.g.style.opacity = 1;
        });
        src.g.style.opacity = 0;
      },
      filekey: function () {
        (spec.tokens || []).forEach(function (t) { if (t.at === 'spawn' && shown(t.id)) put(toks[t.id], 'mid', { dim: true }); });
        toks.k.g.style.opacity = 1; toks.k.g.classList.remove('dim');
      },
      rules: function () { rules.forEach(function (r) { r.g.style.opacity = 1; }); pulse([keeper === places[spec.places[n - 1].id] ? spec.places[n - 1].id : '']); },
      pay: function (d) {
        const coin = token('coin' + count, d.label, 'coin'), from = places[d.from || spec.places[0].id];
        at(coin.g, from.x + (bw - coin.w) / 2, BY + 12); coin.g.style.opacity = 1;
        setTimeout(function () { at(coin.g, 560, TY); coin.g.style.opacity = 0; }, fast ? 0 : 700);
      },
      deposit: function () { pulse([spec.places[n - 1].id]); if (toks.c) { put(toks.c, spec.places[n - 1].id); } keeper.state.textContent = rules.length ? 'your rules' : ''; },
      cut: function (d) { pulse([]); if (d && d.parts) nparts = d.parts; lay(true); keeper.state.textContent = nparts + (nparts === 1 ? ' part' : ' parts'); },
      seal: function () { paint(sealed, true); },
      progress: function (d) { keeper.state.textContent = d.text; },
      store: function () {
        pulse(Object.keys(places));
        if (shardToks.length) cells.forEach(function (c) { c.g.style.opacity = 0; }); else intoKeeper();
        rules.forEach(function (r) { r.g.style.transitionDelay = '0ms'; r.g.style.opacity = 0; });
        (spec.tokens || []).forEach(function (t) {
          if (t.id === 'c' || !t.to) return;
          const tok = toks[t.id];
          if (t.at === 'later') at(tok.g, 280 - tok.w / 2, TY);
          put(tok, t.to);
        });
        (spec.tokens || []).forEach(function (t) { if (!t.to && t.id !== 'c') toks[t.id].g.style.opacity = 0; });
        shardToks.forEach(function (t, i) { shardAt(t, i, spec.places[n - 1].id); });
        toks.k.g.style.opacity = 0;            // the file key is kept nowhere
        keeper.state.textContent = 'sealed, unreadable';
      },
      shards: function (d) {                   // the sealed file, coded into N shards
        shardToks.forEach(function (t) { t.g.remove(); });
        shardToks = [];
        for (let i = 0; i < d.n; i++) { const t = token('s' + i, String(i + 1), 'shard', 26); shardToks.push(t); }
        shardToks.forEach(function (t, i) { if (d.at) { shardAt(t, i, d.at); } else { t.g.style.transition = 'none'; at(t.g, 280 - 13, CY + CH / 2); svg.getBoundingClientRect(); t.g.style.transition = ''; shardAt(t, i, null); } t.g.style.opacity = 1; });
        if (!d.at) cells.forEach(function (c) { c.g.style.opacity = 0.25; });
      },
      gather: function (d) {                   // the shards that really answered come together
        const pick = (d.which || []).map(function (x) { return x - 1; });
        shardToks.forEach(function (t, i) { if (pick.indexOf(i) >= 0) { at(t.g, 280 - (pick.length * 30) / 2 + pick.indexOf(i) * 30, TY + 30); t.g.classList.remove('dim'); } else t.g.classList.add('dim'); });
      },
      start: function () { pulse([]); },
      combine: function (d) {                  // the holders' keys rebuild the link secret
        (d.from || []).forEach(function (id) { put(toks[id], 'mid', { dim: true }); });
        setTimeout(function () { (d.from || []).forEach(function (id) { toks[id].g.style.opacity = 0; }); put(toks[d.to], d.place); toks[d.to].g.style.opacity = 1; }, fast ? 0 : 800);
      },
      prove: function () { pulse(Object.keys(places)); },
      check: function () { pulse([spec.places[n - 1].id]); rules.forEach(function (r) { r.g.style.opacity = 1; }); keeper.state.textContent = 'checking'; },
      release: function () { pulse([spec.places[n - 1].id]); if (toks.c) { put(toks.c, [spawnX(2, 3), TY]); toks.c.g.style.opacity = 1; } keeper.state.textContent = 'released'; },
      rebuild: function () {
        pulse([]); rules.forEach(function (r) { r.g.style.transitionDelay = '0ms'; r.g.style.opacity = 0; });
        ['a', 'b', 'c'].forEach(function (id) { if (toks[id] && shown(id)) put(toks[id], 'mid', { dim: true }); });
        toks.k.g.style.opacity = 1;
      },
      fetch: function () {
        pulse([spec.places[n - 1].id]);
        if (shardToks.length) shardToks.forEach(function (t) { t.g.style.opacity = 0; });
        cells.forEach(function (c, i) { c.g.style.transition = 'none'; at(c.g, keeper.x + 10 + (i % 6) * 19, BY + 8 + Math.floor(i / 6) * 18, 0.46); });
        paint(sealed, true); svg.getBoundingClientRect();
        cells.forEach(function (c) { c.g.style.transition = ''; }); lay(false);
        keeper.state.textContent = nparts + (nparts === 1 ? ' part sent' : ' parts sent');
      },
      unseal: function () { pulse([]); shardToks.forEach(function (t) { t.g.style.opacity = 0; }); paint(plain, false); lay(false); ['a', 'b', 'c', 'k'].forEach(function (id) { if (toks[id]) { toks[id].g.classList.remove('dim'); toks[id].g.style.opacity = 0; } }); },
      destroy: function () { keeper.g.classList.add('down'); keeper.state.textContent = 'destroyed'; },
      kept: function (d) { keeper.state.textContent = d && d.left ? d.left + ' left' : 'kept'; },
      end: function () { pulse([]); }
    };

    function play(item) {
      return new Promise(function (resolve) {
        (ACT[item.name] || function () {})(item.data);
        if (item.caption != null) say(item.name === 'end' || item.name === 'progress' ? item.caption : (++count) + '. ' + item.caption);
        const ms = fast || document.hidden ? 0 : (PACE[item.name] != null ? PACE[item.name] : 1500);
        if (!ms) return resolve();
        setTimeout(resolve, ms);
      });
    }
    if (calm) svg.classList.add('fast');
    ACT.reset();
    skip.addEventListener('click', function () { fast = true; svg.classList.add('fast'); skip.hidden = true; });
    return {
      el: wrap,
      plain: function (x) { plain = x; if (!count && spec.mode !== 'open') ACT.reset(); },
      sealed: function (x) { sealed = x; },
      title: function (t) { title.textContent = t; },
      parts: function (p) { nparts = p; },
      beat: function (name, caption, data) { const it = { name: name, caption: caption, data: data }; playing = playing.then(function () { return play(it); }); return playing; },
      end: function (caption) {
        if (ended) return playing;
        ended = true;
        const it = { name: 'end', caption: caption };
        playing = playing.then(function () { return play(it); }).then(function () { skip.remove(); });
        return playing;
      }
    };
  }

  root.InnernetFilm = { create: create, firstChars: firstChars, sealedChars: sealedChars, imageTiles: imageTiles, noiseTiles: noiseTiles, typeLabel: typeLabel };
})(typeof self !== 'undefined' ? self : this);
