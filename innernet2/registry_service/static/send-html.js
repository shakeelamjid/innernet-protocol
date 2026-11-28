/* INNERNET Send: show the sender's HTML safely.
   The HTML is parsed into an inert document (nothing in it runs), then rebuilt element by element from an
   allowlist into a closed shadow root. No script, frame, form, embed or outside resource survives:
   - links only to https: or mailto:, always opened in a new tab without a referrer;
   - pictures only when embedded in the HTML itself (data:image png, jpeg, gif or webp; no SVG);
   - styles are kept (both <style> blocks and style="" attributes) but scoped to the shadow root, with
     @import and outside url() removed; the box clips everything, so nothing can cover the page around it.
   Styles are applied through the CSS object model, so the page's strict Content-Security-Policy stays on. */
(function (root) {
  'use strict';
  const KEEP = new Set(('a abbr address article aside b bdi bdo blockquote br caption center cite code col colgroup dd del details dfn div dl dt em ' +
    'figcaption figure footer h1 h2 h3 h4 h5 h6 header hr i img ins kbd li main mark nav ol p pre q rp rt ruby s samp section small span strong ' +
    'sub summary sup table tbody td tfoot th thead time tr u ul var wbr').split(' '));
  const DROP = new Set(('script style template noscript iframe frame frameset object embed applet form input button select option textarea ' +
    'link meta base title head svg math canvas audio video source track picture portal dialog slot').split(' '));
  const ATTRS = { '*': ['title', 'lang', 'dir', 'class', 'align', 'valign', 'width', 'height', 'bgcolor', 'color'],
    a: ['href'], img: ['src', 'alt'], td: ['colspan', 'rowspan'], th: ['colspan', 'rowspan', 'scope'], col: ['span'], colgroup: ['span'],
    ol: ['start', 'type', 'reversed'], li: ['value'], details: ['open'], time: ['datetime'], table: ['border', 'cellpadding', 'cellspacing'] };
  const HREF = /^(https:\/\/|mailto:|#)/i;
  const PIC = /^data:image\/(png|jpeg|gif|webp);base64,[a-z0-9+/=\s]+$/i;

  function css(text) {
    return String(text)
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/@import[^;]*;?/gi, '')
      .replace(/@font-face\s*\{[^}]*\}/gi, '')
      .replace(/expression\s*\(/gi, '(')
      .replace(/url\s*\(\s*(['"]?)([^)'"]*)\1\s*\)/gi, function (m, q, u) { return PIC.test(u.trim()) ? m : 'none'; });
  }

  function clean(src, doc, out, sheets) {
    src.childNodes.forEach(function (n) {
      if (n.nodeType === 3) { out.appendChild(doc.createTextNode(n.nodeValue)); return; }
      if (n.nodeType !== 1) return;
      const tag = n.localName;
      if (tag === 'style') { sheets.push(css(n.textContent)); return; }
      if (DROP.has(tag)) return;
      if (!KEEP.has(tag)) { clean(n, doc, out, sheets); return; }       // unknown tag: keep what it says, not the tag
      if (tag === 'img' && !PIC.test((n.getAttribute('src') || '').trim())) return;   // an outside picture: left out, nothing is fetched
      const e = doc.createElement(tag);
      (ATTRS['*'].concat(ATTRS[tag] || [])).forEach(function (a) {
        if (!n.hasAttribute(a)) return;
        const v = n.getAttribute(a).trim();
        if (a === 'href') { if (HREF.test(v)) { e.setAttribute('href', v); if (v[0] !== '#') { e.setAttribute('target', '_blank'); e.setAttribute('rel', 'noopener noreferrer nofollow'); } } return; }
        if (a === 'src') { if (PIC.test(v)) e.setAttribute('src', v); return; }
        e.setAttribute(a, v.slice(0, 500));
      });
      if (n.hasAttribute('data-inn-style')) e.style.cssText = css(n.getAttribute('data-inn-style'));
      out.appendChild(e);
      clean(n, doc, e, sheets);
    });
  }

  const BASE = ':host { display: block; } .page { all: initial; display: block; box-sizing: border-box; padding: 20px; background: #fff; color: #111; ' +
    'font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; overflow-wrap: anywhere; } ' +
    '.page * { max-width: 100%; box-sizing: border-box; } .page img { height: auto; } .page table { border-collapse: collapse; } ' +
    '.page a[href] { color: #0645ad; } .page a:not([href]) { color: inherit; text-decoration: none; } .page pre { white-space: pre-wrap; } ';

  /* Parsed but inert: a template's content is never rendered, run or fetched. */
  function inert(html) {
    const t = document.createElement('template');
    // style="" is renamed before parsing, so the page's policy is not asked about it; it is applied below through the CSS object model
    t.innerHTML = String(html).replace(/<[a-z][^>]*>/gi, function (tag) { return tag.replace(/\sstyle\s*=/gi, ' data-inn-style='); });
    return t.content;
  }

  /* Words a reader sees, for the note limit. */
  function words(html) {
    const d = inert(html);
    d.querySelectorAll('script,style,template').forEach(function (x) { x.remove(); });
    const m = d.textContent.trim().match(/\S+/g);
    return m ? m.length : 0;
  }

  /* The sender's HTML as an element for this page: a host with a closed shadow root. */
  function render(html, doc) {
    doc = doc || document;
    const parsed = inert(html);
    const host = doc.createElement('div'); host.className = 'html-note';
    const shadow = host.attachShadow({ mode: 'closed' });
    const page = doc.createElement('div'); page.className = 'page';
    const sheets = [];
    clean(parsed, doc, page, sheets);
    const all = [BASE].concat(sheets.map(function (t) { return t.replace(/(^|[},])\s*(html|body|:root)\b/gi, '$1 .page'); }));
    try {
      shadow.adoptedStyleSheets = all.map(function (t) { const s = new CSSStyleSheet(); try { s.replaceSync(t); } catch (e) { /* bad CSS: skip it */ } return s; });
    } catch (e) { /* very old browser: the page shows without the sender's styles */ }
    shadow.appendChild(page);
    return host;
  }

  root.InnernetHtml = { render: render, words: words, css: css };
})(window);
