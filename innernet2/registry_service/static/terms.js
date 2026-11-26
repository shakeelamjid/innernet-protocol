'use strict';
(function () {
  const base = location.pathname.replace(/\/terms\/?$/, '');
  // A small, safe Markdown subset: headings, paragraphs. Text is set with textContent only.
  function render(md, into) {
    md.split(/\n\s*\n/).forEach(function (block) {
      const b = block.trim();
      if (!b) return;
      const h = b.match(/^(#{1,3})\s+(.*)$/);
      const el = document.createElement(h ? 'h' + (h[1].length + 1) : 'p');
      el.textContent = h ? h[2] : b.replace(/\n/g, ' ');
      into.append(el);
    });
  }
  fetch(base + '/v1/terms').then(function (r) { return r.json(); }).then(function (t) {
    ['provider', 'client'].forEach(function (k) {
      render(t[k].text, document.getElementById(k + '-text'));
      document.getElementById(k + '-fp').textContent = 'Version ' + t[k].version + ' · fingerprint ' + t[k].sha256;
    });
  }).catch(function () {
    const e = document.getElementById('err'); e.textContent = 'Could not load the terms.'; e.hidden = false;
  });
})();
