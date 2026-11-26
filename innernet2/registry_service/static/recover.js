'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  function say(id, t, err) { $(id).textContent = t; $(id).classList.toggle('error', !!err); }
  let backup = null, seedHex = '';
  const hex = function (s) { return Uint8Array.from(s.match(/../g).map(function (b) { return parseInt(b, 16); })); };
  const tohex = function (buf) { return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''); };

  // Same as the provider: PBKDF2-HMAC-SHA256 (the file's iterations) -> AES-256-GCM, additional data "version\0provider_id".
  async function openBackup(b, pass) {
    const S = crypto.subtle, enc = new TextEncoder();
    const base = await S.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    const key = await S.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: hex(b.salt), iterations: b.iterations }, base,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const seed = await S.decrypt({ name: 'AES-GCM', iv: hex(b.nonce), additionalData: enc.encode(b.version + '\u0000' + b.provider_id) },
      key, hex(b.ciphertext));
    return tohex(seed);
  }

  async function machines() {
    let d;
    try { d = await I.api('/api/me'); }
    catch (err) {
      if (err.status === 401) { $('signin').hidden = false; return; }
      if (err.status === 409) { d = { machines: [] }; } else throw err;
    }
    $('signin').hidden = true; $('pick').hidden = false;
    const tb = $('machines'); tb.textContent = '';
    (d.machines || []).forEach(function (m) {
      const tr = document.createElement('tr');
      [m.name || '(setting up)', m.state, m.backup_kept ? 'yes' : 'no'].forEach(function (t) { const c = document.createElement('td'); c.textContent = t; tr.append(c); });
      const c = document.createElement('td');
      if (m.backup_kept) {
        const b = document.createElement('button'); b.className = 'btn btn-sm'; b.type = 'button'; b.textContent = 'Recover';
        b.addEventListener('click', function () { choose(m); }); c.append(b);
      } else {
        const a = document.createElement('a'); a.href = '#nobackup'; a.textContent = 'No backup kept'; a.addEventListener('click', function () { $('nobackup').hidden = false; }); c.append(a);
      }
      tr.append(c); tb.append(tr);
    });
    if (!(d.machines || []).length) { const tr = document.createElement('tr'); const c = document.createElement('td'); c.colSpan = 4; c.textContent = 'No machines in this account.'; tr.append(c); tb.append(tr); }
  }

  async function choose(m) {
    try {
      const r = await I.api('/api/me/backup?m=' + m.id);
      backup = r.backup;
      $('unlock-for').textContent = 'Backup of ' + (m.name || 'this machine') + ', kept ' + I.when(r.stored_at) + '.';
      $('unlock').hidden = false; $('done').hidden = true; $('pass').focus();
    } catch (err) { say('unlock-msg', I.friendly(err), true); $('unlock').hidden = false; }
  }

  $('unlock-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!backup) return;
    $('unlock-btn').disabled = true; say('unlock-msg', 'Opening… (this takes a few seconds on purpose)');
    try {
      seedHex = await openBackup(backup, $('pass').value);
      $('pass').value = '';
      say('unlock-msg', '');
      $('done-id').textContent = backup.provider_id.slice(0, 16) + '…';
      $('done').hidden = false; $('key-box').hidden = true;
    } catch (err) {
      say('unlock-msg', 'That passphrase does not open this backup. Check it and try again; if it is gone, see below.', true);
      $('nobackup').hidden = false;
    }
    $('unlock-btn').disabled = false;
  });
  $('dl').addEventListener('click', function () {
    const blob = new Blob([JSON.stringify(backup, null, 2) + '\n'], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'innernet-backup.json'; a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });
  $('reveal').addEventListener('click', function () {
    const box = $('key-box');
    box.hidden = !box.hidden;
    box.textContent = 'Secret key (Ed25519 seed, hex): ' + seedHex;
    $('reveal').textContent = box.hidden ? 'Show the key' : 'Hide the key';
  });
  $('signin-btn').addEventListener('click', async function () {
    try {
      const o = await I.api('/api/login/options', {});
      await I.api('/api/login/verify', { flow: o.flow, credential: await I.get(o.options) });
      await machines();
    } catch (err) { say('signin-msg', I.friendly(err), true); }
  });
  machines().catch(function (err) { say('signin-msg', I.friendly(err), true); $('signin').hidden = false; });
})();
