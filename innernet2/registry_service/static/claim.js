'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  const fromLink = new URLSearchParams(location.hash.slice(1)).get('code');
  if (fromLink) { $('code').value = fromLink.toUpperCase(); history.replaceState(null, '', location.pathname); }
  $('code').addEventListener('input', function (e) {
    // 8 characters: a one-time code; 16: the machine code (permanent until rekeyed)
    const raw = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16);
    e.target.value = raw.match(/.{1,4}/g) ? raw.match(/.{1,4}/g).join('-') : '';
  });
  function say(t, err) { $('msg').textContent = t; $('msg').classList.toggle('error', !!err); }
  if (!I.supported()) { $('go').disabled = true; say('This browser does not support passkeys. Use a current browser.', true); return; }
  $('go').addEventListener('click', async function () {
    const code = $('code').value.trim();
    if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}(-[A-Z0-9]{4}-[A-Z0-9]{4})?$/.test(code)) {
      say('Enter the code from your terminal: the machine code (16 characters) or a one-time code (8).', true); return;
    }
    $('go').disabled = true;
    say('Waiting for your device…');
    try {
      const start = await I.api('/api/claim/options', { code: code });
      if (start.resume) {
        // This code was already used to sign in: confirm the passkey again and carry on.
        say('Confirm your passkey to continue setting up this machine…');
        const a = await I.get(start.login_options);
        await I.api('/api/claim/verify', { login: true, flow: start.login_flow, credential: a });
        location.replace(I.BASE + '/setup');
        return;
      }
      let done = false;
      const next = start.setup === false ? '/dashboard' : '/setup';
      try {
        const credential = await I.create(start.options);
        await I.api('/api/claim/verify', { flow: start.flow, credential: credential, name: $('pk-name').value, pair: !!start.pair });
        done = true;
      } catch (err) {
        // This device already holds a passkey for this machine: sign in with it instead.
        if (!(err && err.name === 'InvalidStateError' && start.login_flow)) throw err;
        say('This device already has a passkey for this machine. Confirm it to continue…');
        const assertion = await I.get(start.login_options);
        await I.api('/api/claim/verify', { login: true, flow: start.login_flow, credential: assertion });
        done = true;
      }
      if (done) location.replace(I.BASE + next);
    } catch (err) {
      say(I.friendly(err), true);
      $('go').disabled = false;
    }
  });
})();
