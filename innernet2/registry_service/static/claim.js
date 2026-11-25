'use strict';
(function () {
  const I = window.Innernet;
  const $ = function (id) { return document.getElementById(id); };
  const fromLink = new URLSearchParams(location.hash.slice(1)).get('code');
  if (fromLink) { $('code').value = fromLink.toUpperCase(); history.replaceState(null, '', location.pathname); }
  $('code').addEventListener('input', function (e) {
    let v = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    if (v.length > 4) v = v.slice(0, 4) + '-' + v.slice(4);
    e.target.value = v;
  });
  function say(t, err) { $('msg').textContent = t; $('msg').classList.toggle('error', !!err); }
  if (!I.supported()) { $('go').disabled = true; say('This browser does not support passkeys. Use a current browser.', true); return; }
  $('go').addEventListener('click', async function () {
    const code = $('code').value.trim();
    if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) { say('Enter the 8-character code, like K7QM-4XPA.', true); return; }
    $('go').disabled = true;
    say('Waiting for your device…');
    try {
      const start = await I.api('/api/claim/options', { code: code });
      let done = false;
      try {
        const credential = await I.create(start.options);
        await I.api('/api/claim/verify', { flow: start.flow, credential: credential, name: $('pk-name').value });
        done = true;
      } catch (err) {
        // This device already holds a passkey for this machine: sign in with it instead.
        if (!(err && err.name === 'InvalidStateError' && start.login_flow)) throw err;
        say('This device already has a passkey for this machine. Confirm it to continue…');
        const assertion = await I.get(start.login_options);
        await I.api('/api/claim/verify', { login: true, flow: start.login_flow, credential: assertion });
        done = true;
      }
      if (done) location.replace(I.BASE + '/setup');
    } catch (err) {
      say(I.friendly(err), true);
      $('go').disabled = false;
    }
  });
})();
