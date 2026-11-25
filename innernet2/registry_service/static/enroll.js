'use strict';
(function () {
  const I = window.Innernet;
  const btn = document.getElementById('enroll-btn');
  const msg = document.getElementById('enroll-msg');
  const nameInput = document.getElementById('pk-name');
  const token = new URLSearchParams(location.hash.slice(1)).get('t');
  // Drop the one-time token from the address bar and history right away.
  if (token) history.replaceState(null, '', location.pathname);

  function say(text, isError) {
    msg.textContent = text;
    msg.classList.toggle('error', !!isError);
  }

  if (!token) {
    btn.disabled = true;
    say('This page needs the one-time link from "innernet-provider login".', true);
    return;
  }
  if (!I.supported()) {
    btn.disabled = true;
    say('This browser does not support passkeys. Open the link in a current browser.', true);
    return;
  }

  btn.addEventListener('click', async function () {
    btn.disabled = true;
    say('Waiting for your device…');
    try {
      const start = await I.api('/api/enroll/options', { token: token });
      const credential = await I.create(start.options);
      await I.api('/api/enroll/verify', { flow: start.flow, credential: credential, name: nameInput.value });
      say('Passkey added. Opening your dashboard…');
      location.replace(I.BASE + '/dashboard');
    } catch (err) {
      say(I.friendly(err), true);
      btn.disabled = false;
    }
  });
})();
