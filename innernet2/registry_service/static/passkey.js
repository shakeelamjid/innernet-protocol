'use strict';
// Shared helpers: API calls and WebAuthn JSON <-> ArrayBuffer conversion.
(function () {
  const BASE = location.pathname.replace(/\/(dashboard|enroll|providers\/[^/]*)\/?$/, '');

  async function api(path, body) {
    const opts = { credentials: 'same-origin', headers: { 'X-Innernet': '1' } };
    if (body !== undefined) {
      opts.method = 'POST';
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(BASE + path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) {
      const err = new Error((data && data.detail) || ('Request failed (' + res.status + ')'));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function b64urlToBuf(s) {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  async function create(options) {
    const pk = Object.assign({}, options);
    pk.challenge = b64urlToBuf(options.challenge);
    pk.user = Object.assign({}, options.user, { id: b64urlToBuf(options.user.id) });
    pk.excludeCredentials = (options.excludeCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64urlToBuf(c.id) });
    });
    const cred = await navigator.credentials.create({ publicKey: pk });
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : []
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined
    };
  }

  async function get(options) {
    const pk = Object.assign({}, options);
    pk.challenge = b64urlToBuf(options.challenge);
    pk.allowCredentials = (options.allowCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64urlToBuf(c.id) });
    });
    const cred = await navigator.credentials.get({ publicKey: pk });
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined
    };
  }

  function friendly(err) {
    if (err && err.name === 'NotAllowedError') return 'Cancelled, or the passkey prompt timed out. Try again.';
    if (err && err.name === 'InvalidStateError') return 'This device already has a passkey for this provider.';
    return (err && err.message) || 'Something went wrong. Try again.';
  }

  function when(ts) {
    if (!ts) return '–';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 16);
  }

  window.Innernet = { api: api, create: create, get: get, supported: supported, friendly: friendly, when: when, BASE: BASE };
})();
