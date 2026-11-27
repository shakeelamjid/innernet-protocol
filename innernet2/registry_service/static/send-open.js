/* INNERNET Send: the receiver's page. Proves it holds the link, shows who the file is from and its
   rules, then with the PIN asks the keeper for its share, fetches the sealed parts and opens them here. */
(function () {
  'use strict';
  const C = window.InnernetSend, St = window.InnernetSendStore, $ = function (id) { return document.getElementById(id); };
  const m = location.pathname.match(/\/send\/o\/([0-9a-f]{32})\/?$/);
  const id = m && m[1];
  let secret = null, keys = null, busy = false;

  function say(text, err) { $('msg').textContent = text || ''; $('msg').classList.toggle('error', !!err); }
  function end(title, text) { $('title').textContent = title; $('lede').textContent = text; $('ask').hidden = true; }

  async function start() {
    try { secret = C.unb64u(location.hash.slice(1)); } catch (e) { secret = null; }
    if (!id || !secret || secret.length !== 32) return end('This link is not complete', 'Ask the sender for the whole link, including the part after the # sign.');
    if (!window.crypto || !crypto.subtle || !window.indexedDB) return end('This browser cannot open sealed files', 'Use a current browser on a secure (https) page.');
    keys = await C.linkKeys(secret, id);
    let info;
    try { info = await (await St.api('POST', '/files/' + id + '/info', { auth: C.b64u(keys.auth) })).json(); }
    catch (e) { return end(e.status === 404 ? 'This file does not exist' : 'This link does not work', e.status === 404 ? 'It may have ended more than 30 days ago, or the link is wrong.' : e.message); }
    if (info.state === 'dead') return end('This file is gone', 'It was destroyed (' + info.reason + '). The link and PIN no longer open anything.');
    if (info.state === 'uploading') return end('Not ready yet', 'The sender has not finished sending this file. Try again in a minute.');
    if (info.state === 'spent') return end('This file was already opened', 'It could be opened ' + (info.max_opens === 1 ? 'once' : info.max_opens + ' times') + ', and that is used up.');
    let pv = { from: '', note: '' };
    try { pv = await C.openSmall(keys.preview, id, 'preview', info.preview); } catch (e) { /* shown without a name */ }
    $('lede').textContent = 'It was sealed on the sender\'s device. It opens here, on yours, with the PIN the sender gave you.';
    $('from').textContent = pv.from ? 'From ' + pv.from : 'A sealed file';
    if (pv.note) { $('note').textContent = pv.note; $('note').hidden = false; }
    const leftOpens = info.max_opens ? ' ' + (info.max_opens - info.opens) + ' opening' + (info.max_opens - info.opens === 1 ? '' : 's') + ' left.' : '';
    $('rules').textContent = St.size(info.size) + '. ' + St.rulesLine(info) + leftOpens;
    $('ask').hidden = false;
    $('pin').focus();
  }

  async function open(pin) {
    const device = await St.deviceKey();
    say('Asking the keeper…');
    const body = Object.assign({ auth: C.b64u(keys.auth), pin_proof: await C.pinTag(keys, pin), device_pub: await C.publicRaw(device) },
      await C.signRequest(device, 'open', id));
    const rel = await (await St.api('POST', '/files/' + id + '/open', body)).json();
    const key = await C.fileKey(secret, C.unb64u(rel.keeper_share), pin, id);
    const meta = await C.openSmall(key, id, 'meta', rel.meta);
    const out = [];
    for (let n = 0; n < rel.parts; n++) {
      say('Fetching and opening: ' + Math.round(100 * n / rel.parts) + '%');
      const sealed = new Uint8Array(await (await St.api('GET', '/files/' + id + '/parts/' + n, null, { 'X-Send-Token': rel.token })).arrayBuffer());
      out.push(await C.openPart(key, id, n, rel.parts, sealed));
    }
    const blob = new Blob(out, { type: meta.type });
    if (blob.size !== meta.size) throw new Error('the file is not complete');
    return { blob: blob, meta: meta, rel: rel };
  }

  $('form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (busy) return;
    const pin = $('pin').value.replace(/\D/g, '');
    if (pin.length !== 6) return say('The PIN has 6 digits.', true);
    busy = true; $('go').disabled = true;
    open(pin).then(function (r) {
      const url = URL.createObjectURL(r.blob);
      $('save').href = url; $('save').download = r.meta.name;
      $('name').textContent = r.meta.name;
      $('facts').textContent = St.size(r.meta.size) + '. Opened and checked on this device.';
      $('after').textContent = (r.rel.last ? 'That was the last opening: the file is now being destroyed on the network. ' : '') +
        'Save it now; closing this page discards it.';
      $('title').textContent = 'Your file is open';
      $('lede').textContent = 'Nothing was unsealed anywhere but here.';
      $('ask').hidden = true; $('got').hidden = false;
      $('save').click();
    }).catch(function (e) {
      say(e.name === 'OperationError' ? 'The file could not be opened: its seal does not match. Nothing was saved.' : e.message, true);
      if (e.status === 410) end('This file is gone', e.message);
    }).finally(function () { busy = false; $('go').disabled = false; });
  });

  start().catch(function (e) { end('Something went wrong', e.message); });
})();
