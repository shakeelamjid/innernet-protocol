/* INNERNET Send: the receiver's page. Proves it holds the link, shows who the file is from and its
   rules, then with the PIN asks the keeper for its share, fetches the sealed parts and opens them here. */
(function () {
  'use strict';
  const C = window.InnernetSend, St = window.InnernetSendStore, $ = function (id) { return document.getElementById(id); };
  const m = location.pathname.match(/\/send\/o\/([0-9a-f]{32})\/?$/);
  const id = m && m[1];
  let secret = null, keys = null, busy = false, steps = null, isNote = false, token = null;

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
    const leftOpens = info.max_opens > 1 ? ' ' + (info.max_opens - info.opens) + ' opening' + (info.max_opens - info.opens === 1 ? '' : 's') + ' left.' : '';
    isNote = info.kind === 'note';
    $('title').textContent = isNote ? 'A sealed note for you' : 'A sealed file for you';
    $('rules').textContent = (isNote ? 'A note, shown on this screen. ' : St.size(info.size) + '. ') +
      (info.max_opens === 1 ? 'It opens once and is then destroyed.' : info.max_opens ? 'It opens ' + info.max_opens + ' times.' : 'It opens any number of times until it ends.') +
      (info.forward ? '' : ' Only on the first device that opens it.') + ' Ends ' + St.when(info.expires_at) + '.' + leftOpens;
    steps = St.steps($('six'), $('bar'), [
      { title: 'Link proved', text: 'This device showed it holds the link, without sending the link secret.' },
      { title: 'PIN proved', text: 'A proof made from the PIN is sent. The PIN itself is not.' },
      { title: 'Keeper part released', text: 'The keeper checks the sender\u2019s rules, then hands over its part.' },
      { title: 'File key rebuilt', text: 'From link secret + PIN + keeper part, on this device.' },
      { title: 'Sealed parts fetched and opened', text: '', cells: true },
      { title: 'Checked and put together', text: '' }]);
    steps.set(0, 'done');
    $('ask').hidden = false;
    hold(info.open_after);
  }

  function hold(after) {
    const wait = after - Date.now() / 1000;
    $('held').hidden = wait <= 0; $('go').disabled = wait > 0; $('pin').disabled = wait > 0;
    if (wait > 0) {
      $('held').textContent = 'The sender set this to open after ' + St.when(after) + ' (in ' + St.left(after) + '). Keep the link and the PIN until then.';
      setTimeout(function () { hold(after); }, Math.min(wait * 1000 + 500, 60000));
    } else if (!busy) $('pin').focus();
  }

  async function open(pin) {
    const device = await St.deviceKey();
    $('work').hidden = false;
    steps.set(1, 'run');
    const body = Object.assign({ auth: C.b64u(keys.auth), pin_proof: await C.pinTag(keys, pin), device_pub: await C.publicRaw(device) },
      await C.signRequest(device, 'open', id));
    steps.set(2, 'run', 'Asking the keeper…', 0.4);
    let rel;
    try { rel = await (await St.api('POST', '/files/' + id + '/open', body)).json(); }
    catch (e) { steps.set(1, 'wait'); steps.set(2, 'wait', 'The keeper checks the sender\u2019s rules, then hands over its part.'); $('work').hidden = true; throw e; }
    $('ask').hidden = true;
    steps.set(1, 'done');
    steps.set(2, 'done', rel.last ? 'Released for the last time. The keeper has now destroyed its part: this link and PIN will open nothing again.'
      : 'Released. Opening ' + rel.opens + (rel.max_opens ? ' of ' + rel.max_opens : '') + '.');
    steps.set(3, 'run', 'Stretching the PIN 200,000 rounds…');
    const key = await C.fileKey(secret, C.unb64u(rel.keeper_share), pin, id);
    const meta = await C.openSmall(key, id, 'meta', rel.meta);
    steps.set(3, 'done', 'Rebuilt here. The keeper never had the whole key.');
    const out = [];
    for (let n = 0; n < rel.parts; n++) {
      steps.set(4, 'run', 'Part ' + (n + 1) + ' of ' + rel.parts + ': fetched sealed, opened here.', n / rel.parts);
      const sealed = new Uint8Array(await (await St.api('GET', '/files/' + id + '/parts/' + n, null, { 'X-Send-Token': rel.token })).arrayBuffer());
      out.push(await C.openPart(key, id, n, rel.parts, sealed));
      steps.set(4, 'run', null, (n + 1) / rel.parts);
    }
    steps.set(4, 'done', rel.parts + (rel.parts === 1 ? ' part' : ' parts') + ' opened. Each seal matched, so nothing was changed on the way.');
    steps.set(5, 'run');
    const blob = new Blob(out, { type: meta.type });
    if (blob.size !== meta.size) throw new Error('it is not complete');
    steps.set(5, 'done', St.size(meta.size) + ', complete and unchanged.');
    return { blob: blob, meta: meta, rel: rel };
  }

  $('form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (busy) return;
    const pin = $('pin').value.replace(/\D/g, '');
    if (pin.length !== 6) return say('The PIN has 6 digits.', true);
    busy = true; $('go').disabled = true;
    open(pin).then(async function (r) {
      const note = r.meta.kind === 'note';
      if (note) {
        $('shown').textContent = await r.blob.text(); $('shown').hidden = false;
        $('save').hidden = true; $('name').textContent = 'The note';
        $('facts').textContent = 'Opened and checked on this device. It is shown only here.';
      } else {
        $('save').href = URL.createObjectURL(r.blob); $('save').download = r.meta.name;
        $('name').textContent = r.meta.name;
        $('facts').textContent = St.size(r.meta.size) + '. Opened and checked on this device.';
      }
      $('after').textContent = (r.rel.last ? 'That was the last opening: it is now being destroyed on the network. ' : '') +
        (note ? 'Closing this page discards it.' : 'Save it now; closing this page discards it.');
      $('title').textContent = note ? 'Your note is open' : 'Your file is open';
      $('lede').textContent = 'Nothing was unsealed anywhere but here.';
      $('got').hidden = false;
      if (r.rel.reply_on) { token = r.rel.token; $('reply').hidden = false; }
      if (r.rel.last) setTimeout(function () { steps.burn(); }, 900);
      if (!note) $('save').click();
    }).catch(function (e) {
      say(e.name === 'OperationError' ? 'It could not be opened: its seal does not match. Nothing was saved.' : e.message, true);
      if (e.status === 410) end('This file is gone', e.message);
    }).finally(function () { busy = false; $('go').disabled = false; });
  });

  $('reply').addEventListener('submit', function (ev) {
    ev.preventDefault();
    const text = $('reply-text').value.trim();
    if (!text) return;
    $('reply-go').disabled = true;
    C.sealSmall(keys.preview, id, 'reply', { text: text }).then(function (sealed) {
      return St.api('POST', '/files/' + id + '/reply', { sealed: sealed }, { 'X-Send-Token': token });
    }).then(function () {
      $('reply-text').disabled = true; $('reply-go').hidden = true;
      $('reply-msg').textContent = 'Sent, sealed. Only the sender can read it.';
    }).catch(function (e) { $('reply-msg').textContent = e.message; $('reply-msg').classList.add('error'); $('reply-go').disabled = false; });
  });

  start().catch(function (e) { end('Something went wrong', e.message); });
})();
