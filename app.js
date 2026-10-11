// Murmure — interface et connexion pair-à-pair.
// Le chiffrement est dans crypto.js ; ce fichier ne fait transiter que des messages déjà chiffrés.

import * as E2E from './crypto.js';

const CONFIG = {
  // Options passées à PeerJS. Vide = serveur public de mise en relation (0.peerjs.com).
  // Pour votre propre serveur : { host: 'exemple.org', port: 443, path: '/', secure: true }
  // (pensez alors à adapter « connect-src » dans index.html).
  peerOptions: {},
  maxLength: 4000,
  photoMaxSide: 1600, // côté le plus long, en pixels, après réduction
  photoMaxBytes: 1500 * 1024,
  handshakeTimeoutMs: 20000,
};

const $ = (id) => document.getElementById(id);
const ui = {
  status: $('status'),
  lobby: $('lobby'),
  connecting: $('connecting'),
  chat: $('chat'),
  myLink: $('my-link'),
  copy: $('copy'),
  join: $('join'),
  joinButton: $('join-button'),
  peerInput: $('peer-input'),
  notice: $('notice'),
  reset: $('reset'),
  cancel: $('cancel'),
  safety: $('safety'),
  safetyLabel: $('safety-label'),
  safetyCode: $('safety-code'),
  safetyHelp: $('safety-help'),
  verify: $('verify'),
  leave: $('leave'),
  log: $('log'),
  composer: $('composer'),
  text: $('text'),
  photo: $('photo'),
  photoInput: $('photo-input'),
};

// ---------- Stockage local (identité uniquement, jamais les messages) ----------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('murmure', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbRun(mode, action) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('kv', mode);
      const req = action(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

function newPeerId() {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789'; // 32 symboles : 5 bits par caractère
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes, (b) => alphabet[b & 31]).join('');
}

async function loadIdentity() {
  try {
    const saved = await dbRun('readonly', (store) => store.get('identity'));
    if (saved?.keys?.privateKey && typeof saved.peerId === 'string') return saved;
  } catch { /* stockage indisponible (navigation privée) : identité temporaire */ }
  const fresh = { keys: await E2E.createIdentity(), peerId: newPeerId() };
  try {
    await dbRun('readwrite', (store) => store.put(fresh, 'identity'));
  } catch { /* identité valable pour cette session seulement */ }
  return fresh;
}

function verifiedContacts() {
  try {
    const list = JSON.parse(localStorage.getItem('murmure.verified') || '[]');
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function rememberVerified(fingerprint) {
  try {
    const list = verifiedContacts();
    if (!list.includes(fingerprint)) list.push(fingerprint);
    localStorage.setItem('murmure.verified', JSON.stringify(list.slice(-200)));
  } catch { /* sans stockage, la vérification vaut pour cette conversation */ }
}

// ---------- Affichage ----------

function setStatus(text, state = 'wait') {
  ui.status.textContent = text;
  ui.status.dataset.state = state;
}

function show(view) {
  for (const name of ['lobby', 'connecting', 'chat']) ui[name].hidden = name !== view;
}

function setNotice(text) {
  ui.notice.textContent = text || '';
  ui.notice.hidden = !text;
}

function atBottom(margin = 60) {
  return ui.log.scrollHeight - ui.log.scrollTop - ui.log.clientHeight < margin;
}

function append(node) {
  const stick = atBottom();
  ui.log.append(node);
  if (stick) ui.log.scrollTop = ui.log.scrollHeight;
}

function bubble(who, content) {
  const node = document.createElement('div');
  node.className = `msg ${who}`;
  const time = document.createElement('time');
  time.textContent = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  node.append(content, time); // une chaîne est insérée comme texte, jamais interprétée comme du HTML
  return node;
}

function addMessage(who, text) {
  const node = bubble(who, text);
  append(node);
  return node;
}

const objectUrls = [];

function photoBubble(who, bytes) {
  // Le type est imposé : même un fichier malveillant ne sera traité que comme une image JPEG.
  const url = URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' }));
  objectUrls.push(url);
  const link = document.createElement('a');
  link.href = url;
  link.target = '_blank';
  link.rel = 'noopener';
  link.title = 'Ouvrir en grand';
  const img = document.createElement('img');
  img.alt = who === 'me' ? 'Photo envoyée' : 'Photo reçue';
  img.src = url;
  img.addEventListener('load', () => { if (atBottom(img.height + 80)) ui.log.scrollTop = ui.log.scrollHeight; });
  link.append(img);
  const node = bubble(who, link);
  node.classList.add('photo');
  return node;
}

function clearLog() {
  ui.log.replaceChildren(); // l'historique n'est conservé nulle part
  for (const url of objectUrls.splice(0)) URL.revokeObjectURL(url);
}

function setComposerEnabled(enabled) {
  ui.text.disabled = !enabled;
  for (const button of ui.composer.querySelectorAll('button')) button.disabled = !enabled;
}

function addSystem(text) {
  const node = document.createElement('div');
  node.className = 'system';
  node.textContent = text;
  append(node);
}

function setVerified(verified) {
  ui.safety.dataset.verified = String(verified);
  ui.safetyLabel.textContent = verified ? 'Code de sécurité — contact vérifié' : 'Code de sécurité — non vérifié';
  ui.safetyHelp.hidden = verified;
  ui.verify.hidden = verified;
}

let unread = 0;
function updateTitle() {
  document.title = (unread ? `(${unread}) ` : '') + 'Murmure — messagerie chiffrée';
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    unread = 0;
    updateTitle();
  }
});

// ---------- Connexion ----------

let identity = null;
let peer = null;
let ready = false;
let active = null; // conversation en cours (une seule à la fois)
let pendingInvite = null;

function parsePeerId(input) {
  const raw = String(input || '').trim();
  const id = raw.includes('#') ? raw.slice(raw.lastIndexOf('#') + 1) : raw;
  return /^[A-Za-z0-9]{8,64}$/.test(id) ? id : null;
}

function connectTo(input) {
  const id = parsePeerId(input);
  if (!id) return setNotice('Ce lien ne ressemble pas à une invitation Murmure.');
  if (id === identity.peerId) return setNotice('C’est votre propre lien : envoyez-le à votre contact.');
  if (!ready) return setNotice('Pas encore connecté au service de mise en relation. Réessayez dans un instant.');
  if (active) return;
  setNotice('');
  attach(peer.connect(id, { reliable: true, serialization: 'json' }));
}

function attach(conn) {
  if (active || !ui.chat.hidden) {
    // Déjà en conversation (ou conversation terminée encore affichée) : on prévient et on raccroche.
    conn.on('open', () => {
      try { conn.send({ t: 'busy' }); } catch { /* connexion déjà fermée */ }
      setTimeout(() => conn.close(), 500);
    });
    return;
  }

  const chat = { conn, session: null, closed: false, incoming: null, inbox: Promise.resolve(), outbox: Promise.resolve(), timer: null };
  active = chat;
  show('connecting');

  const offerReady = E2E.createOffer(identity.keys);
  offerReady.catch(() => {});

  const sendHello = async () => {
    try {
      conn.send((await offerReady).hello);
    } catch {
      endChat(chat, 'Impossible de préparer les clés de chiffrement.');
    }
  };
  if (conn.open) sendHello();
  else conn.on('open', sendHello);

  conn.on('data', (data) => {
    // File d'attente : les messages sont traités un par un, dans l'ordre d'arrivée.
    chat.inbox = chat.inbox
      .then(() => onData(chat, data, offerReady))
      .catch((err) => endChat(chat, err?.code === 'version'
        ? 'Votre contact utilise une autre version de Murmure. Rechargez la page tous les deux, puis réessayez.'
        : 'Un message invalide a été reçu : la conversation a été coupée par sécurité.'));
  });
  conn.on('close', () => endChat(chat, chat.session ? 'Votre contact a quitté la conversation.' : 'La connexion a été fermée.'));
  conn.on('error', () => endChat(chat, 'La connexion a été interrompue.'));

  chat.timer = setTimeout(() => {
    if (!chat.session) endChat(chat, 'La connexion n’a pas abouti. Vérifiez que votre contact a bien la page ouverte.');
  }, CONFIG.handshakeTimeoutMs);
}

async function onData(chat, data, offerReady) {
  if (chat.closed || !data || typeof data !== 'object') return;

  if (data.t === 'busy' && !chat.session) {
    endChat(chat, 'Ce contact est déjà en conversation avec quelqu’un d’autre.');
    return;
  }

  if (data.t === 'hello') {
    if (chat.session) throw new Error('échange de clés en double');
    chat.session = await E2E.completeSession(await offerReady, data);
    if (chat.closed) return;
    clearTimeout(chat.timer);
    openChat(chat);
    return;
  }

  if (data.t === 'msg') {
    if (!chat.session) throw new Error('message avant l’échange de clés');
    const frame = await chat.session.decrypt(data);
    if (chat.closed) return;
    receiveFrame(chat, frame);
  }
}

// ---------- Trames : texte et photos ----------
// Chaque envoi (un texte ou une photo) est découpé en trames chiffrées une par une.
// Trame en clair : [type, 1 s'il reste des trames / 0 si c'est la dernière, données…]

const KIND = { text: 1, photo: 2 };
const FRAME_BYTES = 10000; // PeerJS refuse les envois de plus de 16 300 octets une fois encodés
const MAX_BYTES = { [KIND.text]: 20000, [KIND.photo]: 2 * 1024 * 1024 };
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function sendItem(chat, kind, bytes) {
  let offset = 0;
  do {
    const part = bytes.subarray(offset, offset + FRAME_BYTES);
    offset += part.length;
    const frame = new Uint8Array(part.length + 2);
    frame[0] = kind;
    frame[1] = offset < bytes.length ? 1 : 0;
    frame.set(part, 2);
    const packet = await chat.session.encrypt(frame);
    // Laisse le canal se vider pour ne pas saturer la mémoire pendant l'envoi d'une photo.
    while (!chat.closed && chat.conn.dataChannel?.bufferedAmount > 1024 * 1024) await pause(40);
    if (chat.closed) throw new Error('fermée');
    chat.conn.send(packet);
  } while (offset < bytes.length);
}

function receiveFrame(chat, frame) {
  const [kind, more] = frame;
  if (frame.length < 2 || !(kind in MAX_BYTES) || more > 1) throw new Error('trame mal formée');
  let item = chat.incoming;
  if (!item) {
    item = chat.incoming = { kind, parts: [], size: 0, placeholder: null };
    if (kind === KIND.photo && more) {
      item.placeholder = bubble('them', 'Réception d’une photo…');
      item.placeholder.classList.add('pending');
      append(item.placeholder);
    }
  }
  if (item.kind !== kind) throw new Error('trames mélangées');
  item.parts.push(frame.subarray(2));
  item.size += frame.length - 2;
  if (item.size > MAX_BYTES[kind]) throw new Error('envoi trop volumineux');
  if (more) return;

  chat.incoming = null;
  const bytes = new Uint8Array(item.size);
  let offset = 0;
  for (const part of item.parts) {
    bytes.set(part, offset);
    offset += part.length;
  }

  if (kind === KIND.text) {
    addMessage('them', td.decode(bytes));
  } else {
    if (bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) throw new Error('ce n’est pas une image JPEG');
    const node = photoBubble('them', bytes);
    if (item.placeholder) item.placeholder.replaceWith(node);
    else append(node);
  }
  if (document.hidden) {
    unread += 1;
    updateTitle();
  }
}

/** Vrai si le navigateur laisse la page relire un canvas (certaines protections anti-pistage le brouillent). */
function canvasReadable() {
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = 8;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.fillStyle = '#336699';
  ctx.fillRect(0, 0, 8, 8);
  const data = ctx.getImageData(0, 0, 8, 8).data;
  for (let i = 0; i < data.length; i += 4) {
    if (Math.abs(data[i] - 0x33) > 8 || Math.abs(data[i + 1] - 0x66) > 8 || Math.abs(data[i + 2] - 0x99) > 8) return false;
  }
  return true;
}

/** Réduit la photo et la réencode en JPEG : les métadonnées (GPS, appareil, date) ne sont pas conservées. */
async function prepareImage(file) {
  if (!canvasReadable()) throw Object.assign(new Error('canvas bloqué'), { code: 'canvas' });
  let bitmap;
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
  } catch {
    bitmap = await createImageBitmap(file);
  }
  try {
    let side = CONFIG.photoMaxSide;
    let quality = 0.82;
    for (let attempt = 0; attempt < 4; attempt++) {
      const scale = Math.min(1, side / Math.max(bitmap.width, bitmap.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff'; // fond blanc pour les images transparentes
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
      if (!blob) throw new Error('encodage impossible');
      if (blob.size <= CONFIG.photoMaxBytes) return new Uint8Array(await blob.arrayBuffer());
      side = Math.round(side * 0.75);
      quality -= 0.1;
    }
    throw new Error('image trop lourde');
  } finally {
    bitmap.close?.();
  }
}

async function sendPhoto(file) {
  const chat = active;
  if (!chat?.session || !file) return;
  if (!file.type.startsWith('image/')) return addSystem('Seules les images peuvent être envoyées.');
  let bytes;
  try {
    bytes = await prepareImage(file);
  } catch (err) {
    return addSystem(err?.code === 'canvas'
      ? 'Photo non envoyée : ce navigateur bloque la préparation des images (protection anti-pistage du canvas). Autorisez-la pour ce site, puis réessayez.'
      : 'Photo non envoyée : ce fichier n’a pas pu être lu comme une image.');
  }
  if (chat.closed) return;
  const node = photoBubble('me', bytes);
  node.classList.add('sending');
  append(node);
  ui.log.scrollTop = ui.log.scrollHeight;
  chat.outbox = chat.outbox
    .then(() => sendItem(chat, KIND.photo, bytes))
    .then(() => node.classList.remove('sending'))
    .catch(() => {
      node.classList.remove('sending');
      node.classList.add('failed');
      node.title = 'Non envoyée';
    });
}

function openChat(chat) {
  clearLog();
  ui.safetyCode.textContent = chat.session.safetyCode;
  const known = verifiedContacts().includes(chat.session.peerFingerprint);
  setVerified(known);
  setComposerEnabled(true);
  ui.leave.textContent = 'Quitter';
  show('chat');
  addSystem('Conversation chiffrée de bout en bout.');
  addSystem(known
    ? 'Vous avez déjà vérifié ce contact.'
    : 'Nouveau contact : comparez le code de sécurité avant d’échanger des informations sensibles.');
  setStatus('Conversation chiffrée', 'ok');
  ui.text.focus();
}

function endChat(chat, reason) {
  if (chat.closed) return;
  chat.closed = true;
  clearTimeout(chat.timer);
  try { chat.conn.close(); } catch { /* déjà fermée */ }
  if (active === chat) active = null;

  if (chat.session) {
    // On laisse les messages à l'écran jusqu'à ce que l'utilisateur ferme.
    addSystem(reason || 'Conversation terminée.');
    setComposerEnabled(false);
    ui.leave.textContent = 'Fermer';
  } else {
    show('lobby');
    setNotice(reason);
  }
  if (ready) setStatus('En ligne — en attente d’un contact', 'ok');
}

function closeChatView() {
  if (active) endChat(active, 'Vous avez quitté la conversation.');
  clearLog();
  ui.safetyCode.textContent = '';
  unread = 0;
  updateTitle();
  show('lobby');
}

const WEBRTC_OFF = /firefox/i.test(navigator.userAgent)
  ? 'Les connexions directes (WebRTC) sont désactivées dans ce Firefox. Ouvrez about:config, passez « media.peerconnection.enabled » à true, puis rechargez la page. Si le réglage est déjà à true, une extension de confidentialité bloque WebRTC : désactivez-la pour ce site.'
  : 'Les connexions directes (WebRTC) sont désactivées dans ce navigateur, par un réglage ou une extension de confidentialité. Réactivez-les pour ce site, puis rechargez la page.';

const PEER_ERRORS = {
  'peer-unavailable': 'Ce contact n’est pas en ligne. Vous devez avoir tous les deux la page ouverte en même temps.',
  'unavailable-id': 'Murmure est déjà ouvert dans un autre onglet ou une autre fenêtre de ce navigateur.',
  'browser-incompatible': WEBRTC_OFF,
  network: 'Service de mise en relation injoignable. Vérifiez votre connexion internet.',
  'server-error': 'Service de mise en relation injoignable. Réessayez plus tard.',
  'socket-error': 'Service de mise en relation injoignable. Réessayez plus tard.',
  'socket-closed': 'Service de mise en relation injoignable. Réessayez plus tard.',
};

function startPeer() {
  peer = new Peer(identity.peerId, CONFIG.peerOptions);

  peer.on('open', () => {
    ready = true;
    ui.myLink.value = `${location.origin}${location.pathname}#${identity.peerId}`;
    ui.copy.disabled = false;
    ui.joinButton.disabled = false;
    if (!active) setStatus('En ligne — en attente d’un contact', 'ok');
    if (pendingInvite) {
      const invite = pendingInvite;
      pendingInvite = null;
      connectTo(invite);
    }
  });

  peer.on('connection', attach);

  peer.on('disconnected', () => {
    ready = false;
    if (!active) setStatus('Reconnexion…', 'wait');
    setTimeout(() => {
      if (peer && !peer.destroyed && peer.disconnected) peer.reconnect();
    }, 3000);
  });

  peer.on('error', (err) => {
    const message = PEER_ERRORS[err?.type] || 'Erreur de connexion.';
    if (err?.type === 'peer-unavailable') {
      if (active && !active.session) endChat(active, message);
      return;
    }
    if (active?.session) return; // la conversation directe en cours n'est pas affectée
    if (active) endChat(active, message);
    else setNotice(message);
    setStatus('Hors ligne', 'error');
  });
}

// ---------- Actions de l'utilisateur ----------

ui.copy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(ui.myLink.value);
  } catch {
    ui.myLink.select();
    document.execCommand('copy');
  }
  ui.copy.textContent = 'Copié';
  setTimeout(() => { ui.copy.textContent = 'Copier'; }, 1500);
});

ui.join.addEventListener('submit', (event) => {
  event.preventDefault();
  connectTo(ui.peerInput.value);
});

ui.cancel.addEventListener('click', () => {
  if (active) endChat(active, '');
});

ui.leave.addEventListener('click', closeChatView);

ui.verify.addEventListener('click', () => {
  if (!active?.session) return;
  rememberVerified(active.session.peerFingerprint);
  setVerified(true);
  addSystem('Contact marqué comme vérifié sur cet appareil.');
});

ui.composer.addEventListener('submit', (event) => {
  event.preventDefault();
  const chat = active;
  const text = ui.text.value.trim();
  if (!chat?.session || !text) return;
  if (text.length > CONFIG.maxLength) return;
  ui.text.value = '';
  ui.text.style.height = '';
  const node = addMessage('me', text);
  ui.log.scrollTop = ui.log.scrollHeight;
  // File d'envoi : les messages partent dans l'ordre où ils ont été écrits.
  chat.outbox = chat.outbox
    .then(() => sendItem(chat, KIND.text, te.encode(text)))
    .catch(() => {
      node.classList.add('failed');
      node.title = 'Non envoyé';
    });
});

ui.text.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    ui.composer.requestSubmit();
  }
});

ui.text.addEventListener('input', () => {
  ui.text.style.height = 'auto';
  ui.text.style.height = `${Math.min(ui.text.scrollHeight + 2, 140)}px`;
});

ui.photo.addEventListener('click', () => ui.photoInput.click());

ui.photoInput.addEventListener('change', () => {
  const [file] = ui.photoInput.files;
  ui.photoInput.value = ''; // permet de renvoyer la même photo
  sendPhoto(file);
});

// Coller une image dans la zone de texte, ou la glisser sur la conversation.
ui.text.addEventListener('paste', (event) => {
  const file = [...(event.clipboardData?.files || [])].find((f) => f.type.startsWith('image/'));
  if (!file) return;
  event.preventDefault();
  sendPhoto(file);
});

ui.chat.addEventListener('dragover', (event) => {
  if (!active?.session || !event.dataTransfer?.types.includes('Files')) return;
  event.preventDefault();
  ui.chat.classList.add('dropping');
});
ui.chat.addEventListener('dragleave', () => ui.chat.classList.remove('dropping'));
ui.chat.addEventListener('drop', (event) => {
  ui.chat.classList.remove('dropping');
  if (!event.dataTransfer?.files.length) return;
  event.preventDefault();
  sendPhoto(event.dataTransfer.files[0]);
});

ui.reset.addEventListener('click', async () => {
  if (!confirm('Créer une nouvelle identité ? Votre lien actuel ne fonctionnera plus et vos contacts devront revérifier le code de sécurité.')) return;
  try {
    await dbRun('readwrite', (store) => store.delete('identity'));
    localStorage.removeItem('murmure.verified');
  } catch { /* rien à effacer */ }
  location.replace(location.pathname);
});

function readInvite() {
  const id = parsePeerId(location.hash);
  if (!location.hash) return;
  history.replaceState(null, '', location.pathname); // l'invitation ne reste pas dans la barre d'adresse
  if (!id) return setNotice('Ce lien ne ressemble pas à une invitation Murmure.');
  if (ready) connectTo(id);
  else pendingInvite = id;
}

window.addEventListener('hashchange', readInvite);

window.addEventListener('beforeunload', (event) => {
  if (active?.session) event.preventDefault(); // évite de perdre la conversation par un rechargement accidentel
});

// ---------- Démarrage ----------

async function start() {
  if (!window.isSecureContext || !globalThis.crypto?.subtle) {
    setStatus('Indisponible', 'error');
    return setNotice('Murmure a besoin d’une page servie en HTTPS (GitHub Pages convient) pour chiffrer les messages.');
  }
  if (typeof Peer === 'undefined') {
    setStatus('Indisponible', 'error');
    return setNotice('Le fichier vendor/peerjs.min.js n’a pas été chargé. Vérifiez que le dossier « vendor » est bien présent dans le dépôt, puis rechargez la page.');
  }
  if (!window.RTCPeerConnection) {
    setStatus('Indisponible', 'error');
    return setNotice(WEBRTC_OFF);
  }
  try {
    identity = await loadIdentity();
  } catch {
    setStatus('Indisponible', 'error');
    return setNotice('Impossible de créer les clés de chiffrement dans ce navigateur.');
  }
  setStatus('Connexion…', 'wait');
  readInvite();
  startPeer();
}

start();
