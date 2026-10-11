// Murmure — interface et connexion pair-à-pair.
// Le chiffrement est dans crypto.js ; ce fichier ne fait transiter que des messages déjà chiffrés.

import * as E2E from './crypto.js';

const CONFIG = {
  // Options passées à PeerJS. Vide = serveur public de mise en relation (0.peerjs.com).
  // Pour votre propre serveur : { host: 'exemple.org', port: 443, path: '/', secure: true }
  // (pensez alors à adapter « connect-src » dans index.html).
  peerOptions: {},
  maxLength: 4000,
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

function atBottom() {
  return ui.log.scrollHeight - ui.log.scrollTop - ui.log.clientHeight < 60;
}

function append(node) {
  const stick = atBottom();
  ui.log.append(node);
  if (stick) ui.log.scrollTop = ui.log.scrollHeight;
}

function addMessage(who, text) {
  const node = document.createElement('div');
  node.className = `msg ${who}`;
  node.textContent = text; // textContent : le contenu reçu n'est jamais interprété comme du HTML
  const time = document.createElement('time');
  time.textContent = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  node.append(time);
  append(node);
  return node;
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

  const chat = { conn, session: null, closed: false, inbox: Promise.resolve(), outbox: Promise.resolve(), timer: null };
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
      .catch(() => endChat(chat, 'Un message invalide a été reçu : la conversation a été coupée par sécurité.'));
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
    const text = await chat.session.decrypt(data);
    if (chat.closed) return;
    addMessage('them', text);
    if (document.hidden) {
      unread += 1;
      updateTitle();
    }
  }
}

function openChat(chat) {
  ui.log.replaceChildren();
  ui.safetyCode.textContent = chat.session.safetyCode;
  const known = verifiedContacts().includes(chat.session.peerFingerprint);
  setVerified(known);
  ui.text.disabled = false;
  ui.composer.querySelector('button').disabled = false;
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
    ui.text.disabled = true;
    ui.composer.querySelector('button').disabled = true;
    ui.leave.textContent = 'Fermer';
  } else {
    show('lobby');
    setNotice(reason);
  }
  if (ready) setStatus('En ligne — en attente d’un contact', 'ok');
}

function closeChatView() {
  if (active) endChat(active, 'Vous avez quitté la conversation.');
  ui.log.replaceChildren(); // l'historique n'est conservé nulle part
  ui.safetyCode.textContent = '';
  unread = 0;
  updateTitle();
  show('lobby');
}

const PEER_ERRORS = {
  'peer-unavailable': 'Ce contact n’est pas en ligne. Vous devez avoir tous les deux la page ouverte en même temps.',
  'unavailable-id': 'Murmure est déjà ouvert dans un autre onglet ou une autre fenêtre de ce navigateur.',
  'browser-incompatible': 'Ce navigateur ne permet pas les connexions directes (WebRTC).',
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
    .then(async () => {
      const packet = await chat.session.encrypt(text);
      if (chat.closed) throw new Error('fermée');
      chat.conn.send(packet);
    })
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
  if (!window.RTCPeerConnection || typeof Peer === 'undefined') {
    setStatus('Indisponible', 'error');
    return setNotice('Ce navigateur ne permet pas les connexions directes (WebRTC).');
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
