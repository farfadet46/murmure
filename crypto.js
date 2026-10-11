// Murmure — chiffrement de bout en bout (API WebCrypto du navigateur, aucune dépendance).
//
// Protocole, version 2 :
//   • Identité      : paire de clés ECDSA P-256, créée une fois et conservée dans le navigateur.
//   • Par session   : paire de clés ECDH P-256 éphémère, signée par la clé d'identité.
//   • Clés de session : ECDH -> HKDF-SHA-256 -> deux clés AES-256-GCM (une par sens).
//   • Trames        : AES-256-GCM, compteur strictement croissant (anti-rejeu).
//                     Texte et photos sont découpés en trames par app.js.
//   • Code de sécurité : empreinte des deux clés d'identité, à comparer entre contacts.

const PROTO = 'murmure-v2';
const VERSION = 2;
const POINT_LENGTH = 65; // point P-256 non compressé
const MAX_CIPHERTEXT_B64 = 64 * 1024;

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export function toB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(str) {
  if (typeof str !== 'string') throw new Error('champ manquant');
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function compare(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

async function sha256(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

function signedPart(ephPub) {
  return concat(te.encode(`${PROTO}|hello|`), ephPub);
}

/** Crée la paire de clés d'identité. La clé privée n'est pas exportable. */
export function createIdentity() {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

async function rawPublic(key) {
  return new Uint8Array(await subtle.exportKey('raw', key));
}

/** Prépare notre moitié de l'échange de clés pour une nouvelle session. */
export async function createOffer(identity) {
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const idPub = await rawPublic(identity.publicKey);
  const ephPub = await rawPublic(eph.publicKey);
  const sig = new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, signedPart(ephPub)),
  );
  return {
    ephPrivate: eph.privateKey,
    idPub,
    ephPub,
    hello: { t: 'hello', v: VERSION, id: toB64(idPub), eph: toB64(ephPub), sig: toB64(sig) },
  };
}

/** Termine l'échange à partir du « hello » reçu et renvoie la session chiffrée. */
export async function completeSession(offer, hello) {
  if (!hello || hello.v !== VERSION) {
    throw Object.assign(new Error('version de protocole différente'), { code: 'version' });
  }
  const theirId = fromB64(hello.id);
  const theirEph = fromB64(hello.eph);
  const theirSig = fromB64(hello.sig);
  if (theirId.length !== POINT_LENGTH || theirEph.length !== POINT_LENGTH) {
    throw new Error('clé publique mal formée');
  }
  // Refuse un « hello » qui ne serait que le nôtre renvoyé en miroir.
  if (compare(theirId, offer.idPub) === 0 || compare(theirEph, offer.ephPub) === 0) {
    throw new Error('clé identique à la nôtre');
  }

  const theirIdKey = await subtle.importKey('raw', theirId, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const signatureOk = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, theirIdKey, theirSig, signedPart(theirEph));
  if (!signatureOk) throw new Error('signature invalide');

  const theirEphKey = await subtle.importKey('raw', theirEph, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: theirEphKey }, offer.ephPrivate, 256);
  const master = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);

  // Les deux côtés doivent ordonner les clés de la même façon.
  const weAreLow = compare(offer.ephPub, theirEph) < 0;
  const low = weAreLow ? [offer.idPub, offer.ephPub] : [theirId, theirEph];
  const high = weAreLow ? [theirId, theirEph] : [offer.idPub, offer.ephPub];
  const salt = await sha256(concat(...low, ...high));

  const derive = (direction) =>
    subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(`${PROTO}|${direction}`) },
      master,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  const lowToHigh = await derive('low->high');
  const highToLow = await derive('high->low');

  const ids = compare(offer.idPub, theirId) < 0 ? [offer.idPub, theirId] : [theirId, offer.idPub];
  const digest = await sha256(concat(te.encode(`${PROTO}|safety|`), ...ids));
  const view = new DataView(digest.buffer);
  const groups = [];
  for (let i = 0; i < 6; i++) groups.push(String(view.getUint32(i * 4) % 100000).padStart(5, '0'));

  const fingerprint = Array.from(await sha256(theirId), (b) => b.toString(16).padStart(2, '0')).join('');

  return new Session(weAreLow ? lowToHigh : highToLow, weAreLow ? highToLow : lowToHigh, groups.join(' '), fingerprint);
}

const AAD = te.encode(`${PROTO}|msg`);

function nonce(counter) {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, BigInt(counter));
  return iv;
}

class Session {
  #sendKey;
  #receiveKey;
  #sent = 0;
  #received = 0;

  constructor(sendKey, receiveKey, safetyCode, peerFingerprint) {
    this.#sendKey = sendKey;
    this.#receiveKey = receiveKey;
    /** Code à comparer avec le contact (identique des deux côtés s'il n'y a pas d'interception). */
    this.safetyCode = safetyCode;
    /** Empreinte de la clé d'identité du contact. */
    this.peerFingerprint = peerFingerprint;
  }

  /** Chiffre une trame (Uint8Array). */
  async encrypt(bytes) {
    const n = ++this.#sent; // réservé avant tout « await » : jamais deux fois le même compteur
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv: nonce(n), additionalData: AAD }, this.#sendKey, bytes);
    return { t: 'msg', n, c: toB64(new Uint8Array(ct)) };
  }

  /** Déchiffre une trame et renvoie ses octets. */
  async decrypt(msg) {
    if (!Number.isSafeInteger(msg.n) || msg.n <= this.#received) throw new Error('message rejoué ou désordonné');
    if (typeof msg.c !== 'string' || msg.c.length > MAX_CIPHERTEXT_B64) throw new Error('message mal formé');
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: nonce(msg.n), additionalData: AAD }, this.#receiveKey, fromB64(msg.c));
    this.#received = msg.n;
    return new Uint8Array(pt);
  }
}
