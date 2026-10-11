# Murmure

Messagerie chiffrée de bout en bout qui tient dans une page web statique. Pas de compte, pas de numéro de téléphone, pas de serveur à administrer : elle s'héberge gratuitement sur GitHub Pages.

- Les messages sont chiffrés dans le navigateur de l'expéditeur et déchiffrés dans celui du destinataire.
- Ils circulent directement d'un navigateur à l'autre (WebRTC).
- Rien n'est enregistré : l'historique disparaît à la fermeture de la conversation.

## Mise en ligne sur GitHub Pages

1. Créez un dépôt sur GitHub (public, ou privé si votre offre le permet pour Pages).
2. Déposez-y tous les fichiers de ce dossier, à la racine : `index.html`, `app.js`, `crypto.js`, `style.css`, `.nojekyll` et le dossier `vendor/`.
3. Dans le dépôt : **Settings → Pages → Build and deployment**, choisissez **Deploy from a branch**, branche `main`, dossier `/ (root)`, puis **Save**.
4. Après une minute environ, l'application est disponible à l'adresse `https://VOTRE-NOM.github.io/NOM-DU-DEPOT/`.

Pour un essai sur votre ordinateur : `python3 -m http.server` dans ce dossier, puis ouvrez `http://localhost:8000` (ouvrir `index.html` directement en `file://` ne fonctionne pas).

## Utilisation

1. Ouvrez la page et copiez **votre lien d'invitation**.
2. Envoyez-le à votre contact. Il l'ouvre pendant que la page est ouverte chez vous : la conversation démarre.
3. Comparez le **code de sécurité** affiché en haut (30 chiffres) par un autre moyen : appel vocal, en personne. S'il est identique des deux côtés, cliquez sur « Codes identiques ». Le contact sera reconnu automatiquement les fois suivantes.

Votre lien reste le même d'une visite à l'autre dans le même navigateur. « Réinitialiser mon identité » en crée un nouveau.

## Ce que l'outil protège, et ses limites

**Protégé**

- Le contenu des messages : ni GitHub, ni le service de mise en relation, ni votre fournisseur d'accès ne peuvent le lire.
- L'intégrité : un message modifié, rejoué ou réordonné en chemin est rejeté et la conversation est coupée.
- L'usurpation, **à condition de comparer le code de sécurité**. Sans cette vérification, quelqu'un qui contrôle le service de mise en relation pourrait s'intercaler entre vous.
- Les conversations passées : chaque session utilise des clés jetables, détruites à la fermeture.

**Limites à connaître**

- **Ce n'est pas Signal.** Le code n'a pas fait l'objet d'un audit de sécurité indépendant. Pour un usage où une fuite aurait des conséquences graves, utilisez un outil audité.
- Les deux personnes doivent être en ligne en même temps. Pas de messages en attente, pas de notifications quand la page est fermée.
- Conversations à deux uniquement, une à la fois. Texte seulement.
- Les métadonnées ne sont pas cachées : le service de mise en relation (`0.peerjs.com`, serveur public du projet PeerJS) voit les identifiants et les adresses IP au moment de la connexion, et votre contact voit votre adresse IP. Derrière certains pare-feu, la connexion passe par un relais, qui ne voit que des données chiffrées.
- La taille approximative des messages est visible sur le réseau.
- Vous faites confiance au code servi par votre dépôt : quiconque peut le modifier peut modifier l'application. Protégez votre compte GitHub (double authentification).
- La clé d'identité est stockée dans le navigateur (non exportable). Une personne ayant accès à votre session sur l'appareil peut utiliser Murmure à votre place.

## Détails techniques

| Élément | Choix |
| --- | --- |
| Identité | ECDSA P-256, créée dans le navigateur, clé privée non exportable (IndexedDB) |
| Échange de clés | ECDH P-256 éphémère à chaque session, signé par la clé d'identité |
| Dérivation | HKDF-SHA-256, une clé distincte par sens d'envoi |
| Messages | AES-256-GCM, compteur strictement croissant |
| Code de sécurité | SHA-256 des deux clés d'identité, affiché en 30 chiffres |
| Transport | Canal de données WebRTC via [PeerJS](https://peerjs.com) 1.5.4 (copie locale dans `vendor/`, licence MIT) |

Tout le chiffrement repose sur l'API WebCrypto du navigateur ; il est regroupé dans `crypto.js` (environ 150 lignes) pour être relu facilement. Une politique de sécurité du contenu (CSP) dans `index.html` interdit tout script extérieur au dépôt.

### Utiliser votre propre serveur de mise en relation

Le serveur public PeerJS est gratuit mais sans garantie de disponibilité. Vous pouvez héberger [peerjs-server](https://github.com/peers/peerjs-server) ailleurs (GitHub ne fait pas tourner de serveur), puis :

1. renseigner `peerOptions` en haut de `app.js` ;
2. remplacer `0.peerjs.com` par votre domaine dans la ligne `Content-Security-Policy` de `index.html`.
