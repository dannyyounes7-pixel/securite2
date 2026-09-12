# Fiches d'attaques — TP Réel Chapitre 2 (v2)

Support théorique à donner en amont ou en complément du TP. Chaque fiche : mécanisme, catégorie OWASP, pourquoi c'est dangereux, comment ça se corrige.

---

## SQL Injection (V1, V2)

**Mécanisme** : l'application construit une requête SQL en concaténant directement une entrée utilisateur dans la chaîne de requête. L'attaquant insère des fragments SQL (`' OR '1'='1`, `UNION SELECT`) qui modifient la logique de la requête telle qu'interprétée par le moteur de base de données.

**Variantes** :
- *In-band* (erreur ou union-based) : le résultat de l'injection est visible directement dans la réponse.
- *Blind* (booléenne) : seule une différence de comportement (page différente) trahit le résultat.
- *Time-based blind* : aucune différence visible, mais un délai de réponse mesurable (`SLEEP()`) confirme l'injection quand rien d'autre n'est observable.

**OWASP** : A03:2021 — Injection.

**Pourquoi c'est dangereux** : accès en lecture (voire écriture/suppression) à toute la base, contournement total de l'authentification, parfois exécution de commandes système selon le SGBD et sa configuration.

**Correction** : requêtes paramétrées / préparées systématiquement (jamais de concaténation ou de formatage de chaîne dans du SQL), principe du moindre privilège pour le compte de connexion à la base, ORM avec échappement automatique en dernier recours.

---

## Cross-Site Scripting — XSS réfléchie et stockée (V3, V4)

**Mécanisme** : une entrée utilisateur est réinjectée dans le HTML de la réponse sans échappement. Le navigateur de la victime interprète alors cette entrée comme du code exécutable plutôt que comme du texte.

- *Réfléchie* : le payload transite dans la requête (paramètre d'URL) et doit être renvoyé à la victime via un lien piégé — nécessite une action de la victime (cliquer sur un lien).
- *Stockée* : le payload est enregistré côté serveur (ici, un commentaire) et s'exécute pour **tout** visiteur de la page, sans action supplémentaire — impact plus large.

**OWASP** : A03:2021 — Injection (XSS y est classé depuis 2021, anciennement catégorie séparée).

**Pourquoi c'est dangereux** : vol de cookies de session, actions effectuées à l'insu de la victime avec ses droits, defacement, keylogging JavaScript.

**Correction** : échappement systématique en sortie (auto-échappement des moteurs de template comme Jinja2), Content-Security-Policy pour limiter l'exécution de scripts inline, cookies `HttpOnly` pour rendre le cookie de session inaccessible en JavaScript même en cas de XSS réussie.

---

## CSRF — Cross-Site Request Forgery (V5)

**Mécanisme** : une action qui modifie un état côté serveur (ici, déclencher un export) est acceptée sans preuve que la requête émane bien d'une action volontaire de l'utilisateur authentifié. Un site tiers malveillant peut donc forger un formulaire qui soumet automatiquement une requête vers l'application ciblée ; le navigateur de la victime y joint son cookie de session valide.

**OWASP** : A01:2021 — Broken Access Control (le CSRF a été fusionné dans cette catégorie en 2021).

**Pourquoi c'est dangereux** : exécution d'actions au nom de la victime (ici, exfiltration de données vers un email choisi par l'attaquant) sans jamais voler ses identifiants.

**Correction** : token CSRF unique par session/formulaire vérifié côté serveur, vérification de l'en-tête `Origin`/`Referer` en complément, attribut de cookie `SameSite=Lax` ou `Strict`.

---

## Politique de mot de passe faible (V6)

**Mécanisme** : absence de contrôle de complexité, de longueur minimale ou de vérification contre des listes de mots de passe compromis à l'inscription.

**OWASP** : A07:2021 — Identification and Authentication Failures.

**Pourquoi c'est dangereux** : élargit considérablement la surface d'attaque par brute force/dictionnaire ; combiné à l'absence de rate limiting (V7), rend le cassage quasi immédiat.

**Correction** : longueur minimale (12+ caractères recommandé plutôt que complexité artificielle), vérification contre une liste de mots de passe compromis (API HaveIBeenPwned range), hachage fort (`argon2`/`bcrypt`), jamais de stockage en clair.

---

## Absence de rate limiting / brute force (V7)

**Mécanisme** : aucune limite sur le nombre de tentatives de connexion par compte ou par IP dans un intervalle de temps donné.

**OWASP** : A07:2021 — Identification and Authentication Failures.

**Pourquoi c'est dangereux** : permet le brute force ou le credential stuffing (rejouer des couples identifiant/mot de passe fuités ailleurs) à un rythme illimité.

**Correction** : limitation de débit par IP/compte (`flask-limiter`), verrouillage temporaire progressif après N échecs, CAPTCHA après seuil, alerting sur pics de tentatives.

---

## Information Disclosure (Bonus)

**Mécanisme** : un endpoint expose plus de données que nécessaire à sa fonction, sans restriction d'accès ni filtrage des champs sensibles (ici, les mots de passe en clair de tous les utilisateurs).

**OWASP** : A01:2021 — Broken Access Control / A02:2021 — Cryptographic Failures (stockage en clair).

**Pourquoi c'est dangereux** : compromission massive et immédiate en un seul appel, sans avoir besoin d'exploiter une autre faille au préalable.

**Correction** : contrôle d'accès par rôle sur l'endpoint, principe du moindre privilège sur les champs retournés (DTO explicite plutôt que dump direct de la table), ne jamais stocker ni exposer un mot de passe en clair.

---

## NOUVEAU — IDOR : Insecure Direct Object Reference (V8)

**Mécanisme** : l'application utilise un identifiant fourni par le client (ici, l'id dans l'URL) pour retrouver une ressource, sans vérifier que l'utilisateur courant a le droit d'y accéder. Il suffit d'incrémenter ou deviner l'id pour accéder aux ressources d'autrui.

**OWASP** : A01:2021 — Broken Access Control.

**Pourquoi c'est dangereux** : très facile à découvrir (simple énumération d'id), souvent sous-estimé car il n'implique aucune "injection" technique — juste un contrôle métier absent. Impact proportionnel à la sensibilité des ressources exposées.

**Correction** : vérifier systématiquement, côté serveur, que la ressource demandée appartient à l'utilisateur courant ou que son rôle l'y autorise, avant de la renvoyer — jamais se fier uniquement à la difficulté de deviner l'id.

---

## NOUVEAU — Path Traversal (V9)

**Mécanisme** : un nom de fichier fourni par le client est utilisé pour construire un chemin d'accès disque sans normalisation ni validation. Des séquences `../` permettent de remonter en dehors du répertoire prévu et de lire (voire écrire) des fichiers arbitraires accessibles au processus.

**OWASP** : A01:2021 — Broken Access Control (parfois classé A05 — Security Misconfiguration selon le contexte).

**Pourquoi c'est dangereux** : peut exposer du code source, des fichiers de configuration, des secrets, voire des fichiers système selon les droits du processus serveur.

**Correction** : ne jamais construire un chemin à partir d'une entrée utilisateur brute ; utiliser un identifiant opaque (mappé côté serveur vers un chemin fixe) plutôt qu'un nom de fichier ; si un nom de fichier est indispensable, normaliser le chemin (`os.path.realpath`) et vérifier qu'il reste strictement à l'intérieur du répertoire autorisé avant tout accès disque.

---

## NOUVEAU — Mass Assignment (V10)

**Mécanisme** : l'application lie directement les champs reçus dans une requête à un objet ou une insertion en base, sans liste blanche explicite des champs autorisés. Un attaquant ajoute un champ non prévu par l'interface (ici, `role`) qui se retrouve néanmoins traité par le serveur.

**OWASP** : A08:2021 — Software and Data Integrity Failures (ou A04 — Insecure Design selon la classification retenue).

**Pourquoi c'est dangereux** : permet une élévation de privilège directe dès l'inscription, sans avoir besoin d'exploiter une autre faille pour obtenir un rôle élevé.

**Correction** : liste blanche explicite des champs acceptés à chaque endpoint d'écriture (jamais un `**request.form` généralisé), valeurs sensibles (rôle, statut, prix...) assignées uniquement côté serveur ou via un endpoint d'administration séparé et protégé.

---

## NOUVEAU — Open Redirect (V11)

**Mécanisme** : un paramètre contrôlé par le client (`next`) est utilisé tel quel comme cible de redirection après une action légitime (ici, une connexion réussie), sans vérifier qu'il pointe vers une ressource interne à l'application.

**OWASP** : A01:2021 — Broken Access Control (souvent aussi référencé comme faiblesse de validation d'entrée, CWE-601).

**Pourquoi c'est dangereux** : seul, l'impact est limité — mais combiné à un domaine de confiance (un lien `datacorp.local/login?next=...` inspire confiance car le domaine visible est légitime), c'est un vecteur de phishing redoutablement efficace, en particulier pour voler des identifiants sur une fausse page de destination.

**Correction** : n'accepter que des chemins relatifs internes comme cible de redirection (liste blanche ou vérification stricte que l'URL ne contient pas de schéma/domaine externe), ou utiliser un identifiant de destination mappé côté serveur plutôt qu'une URL brute.

---

## Synthèse — familles OWASP couvertes par le TP v2

| Catégorie OWASP Top 10 (2021) | Vulnérabilités du TP |
|---|---|
| A01 — Broken Access Control | V5 (CSRF), V8 (IDOR), V9 (Path Traversal), V11 (Open Redirect), Bonus |
| A02 — Cryptographic Failures | Bonus (mdp en clair) |
| A03 — Injection | V1, V2 (SQLi), V3, V4 (XSS) |
| A04 — Insecure Design | V10 (Mass Assignment) |
| A07 — Identification and Authentication Failures | V6 (mdp faible), V7 (rate limiting) |

Le passage de la v1 à la v2 fait entrer le TP dans 5 catégories du Top 10 au lieu de 3 — bon argument pédagogique si vous voulez justifier l'extension auprès de vos étudiants ou d'un comité de programme.
