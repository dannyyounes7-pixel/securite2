# TP Réel Chapitre 2 — README détaillé

**Penetration Testing & Vulnerability Assessment — DataCorp Analytics**

---

## ⚠️ Avertissement

Cette application (`app.py`) est **intentionnellement vulnérable** à des fins pédagogiques uniquement. Ne la déployez jamais sur un réseau exposé à Internet, et ne réutilisez jamais ce code dans un projet réel.

---

## 1. Prérequis

- Docker + Docker Compose (recommandé), **ou** Python 3.10+ en local
- `curl` (déjà présent sur macOS/Linux ; sur Windows utilisez Git Bash ou WSL)
- Un navigateur web
- Optionnel : Python `requests` si vous utilisez `exploit.py`

## 2. Lancer l'application

### Option A — Docker (recommandé)

```bash
cd tp-reel-secu1-chapitre2/
docker-compose up -d
docker-compose logs -f          # voir les logs en direct
```

Vérifiez que ça tourne :

```bash
curl -i http://localhost:5000/
```

Pour arrêter :

```bash
docker-compose down
```

### Option B — Sans Docker (Python local)

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

L'application écoute sur `http://localhost:5000`.

## 3. Comptes de test

| Utilisateur     | Mot de passe | Rôle                     |
|------------------|--------------|---------------------------|
| `admin`          | `password123`| Administrateur             |
| `analyst`        | `123456`     | Analyste                   |
| `datascientist`  | `analyst`    | Data scientist              |

Ces mots de passe sont volontairement faibles (vulnérabilité 6).

## 4. Endpoints de l'application

| Endpoint            | Méthode(s)   | Description                              |
|----------------------|--------------|--------------------------------------------|
| `/login`             | GET, POST    | Authentification (SQLi)                     |
| `/register`          | GET, POST    | Création de compte (pas de politique de mdp)|
| `/dashboard`         | GET          | Tableau de bord (authentifié)               |
| `/search`            | GET          | Recherche de données (SQLi + Reflected XSS) |
| `/comments`          | GET          | Page de commentaires (Stored XSS)           |
| `/api/comments`      | GET, POST    | API commentaires (Stored XSS)               |
| `/export`            | GET, POST    | Export de données (CSRF)                    |
| `/api/users`         | GET          | Liste des utilisateurs (info disclosure)    |
| `/logout`            | GET          | Déconnexion                                  |

## 5. Comment tester chaque vulnérabilité

### 5.1 SQLi — Authentication bypass (`/login`)
Payload classique : `admin' OR '1'='1--` dans le champ `username`, mot de passe quelconque. Le point faible est la concaténation directe de chaîne dans la requête SQL (voir `app.py`, route `/login`).

### 5.2 SQLi — Extraction de données (`/search`)
Le paramètre `q` est injecté tel quel dans un `LIKE '%...%'`. Testez `' OR '1'='1` pour tout retourner, ou une `UNION SELECT` pour extraire la table `users`.

### 5.3 XSS réfléchie (`/search`)
La valeur de `q` est réinjectée dans le HTML sans échappement. Testez `<script>alert('XSS')</script>`.

### 5.4 XSS stockée (`/comments`, `/api/comments`)
Le champ `comment` n'est ni validé ni échappé à l'affichage. Postez un payload avec `onerror`, il se déclenchera pour tout visiteur de `/comments`.

### 5.5 CSRF (`/export`)
Aucun token CSRF n'est vérifié sur le POST. Un formulaire hébergé sur un site tiers peut déclencher un export au nom d'une victime connectée.

### 5.6 Politique de mot de passe faible (`/register`)
Aucune vérification de complexité : `123`, `password`, etc. sont acceptés.

### 5.7 Absence de rate limiting (`/login`)
Aucune limite de tentatives, ni CAPTCHA, ni verrouillage de compte : le brute force est possible.

### Bonus — Information disclosure (`/api/users`)
Renvoie tous les utilisateurs, mots de passe en clair inclus.

## 6. Scripts fournis

| Fichier               | Usage                                            |
|-------------------------|---------------------------------------------------|
| `exploit.py`           | `python3 exploit.py` — suite complète en Python    |
| `exploit.sh`            | `bash exploit.sh` — équivalent en Bash             |
| `exploit.ps1`           | `.\exploit.ps1` — équivalent en PowerShell (Windows)|
| `curl_commands.sh`      | Commandes curl à copier-coller manuellement        |

## 7. Dépannage

**Port 5000 déjà utilisé**
```bash
lsof -i :5000        # trouver le processus
kill -9 <PID>
```
Ou changez le port dans `docker-compose.yml` (`"5001:5000"`).

**Docker non accessible**
Relancez Docker Desktop, ou utilisez l'option B (Python local).

**curl retourne du HTML au lieu de JSON**
Certaines routes renvoient du HTML par défaut ; utilisez `/api/comments` ou `/api/users` pour du JSON pur.

**SQLi qui ne fonctionne pas**
Vérifiez l'encodage de vos guillemets et apostrophes dans l'URL (`--data-urlencode` avec curl gère cela automatiquement).

## 8. Livrable attendu

Un rapport `TP_REEL_Secu1_Chapitre2_[NOM]_[PRENOM].md` couvrant les 4 phases (Reconnaissance, Exploitation, PoC, Plan de correction), voir `TP_REEL_Secu1_Chapitre2_Sujet.md` pour la structure attendue et `CHECKLIST_TP_REEL_Ch2.md` pour vérifier que rien ne manque avant de rendre.
