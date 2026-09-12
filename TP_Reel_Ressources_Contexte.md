# TP Réel — Chapitre 2 : Ressources de contexte DataCorp Analytics

> À distribuer aux étudiants en complément de `app.py` / `docker-compose.yml`. Ces ressources situent l'application vulnérable dans l'environnement DataCorp déjà étudié au TP Guidé (même entreprise, même chaîne de valeur, même registre d'incidents).

---

## 1. Schéma de la chaîne de valeur — où se situe l'application testée

```
        Domaine transverse : Accès & identités (comptes, IAM, MFA)
        ────────────────────────────────────────────────────────
Ingestion  →  Stockage  →  Traitement  →  Restitution
(flux clients) (S3 + SQL)  (jobs batch)  (app DataCorp Analytics ← VOUS ÊTES ICI)
        ────────────────────────────────────────────────────────
        Domaine transverse : Facteur humain (phishing, erreurs, prestataires)
```

`app.py` correspond à la brique **Restitution** de la chaîne de valeur étudiée au TP Guidé Chapitre 2 : c'est l'interface par laquelle les analystes internes (rôles `analyst`, `datascientist`) consultent les données déjà traitées et les exportent vers des destinataires externes via `/export`.

Deux points de couplage avec les autres briques, à noter dans votre rapport :
- **Stockage** : le bouton "Exporter" (`/export`) écrit dans le même bucket S3 que celui audité au TP Guidé (`datacorp-exports`, cf. section 2 ci-dessous).
- **Accès & identités** : la table `users` de l'application est un sous-ensemble du registre de comptes du chapitre 1 (les rôles `admin`, `analyst`, `datascientist` correspondent aux comptes A-02, A-03, A-04 du registre).

---

## 2. Extrait de configuration du stockage cloud — bucket `datacorp-exports`

Extrait de la policy du bucket S3 vers lequel `/export` envoie les fichiers générés (config volontairement dégradée, cohérente avec le risque "Bucket public" identifié au TP Guidé, score de criticité 20/25) :

```json
{
  "Bucket": "datacorp-exports",
  "BlockPublicAccess": {
    "BlockPublicAcls": false,
    "IgnorePublicAcls": false,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
  },
  "PolicyStatement": [
    {
      "Sid": "AllowExportWrite",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::datacorp-exports",
        "arn:aws:s3:::datacorp-exports/*"
      ]
    }
  ],
  "ServerSideEncryption": "None",
  "VersioningStatus": "Disabled"
}
```

Point de réflexion à faire figurer dans votre analyse (Phase 3, section Impact) : la vulnérabilité CSRF de `/export` (V5) ne se contente pas de déclencher un export non autorisé — le fichier généré atterrit dans un bucket accessible en lecture publique (`Principal: "*"`, Block Public Access désactivé). Cela transforme une CSRF "classique" en fuite de données potentiellement massive et durable (le fichier reste accessible après l'attaque). C'est un bon exemple de chaînage vuln applicative → vuln infrastructure à décrire dans votre scénario chaîné (cf. section 3 du guide fusionné).

---

## 3. Journal simplifié des accès récents

| # | Horodatage | Compte / IP | Action | Résultat |
|---|---|---|---|---|
| 1-13 | 01/03 – 11/03 | analyst, datascientist, admin | Connexions normales, recherches, consultations dashboard | Succès |
| 14 | 12/03 03:14:02–03:15:47 | IP inconnue → admin | 16 tentatives de connexion consécutives sur `/login` (mots de passe différents) | 15 échecs |
| 15 | 12/03 03:15:52 | IP inconnue → admin | Tentative de connexion suivante | **Succès** |
| 16 | 12/03 03:16:10 | admin (session issue de l'entrée 15) | `POST /export` format=csv | Succès — fichier écrit dans `datacorp-exports` |
| 17 | 12/03 04:02:18 | IP 91.208.45.12 (anonyme, hors VPN) | `GET` sur le bucket `datacorp-exports` | Lecture autorisée (bucket public) |
| 18 | 15/03 | prestataire-ext03 (mission terminée le 28/02) | Lecture sur `dc-prod-db` | Succès — compte non révoqué |
| 19 | 18/03 | s.mercier | 2 sessions simultanées depuis des IP différentes | Anomalie non investiguée |
| 20 | 20/03 | analyst | Recherche `/search?q=rapport` | Succès (usage normal) |

Ce journal est volontairement le même registre que celui référencé dans le corrigé du TP Guidé (entrées 14-18, IP 91.208.45.12, prestataire-ext03, s.mercier) : les étudiants qui ont suivi les deux TP doivent reconnaître la continuité et comprendre que **l'entrée 14-16 est la trace exacte de l'attaque qu'ils viennent de reproduire eux-mêmes** en Phase 2 (brute force sur `/login`, éventuellement combiné à la SQLi V1, suivi d'un export CSRF V5). C'est l'occasion de leur faire remarquer que le TP Guidé (analyse à froid d'un journal) et le TP Réel (exploitation à chaud) décrivent le même incident sous deux angles différents.

Question à ajouter à votre rapport, section Phase 1 (recon) : à partir de ce journal, à quel moment un SOC aurait-il pu détecter l'attaque avant l'export (entrée 16) ? Quel contrôle (rate limiting, alerte sur volume de tentatives, MFA) aurait cassé la chaîne à quelle étape ?
