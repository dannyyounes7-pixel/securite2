# ✅ Checklist — TP Réel Chapitre 2

Cochez chaque élément avant de rendre votre rapport.

## Phase 1 — Reconnaissance

- [ ] Tous les endpoints de l'application listés (`/login`, `/search`, `/comments`, `/api/comments`, `/export`, `/api/users`, `/register`, `/dashboard`, `/logout`)
- [ ] Technologies identifiées (Flask, SQLite en mémoire, cookies de session)
- [ ] Comptes de test répertoriés
- [ ] Cartographie des endpoints authentifiés vs publics

## Phase 2 — Exploitation (les 7 vulnérabilités)

- [ ] **Vuln 1** — SQL Injection / Authentication bypass (`/login`) exploitée et décrite
- [ ] **Vuln 2** — SQL Injection dans `/search` (OR-based, UNION, time-based) exploitée
- [ ] **Vuln 3** — Reflected XSS dans `/search` exploitée
- [ ] **Vuln 4** — Stored XSS dans `/comments` / `/api/comments` exploitée
- [ ] **Vuln 5** — CSRF sur `/export` exploitée (formulaire de démonstration inclus)
- [ ] **Vuln 6** — Politique de mot de passe faible démontrée
- [ ] **Vuln 7** — Absence de rate limiting démontrée (brute force)
- [ ] Bonus — Information disclosure via `/api/users` notée

## Phase 3 — Preuves de concept (PoC)

- [ ] Capture d'écran ou sortie de commande pour chaque vulnérabilité
- [ ] Payload exact utilisé documenté pour chaque cas
- [ ] Impact décrit pour chaque vulnérabilité (que peut faire un attaquant concrètement ?)

## Phase 4 — Plan de correction

- [ ] Matrice de sévérité (impact x probabilité) pour les 7 vulnérabilités
- [ ] Priorisation MoSCoW (Must / Should / Could / Won't) justifiée
- [ ] Effort de correction estimé pour chaque vulnérabilité
- [ ] Recommandations techniques concrètes (ex : prepared statements, échappement HTML, tokens CSRF, `bcrypt`/`argon2`, limitation de débit, politique de mot de passe)

## Rapport final

- [ ] Nom de fichier au format `TP_REEL_Secu1_Chapitre2_[NOM]_[PRENOM].md`
- [ ] Longueur cohérente (12–18 pages)
- [ ] Structure claire suivant les 4 phases
- [ ] Relecture orthographique et cohérence terminologique
- [ ] Aucune donnée sensible réelle utilisée (uniquement l'environnement de test local)
