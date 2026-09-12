# TP Réel — Chapitre 2 : Livrables Phase 4 (à remplir par l'étudiant)

> Ce template correspond aux Phases 3 et 4 de la checklist (`CHECKLIST_TP_REEL_Ch2.md`). Il ne contient aucune réponse — à compléter à partir de votre propre exploitation de `app.py` et des ressources de contexte fournies (`TP_Reel_Ressources_Contexte.md`).

---

## Phase 3 — Preuve de concept et scénario chaîné

Pour chaque vulnérabilité exploitée, complétez :

| Vulnérabilité | Payload exact utilisé | Commande / capture | Impact concret (que peut faire un attaquant ?) |
|---|---|---|---|
| V1 — SQLi auth bypass |  |  |  |
| V2 — SQLi `/search` |  |  |  |
| V3 — XSS réfléchie |  |  |  |
| V4 — XSS stockée |  |  |  |
| V5 — CSRF `/export` |  |  |  |
| V6 — Politique mdp faible |  |  |  |
| V7 — Pas de rate limiting |  |  |  |
| Bonus — Info disclosure |  |  |  |

**Scénario d'attaque chaîné** (au moins 2 vulnérabilités reliées, avec diagramme façon Recon → Accès → Escalade → Impact) :

- Étape 1 : ______
- Étape 2 : ______
- Étape 3 : ______
- Impact global du scénario (supérieur à la somme des vulnérabilités isolées ? pourquoi) : ______

---

## Phase 4 — Matrice d'impact × probabilité

Remplissez Impact et Probabilité (1 à 5 chacun) pour les 7 vulnérabilités + bonus, à partir de votre propre exploitation — vos scores peuvent différer du TP Guidé, justifiez-les.

| Vulnérabilité | Impact (1-5) | Probabilité (1-5) | Criticité (I×P) |
|---|---|---|---|
| V1 — SQLi auth bypass |  |  |  |
| V2 — SQLi `/search` |  |  |  |
| V3 — XSS réfléchie |  |  |  |
| V4 — XSS stockée |  |  |  |
| V5 — CSRF `/export` |  |  |  |
| V6 — Politique mdp faible |  |  |  |
| V7 — Pas de rate limiting |  |  |  |
| Bonus — Info disclosure |  |  |  |

Questions :
- Quelle vulnérabilité obtient le score le plus élevé ? Justifiez à partir de vos valeurs individuelles.
- En intégrant le journal d'accès fourni (entrées 14-18), un risque vous semble-t-il sous-estimé par rapport à une analyse purement applicative ?

Matrice 9-box (probabilité × impact) — à tracer :

```
Impact
Élevé   |        |        |        |
Moyen   |        |        |        |
Faible  |        |        |        |
        Faible   Moyen    Élevé      Probabilité
```

---

## Plan de correction

| Vulnérabilité | Cause racine identifiée | Recommandation technique | Effort estimé | MoSCoW |
|---|---|---|---|---|
| V1 |  |  |  |  |
| V2 |  |  |  |  |
| V3 |  |  |  |  |
| V4 |  |  |  |  |
| V5 |  |  |  |  |
| V6 |  |  |  |  |
| V7 |  |  |  |  |
| Bonus |  |  |  |  |

Justification de la priorisation Must :

______

---

## Rendu

- Nom de fichier : `TP_REEL_Secu1_Chapitre2_[NOM]_[PRENOM].md`
- 12-18 pages, 4 phases visibles, relecture faite
- Aucune donnée réelle utilisée (environnement local uniquement)
