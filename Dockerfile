# ============================================================================
# DataCorp Analytics - Dockerfile (v2)
# TP Réel Chapitre 2 - Application intentionnellement vulnérable
# USAGE PÉDAGOGIQUE UNIQUEMENT - NE JAMAIS DÉPLOYER EN PRODUCTION
# ============================================================================
FROM python:3.12-slim

LABEL maintainer="TP Réel Secu1 - Chapitre 2"
LABEL description="Application Flask intentionnellement vulnérable à des fins pédagogiques (v2 - édition enrichie)"
LABEL warning="NE PAS UTILISER EN PRODUCTION"

WORKDIR /app

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code de l'application (v2)
COPY app.py .

# Répertoire utilisé par la vulnérabilité Path Traversal (V9) : doit exister
# et être accessible en écriture par l'utilisateur non-root ci-dessous, sinon
# le démarrage de l'app échoue (os.makedirs à l'import du module).
RUN mkdir -p /app/exports

# Utilisateur non-root pour limiter l'impact du conteneur lui-même
# (l'app reste volontairement vulnérable côté applicatif)
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

CMD ["python", "app.py"]
