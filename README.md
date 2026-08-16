# Coffre-fort de données sensibles

Projet pédagogique conforme au cahier des charges : mots de passe hachés avec bcrypt, données chiffrées par AES-256-GCM, clés de données enveloppées par RSA-3072/OAEP, rotation des clés, API FastAPI, SQLite, journaux de sécurité et démonstration contrôlée de brute force.

## Démarrage local

```bash
python -m venv .venv
source .venv/bin/activate            # Windows : .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
# Exporter les variables de .env avec votre méthode habituelle.
python scripts/init_keys.py
uvicorn app.main:app --reload
```

Documentation interactive : `http://127.0.0.1:8000/docs`.

## Créer un administrateur

```bash
python scripts/create_admin.py admin admin@example.test
```

## Exemples d'appels

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.test","password":"Une-phrase-secrete-2026"}'

curl -X POST http://127.0.0.1:8000/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=alice&password=Une-phrase-secrete-2026'

curl -X POST http://127.0.0.1:8000/vault \
  -H 'Authorization: Bearer VOTRE_JETON' \
  -H 'Content-Type: application/json' \
  -d '{"data_type":"bank_card","payload":{"holder":"Alice","last4":"4242","token":"demo"}}'
```

## Tests et contrôle qualité

```bash
pytest -q
ruff check .
```

## Rotation des clés

Par l'API : `POST /admin/keys/rotate` avec un compte administrateur.

En ligne de commande :

```bash
python scripts/rotate_keys.py
```

La rotation crée une nouvelle paire RSA, ré-enveloppe les clés AES existantes, puis active la nouvelle version. Les anciennes clés privées restent archivées afin d'éviter toute perte de données et doivent être supprimées uniquement après sauvegarde, contrôle et expiration de la période de rétention.

## Sécurité de production

- Servir uniquement derrière HTTPS.
- Stocker `JWT_SECRET` et `KEY_PASSPHRASE` dans un gestionnaire de secrets.
- Monter le répertoire `keys` avec des permissions strictes et des sauvegardes chiffrées.
- Remplacer le limiteur mémoire par Redis dans un déploiement multi-instance.
- Remplacer SQLite par PostgreSQL si la concurrence, l'audit ou la haute disponibilité l'exigent.
- Ne jamais journaliser les mots de passe, jetons ou contenus déchiffrés.

## Limites pédagogiques

Ce projet illustre une architecture sûre, mais ne remplace pas une revue cryptographique, un test d'intrusion, une analyse d'impact RGPD ni un service KMS/HSM géré en production.
