# Priv-Eye — Production Deployment

## Checklist before going live

| # | Item | Where |
|---|---|---|
| 1 | `ENVIRONMENT=production` | `.env` |
| 2 | `DEBUG=false` | `.env` |
| 3 | Strong `JWT_SECRET` (≥48 random bytes) | `.env` |
| 4 | Switch `JWT_ALGORITHM` to `RS256` and supply key pair | `.env` + key files |
| 5 | `MODEL_SHA256` set to trained model digest | `.env` |
| 6 | `DATABASE_URL` pointing to Postgres (not SQLite) | `.env` |
| 7 | TLS termination in front of both services | Reverse proxy |
| 8 | `CORS_ORIGINS` locked to your actual dashboard origin | `.env` |
| 9 | Rate limits reviewed and tuned | `.env` |
| 10 | Firewall: only 443 public; 8000/3000 internal | Infra |

---

## Environment variables reference

### API

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` disables /docs, enforces SHA256, requires RS256 |
| `DEBUG` | `true` | Must be `false` in prod |
| `JWT_SECRET` | — | 48+ random bytes; rotate by reissuing all tokens |
| `JWT_ALGORITHM` | `HS256` | Use `RS256` in prod |
| `DATABASE_URL` | `sqlite+aiosqlite:///./priveye.db` | Use `postgresql+asyncpg://…` in prod |
| `MODEL_PATH` | `./priveye_api/ml/model.pkl` | Mount as volume |
| `MODEL_SHA256` | _(empty)_ | Required in prod; output by `train_model.py` |
| `GEMINI_API_KEY` | _(empty)_ | Omit to disable `/api/v1/insights` |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated; no wildcards in prod |

### Dashboard

| Variable | Default | Notes |
|---|---|---|
| `PRIVEYE_API` | `http://localhost:8000` | Internal API base URL |
| `ENVIRONMENT` | `development` | Set to `production` to enable `Secure` cookie flag |

---

## Switching to RS256 JWT

1. Generate key pair:
   ```bash
   openssl genrsa -out priveye_private.pem 2048
   openssl rsa -in priveye_private.pem -pubout -out priveye_public.pem
   ```
2. Set in `.env`:
   ```
   JWT_ALGORITHM=RS256
   JWT_PRIVATE_KEY_PATH=/secrets/priveye_private.pem
   JWT_PUBLIC_KEY_PATH=/secrets/priveye_public.pem
   ```
3. Mount key files as read-only secrets in the container (not baked into the image).

---

## Postgres migration

1. Change `DATABASE_URL`:
   ```
   DATABASE_URL=postgresql+asyncpg://priveye:<pw>@db:5432/priveye
   ```
2. Run Alembic:
   ```bash
   docker compose run --rm api alembic upgrade head
   ```
3. The `init_db()` dev shortcut is skipped when `ENVIRONMENT != development`.

---

## Model artifact management

The `model.pkl` is a joblib-serialised payload containing the sklearn RF, the feature
column list, and metadata. It must be:

- **Versioned** — `model_meta.json` is written alongside it; check `version` + `sha256`.
- **Integrity-checked** — Set `MODEL_SHA256` in `.env`; the API refuses to start in production
  without it.
- **Mounted as a volume** — Do not bake `model.pkl` into the Docker image. The model will be
  retrained as real telemetry accumulates.

---

## Reverse proxy (nginx example)

```nginx
server {
    listen 443 ssl http2;
    server_name priveye.example.com;

    # TLS config omitted — use certbot / Let's Encrypt
    ssl_certificate     /etc/letsencrypt/live/priveye.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/priveye.example.com/privkey.pem;

    # Dashboard
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API (agents post here directly, or via dashboard /proxy/*)
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /healthz {
        proxy_pass http://127.0.0.1:8000/healthz;
    }
}
```

---

## Agent deployment

```bash
# On each target host:
pip install priveye-agent  # or: pip install -e /path/to/agent

# Store credentials as systemd environment or .env file (chmod 600, root-owned).
cat > /etc/priveye.env <<EOF
PRIVEYE_API=https://priveye.example.com
PRIVEYE_HOST_ID=<id from POST /api/v1/hosts>
PRIVEYE_HMAC_KEY=<key from POST /api/v1/hosts>
EOF
chmod 600 /etc/priveye.env

# Cron — scan every 6 hours:
echo "0 */6 * * * root env $(cat /etc/priveye.env | xargs) priveye-agent scan >> /var/log/priveye-agent.log 2>&1" \
  > /etc/cron.d/priveye-agent
```
