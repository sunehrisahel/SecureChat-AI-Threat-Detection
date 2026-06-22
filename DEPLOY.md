# Deploying SecureChat to Vercel

This repo contains two services that must be deployed separately on Vercel.

## Architecture

```
Vercel Project 1: prompt-injection-detector
  └── https://your-detector.vercel.app

Vercel Project 2: chatbot
  ├── ANTHROPIC_API_KEY (env var — secret)
  ├── DETECTOR_URL = https://your-detector.vercel.app/analyze
  └── https://your-chatbot.vercel.app  ← users visit this
```

## Prerequisites

- A [Vercel account](https://vercel.com) (free tier works)
- Your GitHub repo connected to Vercel
- An Anthropic API key (set only in Vercel env vars, never in code)

---

## Step 1 — Deploy the detector

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import `SecureChat---AI-Threat-Detection`
3. Configure:
   - **Root Directory:** `prompt-injection-detector`
   - **Framework Preset:** Other (FastAPI is auto-detected via `pyproject.toml`)
4. **Environment variables** (recommended for production):

| Name | Value | Environments |
|------|-------|--------------|
| `DETECTOR_API_KEY` | random secret (e.g. `openssl rand -hex 32`) | Production, Preview |
| `ADMIN_API_KEY` | random secret | Production, Preview |
| `ALLOWED_ORIGINS` | `https://your-chatbot.vercel.app` | Production |

5. Click **Deploy**
6. Copy the production URL, e.g. `https://securechat-detector.vercel.app`

Verify:

```bash
curl https://your-detector.vercel.app/health
curl -X POST https://your-detector.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_DETECTOR_API_KEY" \
  -d '{"text": "hello", "source": "test"}'
```

---

## Step 2 — Deploy the chatbot

1. **Add New** → **Project** (same GitHub repo again)
2. Configure:
   - **Root Directory:** `chatbot`
   - **Framework Preset:** Other
3. Add **Environment Variables**:

| Name | Value | Environments |
|------|-------|--------------|
| `ANTHROPIC_API_KEY` | `sk-ant-your-real-key` | Production, Preview, Development |
| `DETECTOR_URL` | optional — defaults to Render detector URL on Vercel | Production |
| `DETECTOR_API_KEY` | optional when using inline detector | Production, Preview |
| `VERCEL_PROTECTION_BYPASS` | bypass secret from detector project (if Deployment Protection is on) | Production, Preview |
| `ADMIN_API_KEY` | same as detector project | Production, Preview |
| `ALLOWED_ORIGINS` | `https://your-chatbot.vercel.app` | Production |
| `COOKIE_SECURE` | `true` | Production |

**Note:** SecureChat on Vercel calls the detector on **Render** (`https://securechat-detector-api.onrender.com/analyze`) by default. Deploy the Render blueprint first (Step 4). Override with `DETECTOR_URL` if needed.

4. Click **Deploy**
5. Open `https://your-chatbot.vercel.app`

---

## Step 3 — Local development

```bash
# Terminal 1 — detector
cd prompt-injection-detector
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Terminal 2 — chatbot
cd chatbot
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY
pip install -r requirements.txt
uvicorn web_server:app --reload --port 3000
```

Open `http://localhost:3000`

---

## Vercel CLI (optional)

```bash
npm i -g vercel
vercel login

cd prompt-injection-detector
vercel --prod

cd ../chatbot
vercel env add ANTHROPIC_API_KEY production
vercel env add DETECTOR_URL production
vercel --prod
```

---

## Files added for Vercel

| File | Purpose |
|------|---------|
| `prompt-injection-detector/pyproject.toml` | Entrypoint (`app.main:app`) + production dependencies |
| `prompt-injection-detector/vercel.json` | Minimal Vercel config (entrypoint comes from pyproject.toml) |
| `prompt-injection-detector/.vercelignore` | Exclude tests/dashboard from upload |
| `chatbot/pyproject.toml` | Entrypoint (`web_server:app`) + dependencies |
| `chatbot/vercel.json` | Minimal Vercel config |
| `chatbot/.vercelignore` | Exclude local env files from upload |

---

## Troubleshooting deploy failures

### Error: `app/main.py` doesn't match any Serverless Functions inside the api directory

Your repo still has the old `vercel.json` with a `functions` block. Pull the latest `main` (or redeploy after the fix commit). Correct config is an **empty** `vercel.json`; the entrypoint comes from `pyproject.toml`:

```toml
[tool.vercel]
entrypoint = "app.main:app"   # detector
entrypoint = "web_server:app" # chatbot
```

### Build succeeds but chat shows "detector offline"

1. Set `DETECTOR_URL` on the **chatbot** project to your detector URL + `/analyze`, e.g. `https://your-detector.vercel.app/analyze`.
2. If **Deployment Protection** is enabled on the detector Vercel project, server-to-server health checks get **401** before reaching FastAPI. Either:
   - **Recommended for production APIs:** Detector project → **Settings** → **Deployment Protection** → copy **Protection Bypass for Automation** → set `VERCEL_PROTECTION_BYPASS` on the **chatbot** (and Render red-team) project to that value.
   - **Or** disable Deployment Protection on the **detector** project (keep it on the chatbot UI if you want).
3. Ensure `DETECTOR_API_KEY` on the chatbot matches the detector project when auth is enabled.
4. Hover the "detector offline" label in SecureChat — the tooltip shows the server-side hint from `/health`.

### Detector build fails on bundle size

scikit-learn can exceed Vercel limits. Deploy the detector on [Render](https://render.com) instead and point `DETECTOR_URL` at that URL.

---

- **Cold starts** — first request after idle can take 10–30+ seconds (detector is heavier due to scikit-learn)
- **Ephemeral logs** — detector logs are written to `/tmp` on Vercel and do not persist across invocations
- **In-memory chat history** — conversation resets when a new serverless instance spins up
- **Bundle size** — if the detector deploy fails, the ML dependencies may exceed Vercel's function size limit; consider Render for the detector instead

---

## Phase 1 security (production)

| Feature | Behavior |
|---------|----------|
| **Fail-closed** | If the detector is unreachable, messages are **blocked** (set `DETECTOR_FAIL_OPEN=true` locally to disable) |
| **Warn blocking** | `action: warn` messages are **blocked** before reaching Claude (`BLOCK_WARN_ACTION=true` by default) |
| **Session isolation** | Each browser gets its own conversation via `securechat_session` cookie |
| **Rate limits** | `/chat` — 30 req/min per session; `/analyze` — 60 req/min per IP |
| **Auth** | When `DETECTOR_API_KEY` is set, `/analyze` requires `Authorization: Bearer …` |
| **Admin endpoints** | When `ADMIN_API_KEY` is set, `/logs` and `/analytics` require admin token |

Local dev works without API keys (open endpoints). **Always set both keys in production.**

---

## API key security

- Set `ANTHROPIC_API_KEY` only in Vercel **Environment Variables**
- Never commit `.env` or hardcode keys in `config.py`
- Rotate your key if it was ever committed to git

---

## Alternative: Render (simpler)

If Vercel deploy fails due to bundle size or cold starts, [Render](https://render.com) is a better fit for long-running Python servers. See the chatbot README for local setup.

---

## Step 4 — Deploy the Red Team Console + detector API (Render)

Streamlit cannot run on Vercel serverless. Use [Render](https://render.com) with the included `render.yaml` blueprint (creates **prompt-injection-detector** + **red-team-console**).

1. Push this repo to GitHub.
2. Go to [render.com/deploy](https://render.com/deploy) → connect `SecureChat-AI-Threat-Detection`.
3. Render detects `render.yaml` and creates **securechat-detector-api** + **red-team-console**.
4. Set **ANTHROPIC_API_KEY** on **red-team-console** (secret).
5. Deploy → both services use `https://securechat-detector-api.onrender.com/analyze`.

Session attack history persists on the Render disk via `.red_team_session.json` until redeploy.
