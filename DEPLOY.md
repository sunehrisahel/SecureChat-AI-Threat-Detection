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
4. **Environment variables:** none required
5. Click **Deploy**
6. Copy the production URL, e.g. `https://securechat-detector.vercel.app`

Verify:

```bash
curl https://your-detector.vercel.app/health
curl -X POST https://your-detector.vercel.app/analyze \
  -H "Content-Type: application/json" \
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
| `DETECTOR_URL` | `https://your-detector.vercel.app/analyze` | Production, Preview, Development |

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
| `prompt-injection-detector/pyproject.toml` | Entrypoint + production dependencies |
| `prompt-injection-detector/vercel.json` | Exclude tests/dashboard from bundle |
| `chatbot/pyproject.toml` | Entrypoint + dependencies |
| `chatbot/vercel.json` | Function config |

---

## Known Vercel limitations

- **Cold starts** — first request after idle can take 10–30+ seconds (detector is heavier due to scikit-learn)
- **Ephemeral logs** — detector logs are written to `/tmp` on Vercel and do not persist across invocations
- **In-memory chat history** — conversation resets when a new serverless instance spins up
- **Bundle size** — if the detector deploy fails, the ML dependencies may exceed Vercel's function size limit; consider Render for the detector instead

---

## API key security

- Set `ANTHROPIC_API_KEY` only in Vercel **Environment Variables**
- Never commit `.env` or hardcode keys in `config.py`
- Rotate your key if it was ever committed to git

---

## Alternative: Render (simpler)

If Vercel deploy fails due to bundle size or cold starts, [Render](https://render.com) is a better fit for long-running Python servers. See the chatbot README for local setup.
