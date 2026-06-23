# Monorepo split (June 2026)

This repository is the **legacy monorepo**. New development uses two independent repos:

| Component | New repository |
|-----------|----------------|
| Detector API + SecureChat UI | [prompt-injection-detector](https://github.com/sunehrisahel/prompt-injection-detector) |
| Red Team Console | [prompt-injection-red-team](https://github.com/sunehrisahel/prompt-injection-red-team) |

## Render migration (zero downtime)

1. Deploy **prompt-injection-detector** from the new repo (keep `securechat-detector-api` running)
2. Deploy **prompt-injection-red-team** from the new repo (keep `red-team-console` running)
3. Test new URLs, then delete old Render services when ready

See `prompt-injection-detector/DEPLOY.md` in the new repo for step-by-step instructions.

## Vercel

SecureChat (`chatbot/`) can deploy from the detector repo or remain on this monorepo until you switch.
