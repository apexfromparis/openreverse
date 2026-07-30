# GitHub to Discord webhook

## Render setup

Create a Render Web Service from this repository with:

- Root Directory: `discord-webhook`
- Build Command: `npm install`
- Start Command: `npm start`

Add these environment variables:

- `DISCORD_WEBHOOK_URL`: the Discord webhook URL
- `WEBHOOK_SECRET`: a random secret, for example `openssl rand -hex 32`

The public GitHub webhook URL will be:

`https://YOUR-RENDER-SERVICE.onrender.com/github-webhook`

In GitHub, add that URL under Settings > Webhooks, select `application/json`, set the same secret, and enable only the `Pushes` event.
