# Muse

Tracks your Muse subscription quota (5h session window + weekly) using your
`dev.meta.ai` browser login.

## What it tracks

| Metric | Meaning |
|---|---|
| Session | 5h session-window quota used |
| Weekly | Weekly quota used |

Both meters carry their reset time. When Meta reports your plan tier (e.g. "Muse Code High Usage"), OpenUsage shows it beside the provider name with the redundant "Muse Code" prefix cut (e.g. "High Usage").

## Where credentials come from

Only one cookie authenticates the usage page: `llm_sess`. Checked in this order — whichever works first wins:

1. A manually saved cookie: `~/.config/muse-usage/session`, or the `MUSE_LLM_SESS` environment variable. The Settings API-key editor manages the saved file, so you can paste the cookie once from browser DevTools (Application → Cookies → `https://dev.meta.ai` → `llm_sess`) instead of granting disk access.
2. Your default browser's cookie store, then every other installed browser (Brave, Chrome, Arc, Edge, Firefox, Safari). Chromium cookies are decrypted with the browser's Keychain item (`<Browser> Safe Storage`), which may prompt once for approval.

If the saved cookie is rejected but a browser holds a fresh one, the browser cookie is used instead.

Reading another app's cookie store needs Full Disk Access for OpenUsage (System Settings → Privacy & Security → Full Disk Access). Without it, use the manual cookie from step 1.

## Troubleshooting

- **"Sign in to dev.meta.ai …"** — no session cookie was found anywhere. Sign in to `dev.meta.ai` in your browser and refresh.
- **"Session expired"** — the cookie was rejected. Your browser session timed out or you logged out; sign in again in the browser and refresh.
- **"Couldn't read your browser's cookies"** — macOS denied the read. Grant OpenUsage Full Disk Access (see above) or save the cookie manually.

## Under the hood

`GET https://dev.meta.ai/usage/` with the session cookie plus `Accept: text/html` (a request without it gets an error page or a variant without quota data), following the redirect to the team's `team_id`/`project_id` URL. The page embeds the full quota result in its `LLMDCUsageQuery` preloader data, so no GraphQL call is needed. Quota numbers arrive as weighted-used/weighted-limit pairs and are reported as percent used.
