# RDX Anti-Bypass

একটি deploy-ready Telegram-managed anti-bypass service। এটি shortener callback-কে একই browser session-এর সঙ্গে bind করে। কোনো bypass bot/API final callback URL বের করে অন্য browser-এ paste বা share করলে callback কাজ করবে না; ছবির মতো **Access Denied** page দেখাবে এবং ঘটনাটি log করবে।

## কী আছে

- FastAPI web protection service
- Aiogram 3 Telegram dashboard
- Koyeb Docker/Procfile deployment
- Vercel serverless deployment
- MongoDB persistence
- Signed `HttpOnly` same-browser session
- Per-visit one-time callback nonce
- Direct paste/share detection
- Browser, optional network-prefix এবং referrer binding
- Link/flow expiry, minimum completion time ও replay lock
- Developer API, statistics, activity history এবং text log export
- Responsive Access Denied/Access Granted pages
- Automated security-flow tests

## Protection flow

```text
Protected URL
    │
    ├─ creates signed browser session + one-time challenge
    │
    ├─ calls configured shortener API with a unique callback
    │
    ├─ user completes the shortener in the same browser
    │
    └─ callback validates cookie + nonce + time + browser + expiry
             ├─ valid    → Access Granted → target URL
             └─ invalid  → Access Denied + security log
```

Final callback-এ target URL রাখা হয় না। Target server-side database-এ থাকে। সাধারণ direct-link resolver callback URL পেলেও original browser-এর signed `HttpOnly` cookie পায় না।

> কোনো web security system advanced real-browser automation-এর বিরুদ্ধে চিরস্থায়ী 100% guarantee দিতে পারে না। এই implementation direct resolvers, pasted/shared callbacks, token tampering এবং common replay attacks block করার জন্য defence-in-depth ব্যবহার করে।

## Environment variables

`.env.example` কপি করে `.env` বানান। কখনো `.env` বা আসল secret GitHub-এ commit করবেন না।

প্রথমে secret তৈরি করুন:

```bash
python scripts/generate_secrets.py
```

অবশ্যই সেট করতে হবে:

| Variable | কাজ |
|---|---|
| `PUBLIC_BASE_URL` | Deploy করা service URL, যেমন `https://protect.example.com` |
| `SECRET_KEY` | Cookie, challenge ও hashed telemetry signing secret |
| `API_KEY` | Developer API authentication key |
| `MONGODB_URI` | MongoDB Atlas connection URI; production-এ required |
| `BOT_TOKEN` | BotFather token; bot ব্যবহার না করলে ফাঁকা রাখা যায় |
| `BOT_ADMIN_IDS` | Comma-separated Telegram numeric IDs |
| `WEBHOOK_SECRET` | Telegram webhook verification secret |

Shortener configuration:

| Variable | Example |
|---|---|
| `DEMO_MODE` | Production-এ `false` |
| `SHORTENER_NAME` | `My Shortener` |
| `SHORTENER_DOMAIN` | `short.example.com` |
| `SHORTENER_API_URL` | `https://short.example.com/api` |
| `SHORTENER_API_KEY` | Provider API key |
| `SHORTENER_API_KEY_PARAM` | সাধারণত `api` |
| `SHORTENER_URL_PARAM` | সাধারণত `url` |
| `SHORTENER_FORMAT_PARAM` | সাধারণত `format` |
| `SHORTENER_FORMAT_VALUE` | সাধারণত `text` |

দুই ধরনের endpoint support করে:

1. Query API: `https://short.example.com/api?api=KEY&url=CALLBACK&format=text`
2. Template API: `https://short.example.com/api?key={key}&url={url}`

JSON response হলে `shortenedUrl`, `shortened_url`, `short_url`, `short` বা `url` field automatically পড়বে। Plain-text URL-ও support করে। Provider-এর API format আলাদা হলে `app/shortener.py` adapter-এ ছোট পরিবর্তন লাগবে।

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
set -a; source .env; set +a
uvicorn app.main:app --reload --port 8000
```

Local demo-তে:

```env
ENVIRONMENT=development
PUBLIC_BASE_URL=http://localhost:8000
DEMO_MODE=true
BOT_MODE=disabled
```

Open `http://localhost:8000/docs` for local API documentation.

## Koyeb deployment

Koyeb-এর জন্য polling mode সহজ এবং recommended:

1. এই folder নতুন GitHub repository-তে push করুন।
2. Koyeb-এ **Create Web Service → GitHub → repository** নির্বাচন করুন।
3. Builder হিসেবে Dockerfile ব্যবহার করুন। Exposed port `8000`।
4. MongoDB Atlas-এ database তৈরি করে `MONGODB_URI` দিন।
5. `.env.example` অনুযায়ী environment variables যোগ করুন।
6. প্রথম deploy-এর domain পাওয়ার পর `PUBLIC_BASE_URL=https://YOUR-SERVICE.koyeb.app` সেট করে redeploy করুন।
7. Koyeb bot-এর জন্য:

```env
ENVIRONMENT=production
BOT_MODE=polling
AUTO_SET_WEBHOOK=false
DEMO_MODE=false
```

Health check path: `/health`

## Vercel deployment

Vercel filesystem persistent নয়, তাই MongoDB অবশ্যই ব্যবহার করতে হবে। Telegram polling-ও serverless environment-এ ব্যবহার করবেন না।

1. GitHub repository Vercel-এ import করুন।
2. Framework preset: **Other**। Root directory এই project folder।
3. `.env.example` অনুযায়ী variables দিন।
4. Vercel-এর production URL দিয়ে `PUBLIC_BASE_URL` সেট করুন।
5. Bot settings:

```env
ENVIRONMENT=production
BOT_MODE=webhook
AUTO_SET_WEBHOOK=false
DEMO_MODE=false
```

6. Deploy হওয়ার পরে webhook set করুন:

```bash
curl -X POST "https://YOUR-APP.vercel.app/api/v1/telegram/setup" \
  -H "X-API-Key: YOUR_API_KEY"
```

## Telegram commands

Configured admin IDs ব্যবহার করতে পারবে:

- `/protect https://example.com/target` — protected link তৈরি
- `/stats` — statistics
- `/logs` — recent security logs `.txt` export

Bot dashboard-এ Sites, Statistics, Security, History, Logs, Settings, Help এবং About menu আছে।

## Developer API

### Protected link তৈরি

```bash
curl -X POST "https://protect.example.com/api/v1/links" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "target_url": "https://t.me/your_bot?start=verified_123",
    "user_id": 123456789,
    "expires_in": 86400,
    "max_uses": 1,
    "metadata": {"source": "rdx-leech"}
  }'
```

Response:

```json
{
  "id": "opaque-link-id",
  "protected_url": "https://protect.example.com/go/opaque-link-id",
  "expires_at": "2026-07-22T08:00:00+00:00",
  "max_uses": 1
}
```

### RDX/Leech bot integration example

```python
import httpx

async def create_protected_verification(target_url: str, user_id: int) -> str:
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://protect.example.com/api/v1/links",
            headers={"X-API-Key": "YOUR_API_KEY"},
            json={
                "target_url": target_url,
                "user_id": user_id,
                "expires_in": 86400,
                "max_uses": 1,
            },
        )
        response.raise_for_status()
        return response.json()["protected_url"]
```

আরও endpoints:

- `GET /api/v1/links`
- `GET /api/v1/links/{link_id}`
- `GET /api/v1/stats`
- `GET /api/v1/events`
- `POST /api/v1/telegram/setup`

সব `/api/v1/*` endpoint-এ `X-API-Key` প্রয়োজন। Status/list responses target URL প্রকাশ করে না।

## Recommended production settings

```env
ENVIRONMENT=production
DEMO_MODE=false
FLOW_TTL_SECONDS=1200
LINK_EXPIRY_SECONDS=86400
MIN_COMPLETION_SECONDS=8
BIND_IP_PREFIX=true
STRICT_REFERRER=false
```

Mobile network change হলে `BIND_IP_PREFIX=true` মাঝে মাঝে legitimate user block করতে পারে। এমন হলে এটি `false` করুন। অনেক shortener `Referer` strip করে, তাই provider test না করা পর্যন্ত `STRICT_REFERRER=false` রাখুন।

## Test

```bash
pip install -r requirements-dev.txt
pytest
```

Tests নিশ্চিত করে:

- same-browser callback succeeds
- অন্য browser-এ direct paste fails
- modified nonce fails
- one-time callback replay fails
- expired link flow শুরু করতে পারে না
- API key ছাড়া admin data পাওয়া যায় না
- unsafe target scheme rejected

## Branding

`APP_NAME`, `OWNER_USERNAME`, `BOT_BANNER_URL`, `UPDATES_URL` ও `SUPPORT_URL` দিয়ে branding বদলান। Web page-এর color/layout `app/static/style.css` থেকে পরিবর্তন করা যায়। অন্য bot-এর logo/name ব্যবহার না করে নিজের branding ব্যবহার করুন।

## Deployment references

- [Vercel FastAPI deployment](https://vercel.com/docs/frameworks/backend/fastapi)
- [Vercel Python runtime](https://vercel.com/docs/functions/runtimes/python)
- [Koyeb services, ports and health checks](https://www.koyeb.com/docs/reference/services)
