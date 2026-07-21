from __future__ import annotations

import secrets


print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
print(f"API_KEY={secrets.token_urlsafe(36)}")
print(f"WEBHOOK_SECRET={secrets.token_urlsafe(24).replace('-', 'A').replace('_', 'B')}")
