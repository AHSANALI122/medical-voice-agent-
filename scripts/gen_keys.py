"""Print a set of fresh keys for a local .env. Output is a secret — do not commit."""

import base64
import secrets

FIELDS = [
    "VB_ENCRYPTION_KEY",
    "VB_REFERENCE_HMAC_KEY",
    "VB_CHANNEL_SECRET_WEB",
    "VB_CHANNEL_SECRET_PHONE",
    "VB_CHANNEL_SECRET_TESTER",
]

for field in FIELDS:
    print(f"{field}={base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}")
