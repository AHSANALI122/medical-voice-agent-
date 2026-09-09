"""Field encryption and keyed hashing (C-08, C-24).

Two distinct keys, two distinct jobs:
  - AES-256-GCM with a fresh 12-byte nonce per row encrypts patient names.
    key_id travels with the row so a key can be rotated without a migration.
  - HMAC-SHA256 turns a booking reference into a stored value that can be
    compared and uniquely indexed but never read back (section 5.1).

Nothing here decides permission. These are primitives.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

NONCE_BYTES = 12
# Bound the ciphertext to the same domain as the field it protects, so a
# ciphertext lifted from one column cannot be replayed into another.
AAD_PATIENT_NAME = b"voicebook:patient_name:v1"


def encrypt_field(plaintext: str, *, aad: bytes = AAD_PATIENT_NAME) -> tuple[bytes, bytes, str]:
    """Returns (ciphertext, nonce, key_id)."""
    settings = get_settings()
    nonce = os.urandom(NONCE_BYTES)
    aesgcm = AESGCM(settings.encryption_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return ciphertext, nonce, settings.vb_encryption_key_id


def decrypt_field(
    ciphertext: bytes, nonce: bytes, key_id: str, *, aad: bytes = AAD_PATIENT_NAME
) -> str:
    settings = get_settings()
    if key_id != settings.vb_encryption_key_id:
        raise ValueError(f"no key available for key_id {key_id!r}")
    aesgcm = AESGCM(settings.encryption_key)
    return aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")


def reference_hmac(reference: str) -> tuple[bytes, str]:
    """Keyed digest of a booking reference. Returns (digest, key_id).

    Domain-separated so this digest can never be confused with a request
    signature computed under a different key for a different purpose.

    key_id names the key epoch, not one key: both keys rotate together, so one
    label identifies which generation produced any stored row.
    """
    settings = get_settings()
    message = b"voicebook:reference:v1|" + reference.encode("ascii")
    digest = hmac.new(settings.reference_hmac_key, message, hashlib.sha256).digest()
    return digest, settings.vb_encryption_key_id


def bucket_key(scope: str, *parts: str) -> str:
    """Keyed digest of a rate-limit bucket's identity.

    The parts include a patient name, which is PHI. `rate_limit_buckets` is not
    an encrypted table, so the name must not land in it in the clear: hashing
    the tuple gives a key that is stable enough to count against and useless to
    anyone reading the table.
    """
    settings = get_settings()
    message = ("voicebook:bucket:v1|" + scope + "|" + "|".join(parts)).encode("utf-8")
    return hmac.new(settings.reference_hmac_key, message, hashlib.sha256).hexdigest()


def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
