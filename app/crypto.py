"""Cryptographic helpers for identity and secret protection.

Handles authenticated encryption at rest for sensitive credentials such as
TOTP/MFA secrets using Fernet (AES-128-CBC + HMAC-SHA256).

Supports seamless zero-downtime key rotation via MultiFernet and transparent
backward compatibility for legacy plaintext records.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import current_app

if TYPE_CHECKING:
    from flask import Flask

logger = logging.getLogger(__name__)

FERNET_TOKEN_PREFIX = "gAAAAA"
FERNET_MIN_TOKEN_LENGTH = 100


def get_mfa_cipher(app: Flask | None = None) -> MultiFernet | None:
    """Instantiate a MultiFernet cipher using configured BLOGG_MFA_ENCRYPTION_KEY(s).

    Supports comma-separated keys for key rotation:
        BLOGG_MFA_ENCRYPTION_KEY="primary_new_key,secondary_old_key"
    The primary key is used for new encryptions; all keys are attempted in order
    for decryption.
    """
    if app is None:
        try:
            app = current_app._get_current_object()
        except RuntimeError:
            return None

    raw_keys = app.config.get("BLOGG_MFA_ENCRYPTION_KEY")
    if not raw_keys:
        return None

    if isinstance(raw_keys, str):
        key_list = [k.strip() for k in raw_keys.split(",") if k.strip()]
    elif isinstance(raw_keys, (list, tuple)):
        key_list = [k.strip() if isinstance(k, str) else k for k in raw_keys if k]
    else:
        return None

    if not key_list:
        return None

    fernets = []
    for k in key_list:
        try:
            fernets.append(Fernet(k.encode("utf-8") if isinstance(k, str) else k))
        except Exception as exc:
            app.logger.error(
                "Invalid Fernet key in BLOGG_MFA_ENCRYPTION_KEY: %s", type(exc).__name__
            )
            return None

    return MultiFernet(fernets)


def is_encrypted_secret(val: str | None) -> bool:
    """Check whether a secret string appears to be an encrypted Fernet token.

    Fernet tokens are URL-safe base64 strings starting with 'gAAAAA' (version 0x80)
    and exceeding 100 characters in length. Plaintext Base32 TOTP secrets only contain
    uppercase letters [A-Z] and digits [2-7] (typically 16-32 characters) and never
    contain lowercase characters or '-'/'_'.
    """
    if not val or not isinstance(val, str):
        return False
    return val.startswith(FERNET_TOKEN_PREFIX) and len(val) >= FERNET_MIN_TOKEN_LENGTH


def encrypt_mfa_secret(secret: str | None) -> str | None:
    """Encrypt a plaintext MFA secret using authenticated encryption (Fernet).

    If the secret is None or empty, returns None.
    If the secret is already encrypted, returns it unchanged.
    """
    if not secret:
        return None
    if is_encrypted_secret(secret):
        return secret

    cipher = get_mfa_cipher()
    if cipher is None:
        raise RuntimeError("Cannot encrypt MFA secret: BLOGG_MFA_ENCRYPTION_KEY is not configured.")

    encrypted_bytes = cipher.encrypt(secret.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_mfa_secret(ciphertext: str | None) -> str | None:
    """Decrypt an encrypted MFA secret using MultiFernet.

    Provides transparent fallback for legacy plaintext secrets (not yet migrated).
    If decryption fails due to key mismatch or corrupted ciphertext, logs an error
    without exposing the secret and safely returns None.
    """
    if not ciphertext:
        return None

    if not is_encrypted_secret(ciphertext):
        # Transparent migration fallback: unencrypted legacy secret.
        return ciphertext

    cipher = get_mfa_cipher()
    if cipher is None:
        try:
            current_app.logger.error(
                "MFA secret decryption failed: BLOGG_MFA_ENCRYPTION_KEY not configured"
            )
        except RuntimeError:
            logger.error("MFA secret decryption failed: BLOGG_MFA_ENCRYPTION_KEY not configured")
        return None

    try:
        decrypted_bytes = cipher.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken:
        try:
            current_app.logger.error("MFA secret decryption failed: Invalid token or incorrect key")
        except RuntimeError:
            logger.error("MFA secret decryption failed: Invalid token or incorrect key")
        return None
    except Exception as exc:
        try:
            current_app.logger.error("MFA secret decryption failed: %s", type(exc).__name__)
        except RuntimeError:
            logger.error("MFA secret decryption failed: %s", type(exc).__name__)
        return None


def rotate_mfa_secret(ciphertext: str | None) -> str | None:
    """Re-encrypt an existing Fernet token with the primary encryption key.

    Returns the re-encrypted ciphertext, or unchanged if unencrypted/None.
    """
    if not ciphertext or not is_encrypted_secret(ciphertext):
        return ciphertext

    cipher = get_mfa_cipher()
    if cipher is None:
        raise RuntimeError("Cannot rotate MFA secret: BLOGG_MFA_ENCRYPTION_KEY is not configured.")

    rotated_bytes = cipher.rotate(ciphertext.encode("utf-8"))
    return rotated_bytes.decode("utf-8")
