"""Startup check: the encryption key must open what the database holds.

The signing private keys (and service tokens, container environment variables) are stored encrypted with
``ENCRYPTION_KEY``, which lives in the secrets file (``secrets/secrets.json``) or the environment, never in the
database. If the secrets directory or volume is lost or replaced, a server that simply carried on would generate a
fresh key, start, report healthy and publish the unchanged JWKS -- and then answer every token request with a 500,
because the active signing key no longer decrypts. So at startup, after the migrations and before anything may
generate a key:

- a database that holds no encrypted value is a new install: nothing to check, the key is generated as before;
- a database that holds encrypted values while neither the environment nor the secrets file holds any key is a lost
  secrets file: refuse to start (never generate a new key over it);
- every signing key that signs or is about to (active, pending) must decrypt with the configured keyring, or refuse
  to start;
- other encrypted values (retired signing keys, service tokens, container environment variables) that do not open
  are logged as a warning: they break only their own feature, and the rotation command refuses until they are fixed.
"""

from __future__ import annotations

from typing import List, Optional

from src.adapters import EncryptedColumnAdapter, OAuthKeyAdapter
from src.logging import get_logger
from src.utils import secrets_store
from src.utils.crypto import TokenCrypto, configured_keyring, key_id_of_ciphertext

logger = get_logger("encryption_check")

SIGNING_COLUMN = "oauth_signing_keys.private_pem_enc"


class EncryptionKeyMismatchError(RuntimeError):
    """The configured encryption key cannot open the database's signing keys: refuse to start."""


def _fix(location: str) -> str:
    return (
        "MCP Gate did not start, and did not generate a new key, because that would leave every signing key and "
        "stored secret unreadable. Most likely the secrets directory or volume was lost or replaced (or "
        "ENCRYPTION_KEY was changed). To fix it, either restore "
        f"{location} from the backup made with this database, or set ENCRYPTION_KEY to the key this database was "
        "encrypted with (older keys, comma-separated, in ENCRYPTION_KEYS_PREVIOUS), then start again. "
        "`python -m src.cli encryption-key status` shows which values open. Starting over with an empty database "
        "is the only other way, and it loses every client, token and key."
    )


def _needed_key_ids(values: List[str]) -> str:
    ids = sorted({key_id_of_ciphertext(v) or "untagged (from before 1.4)" for v in values})
    return ", ".join(ids)


def _opens(crypto: TokenCrypto, value: str) -> bool:
    try:
        crypto.decrypt(value)
        return True
    except Exception:
        return False


def check_encryption_key(db) -> Optional[str]:
    """Raise EncryptionKeyMismatchError when the configured key cannot open the database's signing keys. Returns a
    warning (also logged) when only other encrypted values do not open, else None. Reads only; never generates."""
    encrypted = {name: [v for _, v in EncryptedColumnAdapter.values(db, name)]
                 for name in EncryptedColumnAdapter.COLUMNS}
    if not any(encrypted.values()):
        return None  # a new install (or nothing encrypted yet): the key may be generated
    location = str(secrets_store.store_location())

    crypto = configured_keyring()
    if crypto is None:
        all_values = [v for values in encrypted.values() for v in values]
        raise EncryptionKeyMismatchError(
            f"The encryption key does not match the database: the database holds {len(all_values)} encrypted "
            f"value(s) (key id {_needed_key_ids(all_values)}), but no ENCRYPTION_KEY is set and {location} holds "
            "none. " + _fix(location))

    in_use = [k for k in OAuthKeyAdapter.list_all(db)
              if k.private_pem_enc and (k.is_active or k.is_pending)]
    unreadable = [k for k in in_use if not _opens(crypto, k.private_pem_enc)]
    if unreadable:
        kids = ", ".join(k.kid[:12] + "…" for k in unreadable)
        raise EncryptionKeyMismatchError(
            f"The encryption key does not match the database: signing key(s) {kids} cannot be decrypted. They "
            f"need encryption key id {_needed_key_ids([k.private_pem_enc for k in unreadable])}; the configured "
            f"key(s) are {', '.join(crypto.key_ids())}. " + _fix(location))

    checked = {k.private_pem_enc for k in in_use}
    others = {name: sum(1 for v in values if v not in checked and not _opens(crypto, v))
              for name, values in encrypted.items()}
    if any(others.values()):
        detail = ", ".join(f"{name}: {n}" for name, n in others.items() if n)
        warning = (f"Some encrypted values do not open with the current encryption key ({detail}). The signing keys "
                   "in use are fine, but these values stay unreadable until the key they were written with is "
                   "back in ENCRYPTION_KEYS_PREVIOUS (or in the secrets file); the rotation command refuses to run "
                   "until then.")
        logger.warning(warning)
        return warning
    return None
