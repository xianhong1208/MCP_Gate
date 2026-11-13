"""AES-256-GCM encryption at rest (private keys, service tokens, container env) and SHA-256 hashing helpers.

Keys form a keyring (#30):

- the newest key, ``ENCRYPTION_KEY`` (environment, else the secrets file, generated on first start), encrypts every
  new value;
- previous keys, ``ENCRYPTION_KEYS_PREVIOUS`` (comma-separated; environment and/or the secrets file), still decrypt
  what they encrypted until ``python -m src.cli encryption-key rotate`` has re-encrypted it and retired them.

Every ciphertext names the key that made it: ``mg1:<key id>:<base64(nonce | tag | ciphertext)>``. The key id is a
truncated, domain-separated hash of the AES key, so the stored value says which key to use without revealing it.
Values written before #30 carry no tag; they are tried with each key in turn (GCM authenticates, so a wrong key
fails rather than returning garbage).

A running server re-reads the keyring when the secrets file changes (checked on every encryption, and when a value
names a key it does not know), so a rotation needs no restart.
"""

import base64
import hashlib
import os
import threading
from typing import Iterable, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PREFIX = "mg1"
PREVIOUS_NAME = "ENCRYPTION_KEYS_PREVIOUS"


class UnknownEncryptionKeyError(ValueError):
    """A value names a key the keyring does not hold."""


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


def key_id_of(key: bytes) -> str:
    return hashlib.sha256(b"mcp-gate encryption key id\0" + key).hexdigest()[:12]


def split_keys(raw: Optional[str]) -> List[str]:
    return [k.strip() for k in (raw or "").split(",") if k.strip()]


def parse(ciphertext: str) -> Tuple[Optional[str], bytes]:
    """(key id or None for a pre-#30 value, raw bytes)."""
    if ciphertext.startswith(PREFIX + ":"):
        _, kid, body = ciphertext.split(":", 2)
        return kid, base64.b64decode(body)
    return None, base64.b64decode(ciphertext)


def key_id_of_ciphertext(ciphertext: str) -> Optional[str]:
    return parse(ciphertext)[0] if ciphertext else None


def _gcm_decrypt(key: bytes, data: bytes) -> str:
    nonce, tag, encrypted = data[:12], data[12:28], data[28:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return (decryptor.update(encrypted) + decryptor.finalize()).decode()


def _previous_keys(stored: dict, newest: str) -> List[str]:
    previous = split_keys(os.environ.get(PREVIOUS_NAME)) + split_keys(stored.get(PREVIOUS_NAME))
    # Changing ENCRYPTION_KEY in the environment by hand while the file still holds the old one: keep the file's
    # key readable too, so nothing it encrypted becomes unreadable.
    if stored.get("ENCRYPTION_KEY") and stored["ENCRYPTION_KEY"] != newest:
        previous.append(stored["ENCRYPTION_KEY"])
    return previous


class TokenCrypto:
    """AES-256-GCM encrypt/decrypt with a keyring: the first key encrypts, any key decrypts what it made."""

    def __init__(self, secret_key: Optional[str] = None, previous: Iterable[str] = (), *, reloadable: bool = False):
        self._lock = threading.Lock()
        self._reloadable = reloadable
        self._version = None
        if secret_key is None:
            self._reloadable = True
            self._load_from_store(generate=True)
        else:
            self._set_keys(secret_key, list(previous))

    # -- keyring ---------------------------------------------------------------------------------------------------
    def _set_keys(self, newest: str, previous: List[str]) -> None:
        keys = [derive_key(newest)] + [derive_key(p) for p in previous]
        ring = {}
        for k in keys:
            ring.setdefault(key_id_of(k), k)
        self.key = keys[0]
        self.key_id = key_id_of(self.key)
        self._ring = ring

    def _load_from_store(self, *, generate: bool) -> None:
        from src.utils import secrets_store

        version = secrets_store.file_version()
        newest = os.environ.get("ENCRYPTION_KEY", "").strip()
        stored = secrets_store.read_file()
        if not newest:
            newest = (secrets_store.get_secret("ENCRYPTION_KEY") if generate or not stored.get("ENCRYPTION_KEY")
                      else stored["ENCRYPTION_KEY"])
        self._set_keys(newest, _previous_keys(stored, newest))
        self._version = version

    def reload_if_changed(self) -> bool:
        if not self._reloadable:
            return False
        from src.utils import secrets_store

        if secrets_store.file_version() == self._version:
            return False
        with self._lock:
            self._load_from_store(generate=False)
        return True

    def key_ids(self) -> List[str]:
        """Key ids in the ring, newest first."""
        return list(self._ring)

    def has_key(self, key_id: str) -> bool:
        return key_id in self._ring

    # -- encrypt / decrypt -----------------------------------------------------------------------------------------
    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        self.reload_if_changed()
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        body = base64.b64encode(nonce + encryptor.tag + ciphertext).decode()
        return f"{PREFIX}:{self.key_id}:{body}"

    def decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        kid, data = parse(ciphertext)
        if kid is not None:
            if kid not in self._ring and not self.reload_if_changed():
                raise UnknownEncryptionKeyError(f"encrypted with key {kid}, which is not in the keyring")
            if kid not in self._ring:
                raise UnknownEncryptionKeyError(f"encrypted with key {kid}, which is not in the keyring")
            return _gcm_decrypt(self._ring[kid], data)
        # A value from before #30: no tag, so try each key (newest first); GCM rejects the wrong ones
        last_error: Exception = UnknownEncryptionKeyError("no key decrypts this value")
        for key in self._ring.values():
            try:
                return _gcm_decrypt(key, data)
            except Exception as e:
                last_error = e
        raise last_error

    def decrypts_with_newest(self, ciphertext: str) -> bool:
        """The value is tagged with the newest key and that key opens it."""
        if not ciphertext:
            return True
        kid, data = parse(ciphertext)
        if kid != self.key_id:
            return False
        try:
            _gcm_decrypt(self.key, data)
            return True
        except Exception:
            return False


def configured_keyring() -> Optional[TokenCrypto]:
    """The keyring the environment and the secrets file hold, built without generating a key: None when neither
    holds any key (no ENCRYPTION_KEY and no ENCRYPTION_KEYS_PREVIOUS). For the startup check, which must look before
    get_crypto() would generate a fresh key (src/encryption_check.py)."""
    from src.utils import secrets_store

    stored = secrets_store.read_file()
    newest = os.environ.get("ENCRYPTION_KEY", "").strip() or stored.get("ENCRYPTION_KEY", "")
    keys = ([newest] if newest else []) + _previous_keys(stored, newest)
    if not keys:
        return None
    return TokenCrypto(keys[0], keys[1:])


_crypto_instance: Optional[TokenCrypto] = None


def get_crypto() -> TokenCrypto:
    global _crypto_instance
    if _crypto_instance is None:
        _crypto_instance = TokenCrypto()
    return _crypto_instance


def reset_crypto() -> None:
    """For tests: rebuild the singleton after changing the key."""
    global _crypto_instance
    _crypto_instance = None


def encrypt_token(token: str) -> str:
    return get_crypto().encrypt(token)


def decrypt_token(encrypted: str) -> str:
    return get_crypto().decrypt(encrypted)


def hash_token(token: str) -> str:
    """SHA-256 hex (for values like client secrets / authorization codes that only need comparing, never
    recovering)."""
    return hashlib.sha256(token.encode()).hexdigest()


def get_token_prefix(token: str, length: int = 8) -> str:
    return token[:length] if len(token) >= length else token
