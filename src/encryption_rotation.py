"""Rotate ENCRYPTION_KEY without downtime (#30): ``python -m src.cli encryption-key rotate``.

1. Check that every encrypted value in the database opens with the current keyring; refuse otherwise (nothing is
   changed, so a wrong key can never make things worse).
2. Add a new key to the keyring in the secrets file: it becomes ``ENCRYPTION_KEY`` and the old one moves to
   ``ENCRYPTION_KEYS_PREVIOUS``. A running MCP Gate notices the file changed and encrypts with the new key from its
   next write on, while still reading the old one -- no restart.
3. Re-encrypt every value that is not under the newest key: decrypt, encrypt, check the round trip, then a
   conditional UPDATE that only replaces the value it read (a concurrent edit wins and is picked up next pass).
4. Wait a few seconds for a running server to pick up the keyring, scan again, repeat until nothing is left.
5. Verify that every value is tagged with the newest key and opens with it, and only then retire the old key
   (remove it from the secrets file).

Interrupted anywhere, it is safe to run again: with previous keys still in the keyring it resumes at step 3 without
making another key. With ``ENCRYPTION_KEY`` set in the environment the command cannot change it: set the new value in
ENCRYPTION_KEY and the old one in ENCRYPTION_KEYS_PREVIOUS, restart, and run it to re-encrypt; it then says when the
previous keys can be removed.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import Counter
from typing import Callable, Dict

from src.adapters import EncryptedColumnAdapter
from src.utils import crypto as crypto_mod
from src.utils import secrets_store
from src.utils.crypto import PREVIOUS_NAME, TokenCrypto, split_keys

MAX_PASSES = 5


class RotationRefused(Exception):
    pass


def _keyring() -> TokenCrypto:
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()
    return TokenCrypto()


def scan(db, crypto: TokenCrypto) -> Dict[str, Counter]:
    """Per column: how many values are under the newest key, under an older key in the ring ("previous"), from
    before key ids ("untagged"), or open with no key in the ring ("unreadable")."""
    report: Dict[str, Counter] = {}
    for name in EncryptedColumnAdapter.COLUMNS:
        counts: Counter = Counter()
        for _, value in EncryptedColumnAdapter.values(db, name):
            if crypto.decrypts_with_newest(value):
                counts["newest"] += 1
                continue
            try:
                crypto.decrypt(value)
            except Exception:
                counts["unreadable"] += 1
                continue
            counts["untagged" if crypto_mod.key_id_of_ciphertext(value) is None else "previous"] += 1
        report[name] = counts
    return report


def _total(report: Dict[str, Counter], kind: str) -> int:
    return sum(c[kind] for c in report.values())


def reencrypt(db, crypto: TokenCrypto) -> int:
    """One pass: every value not under the newest key is re-encrypted with it. Returns how many were replaced."""
    replaced = 0
    for name in EncryptedColumnAdapter.COLUMNS:
        for key, value in EncryptedColumnAdapter.values(db, name):
            if crypto.decrypts_with_newest(value):
                continue
            plaintext = crypto.decrypt(value)
            new = crypto.encrypt(plaintext)
            if crypto.decrypt(new) != plaintext or not crypto.decrypts_with_newest(new):  # pragma: no cover
                raise RuntimeError(f"round trip failed for {name}")
            if EncryptedColumnAdapter.replace(db, name, key, value, new):
                replaced += 1
    return replaced


def _env_managed() -> bool:
    return bool(os.environ.get("ENCRYPTION_KEY", "").strip())


def rotate(db, *, settle_seconds: float = 3.0, out: Callable[[str], None] = print,
           sleep: Callable[[float], None] = time.sleep) -> dict:
    crypto = _keyring()
    before = scan(db, crypto)
    unreadable = _total(before, "unreadable")
    if unreadable:
        raise RotationRefused(
            f"{unreadable} encrypted value(s) do not open with the current keyring; nothing was changed. Restore the "
            "key they were written with (ENCRYPTION_KEY / ENCRYPTION_KEYS_PREVIOUS) first.")

    new_key = False
    stored = secrets_store.read_file()
    if _env_managed():
        out("ENCRYPTION_KEY is set in the environment: re-encrypting under it (no new key is made).")
    elif split_keys(stored.get(PREVIOUS_NAME)):
        out("A previous key is still in the keyring: resuming the interrupted rotation (no new key is made).")
    else:
        old = stored.get("ENCRYPTION_KEY") or secrets_store.get_secret("ENCRYPTION_KEY")
        fresh = secrets.token_urlsafe(32)

        def add_key(values):
            values[PREVIOUS_NAME] = ",".join([old] + split_keys(values.get(PREVIOUS_NAME)))
            values["ENCRYPTION_KEY"] = fresh

        secrets_store.update_file(add_key)
        new_key = True
        crypto = _keyring()
        out(f"Added encryption key {crypto.key_id} to {secrets_store.store_location()}; new writes use it now.")

    replaced = 0
    for attempt in range(MAX_PASSES):
        replaced += reencrypt(db, crypto)
        if settle_seconds:
            sleep(settle_seconds)  # a running server picks up the new keyring on its next write
        report = scan(db, crypto)
        if not (_total(report, "previous") or _total(report, "untagged") or _total(report, "unreadable")):
            break
    else:
        raise RotationRefused(
            f"values under an older key keep appearing after {MAX_PASSES} passes; the old key was kept. Run the "
            "command again (is a server still running with an old MCP Gate version?).")

    # Verified: every value is under the newest key and opens with it
    retired = _retire_previous(crypto, out)
    summary = {"new_key": new_key, "key_id": crypto.key_id, "reencrypted": replaced, "retired": retired,
               "values": {name: c["newest"] for name, c in report.items()}}
    out(f"Re-encrypted {replaced} value(s); {sum(summary['values'].values())} value(s) are under key "
        f"{crypto.key_id}.")
    return summary


def _retire_previous(crypto: TokenCrypto, out: Callable[[str], None]) -> int:
    stored = secrets_store.read_file()
    env_newest = os.environ.get("ENCRYPTION_KEY", "").strip()
    file_previous = split_keys(stored.get(PREVIOUS_NAME))
    stale_file_key = bool(env_newest and stored.get("ENCRYPTION_KEY") and stored["ENCRYPTION_KEY"] != env_newest)
    retired = len(file_previous) + (1 if stale_file_key else 0)

    if file_previous or stale_file_key:
        def drop(values):
            values.pop(PREVIOUS_NAME, None)
            if stale_file_key:
                values.pop("ENCRYPTION_KEY", None)

        secrets_store.update_file(drop)
        out(f"Retired {retired} old key(s): nothing encrypted with them is left.")
    if split_keys(os.environ.get(PREVIOUS_NAME)):
        out("Nothing needs the keys in ENCRYPTION_KEYS_PREVIOUS any more: remove that variable at your next restart.")
    crypto_mod.reset_crypto()
    return retired


def status(db) -> Dict[str, Counter]:
    return scan(db, _keyring())


def describe(report: Dict[str, Counter]) -> str:
    lines = []
    for name, counts in report.items():
        parts = ", ".join(f"{k} {counts[k]}" for k in ("newest", "previous", "untagged", "unreadable") if counts[k])
        lines.append(f"  {name}: {parts or 'empty'}")
    return "\n".join(lines)
