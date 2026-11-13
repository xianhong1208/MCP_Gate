"""Encrypted columns, for re-encryption under a new ENCRYPTION_KEY (#30, src/encryption_rotation.py)."""

from db.crud import EncryptedColumnCRUD


class EncryptedColumnAdapter(EncryptedColumnCRUD):
    pass
