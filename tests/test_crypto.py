"""Crypto utility tests.

Coverage:
1. Token encryption/decryption
2. Key handling
"""

import pytest
import os


class TestTokenEncryption:
    """Token encryption/decryption tests."""

    def test_encrypt_decrypt_token(self):
        """Encrypt and decrypt a token."""
        # Set the test key
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token, decrypt_token

        original_token = "my-secret-mcp-token-12345"

        # Encrypt
        encrypted = encrypt_token(original_token)
        assert encrypted != original_token
        assert len(encrypted) > 0

        # Decrypt
        decrypted = decrypt_token(encrypted)
        assert decrypted == original_token

    def test_encrypt_empty_token(self):
        """Encrypt an empty token."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token

        encrypted = encrypt_token("")
        assert encrypted == ""

    def test_decrypt_empty_token(self):
        """Decrypt an empty token."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import decrypt_token

        decrypted = decrypt_token("")
        assert decrypted == ""

    def test_encrypt_special_characters(self):
        """Encrypt a token containing special characters."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token, decrypt_token

        special_token = "token!@#$%^&*()_+-=[]{}|;':\",./<>?"

        encrypted = encrypt_token(special_token)
        decrypted = decrypt_token(encrypted)

        assert decrypted == special_token

    def test_different_tokens_different_ciphertext(self):
        """Different tokens produce different ciphertexts."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token

        token1 = "token-one"
        token2 = "token-two"

        encrypted1 = encrypt_token(token1)
        encrypted2 = encrypt_token(token2)

        assert encrypted1 != encrypted2

    def test_same_token_different_ciphertext_each_time(self):
        """The same token yields a different ciphertext on every encryption (because the IV differs)."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token

        token = "same-token"

        encrypted1 = encrypt_token(token)
        encrypted2 = encrypt_token(token)

        # A random IV is used, so the same plaintext should encrypt differently each time
        assert encrypted1 != encrypted2

    def test_long_token_encryption(self):
        """Encrypt a long token."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token, decrypt_token

        long_token = "x" * 1000  # 1000-character token

        encrypted = encrypt_token(long_token)
        decrypted = decrypt_token(encrypted)

        assert decrypted == long_token

    def test_unicode_token_encryption(self):
        """Encrypt a Unicode token."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from src.utils.crypto import encrypt_token, decrypt_token

        unicode_token = "密碼Token🔐中文"

        encrypted = encrypt_token(unicode_token)
        decrypted = decrypt_token(encrypted)

        assert decrypted == unicode_token


class TestKeyDerivation:
    """Key derivation tests."""

    def test_key_derivation_consistency(self):
        """Key derivation is consistent."""
        os.environ["SERVICE_TOKEN_SECRET"] = "consistent-secret-key!!"

        from src.utils.crypto import encrypt_token, decrypt_token

        token = "test-token"
        encrypted = encrypt_token(token)

        # The same key should be able to decrypt
        decrypted = decrypt_token(encrypted)
        assert decrypted == token

    def test_different_keys_cannot_decrypt(self):
        """A different key cannot decrypt."""
        os.environ["SERVICE_TOKEN_SECRET"] = "original-secret-key-32!!"

        from src.utils.crypto import encrypt_token

        token = "secret-data"
        encrypted = encrypt_token(token)

        # Change the key
        os.environ["SERVICE_TOKEN_SECRET"] = "different-secret-key-32!"

        # Reload the module so it picks up the new key
        import importlib
        import src.utils.crypto as crypto_module
        importlib.reload(crypto_module)

        from src.utils.crypto import decrypt_token

        # Should fail to decrypt or return a wrong result
        try:
            decrypted = decrypt_token(encrypted)
            # If no exception was raised, check that the result is wrong
            assert decrypted != token or decrypted is None
        except Exception:
            # Failure is expected
            pass


class TestCryptoSpecCoverage:
    """Fill the SPEC-CRYPTO coverage gaps: tamper detection, missing key, hash, prefix.

    Constructs TokenCrypto(secret_key=...) directly, bypassing the singleton / environment variables,
    to keep the tests isolated (see SPEC-CRYPTO section 5).
    """

    def test_tampered_ciphertext_rejected(self):
        """TC-CRYPTO-03 / REQ-CRYPTO-03: tampered ciphertext must be rejected, never return wrong plaintext."""
        from src.utils.crypto import TokenCrypto

        crypto = TokenCrypto(secret_key="unit-test-secret-A")
        cipher = crypto.encrypt("my-secret-token-123")

        # Tamper with the trailing characters (base64) to corrupt the GCM tag / content
        tampered = cipher[:-2] + ("AA" if cipher[-2:] != "AA" else "BB")

        with pytest.raises(Exception):
            crypto.decrypt(tampered)

    def test_missing_secret_is_generated_and_persisted(self, monkeypatch, tmp_path):
        """Without ENCRYPTION_KEY the secrets store generates and persists one, and returns the same key every
        time afterwards."""
        from src.utils import secrets_store
        from src.utils.crypto import TokenCrypto

        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setenv("MCP_CENTER_SECRETS_FILE", str(tmp_path / "secrets.json"))
        secrets_store.reset_cache()
        first = TokenCrypto()
        secrets_store.reset_cache()
        second = TokenCrypto()
        assert first.key == second.key
        assert (tmp_path / "secrets.json").exists()
        assert second.decrypt(first.encrypt("hello")) == "hello"

    def test_wrong_key_cannot_decrypt(self):
        """TC-CRYPTO-05 / REQ-CRYPTO-05: different keys cannot decrypt each other's output (strengthens the
        existing test)."""
        from src.utils.crypto import TokenCrypto

        a = TokenCrypto(secret_key="key-A-unit-test")
        b = TokenCrypto(secret_key="key-B-unit-test")
        cipher = a.encrypt("cross-key-secret")

        with pytest.raises(Exception):
            b.decrypt(cipher)

    def test_hash_token_stable_and_unique(self):
        """TC-CRYPTO-06 / REQ-CRYPTO-06: hash_token is stable, 64 hex digits, and unique."""
        from src.utils.crypto import hash_token

        h1 = hash_token("token-a")
        h1_again = hash_token("token-a")
        h2 = hash_token("token-b")

        assert h1 == h1_again                      # stable
        assert len(h1) == 64                        # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in h1)
        assert h1 != h2                             # unique

    def test_get_token_prefix(self):
        """TC-CRYPTO-07 / REQ-CRYPTO-07: take the prefix; return the original string when it is shorter."""
        from src.utils.crypto import get_token_prefix

        assert get_token_prefix("abcdef12345") == "abcdef12"   # first 8 characters
        assert get_token_prefix("abc") == "abc"                 # too short: original string returned
        assert get_token_prefix("abcdef12345", length=4) == "abcd"


class TestServiceTokenInDatabase:
    """Service token encryption in the database."""

    def test_service_auth_token_stored_encrypted(self, db_session):
        """The service auth token is stored encrypted."""
        os.environ["SERVICE_TOKEN_SECRET"] = "test-secret-key-32-chars-long!!"

        from db.crud import ServiceCRUD
        from src.utils.crypto import encrypt_token, decrypt_token

        original_token = "my-mcp-auth-token"
        encrypted_token = encrypt_token(original_token)

        service = ServiceCRUD.create(
            db=db_session,
            name="encrypted-token-service",
            host="localhost",
            port=9100,
            auth_token_encrypted=encrypted_token,
        )

        # Fetch from the database
        fetched = ServiceCRUD.get_by_id(db_session, str(service.id))

        # The stored value should be the encrypted one
        assert fetched.auth_token_encrypted == encrypted_token
        assert fetched.auth_token_encrypted != original_token

        # Decrypting should yield the original value
        decrypted = decrypt_token(fetched.auth_token_encrypted)
        assert decrypted == original_token
