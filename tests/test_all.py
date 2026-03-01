"""Tests for xtea_cython."""

import os
import pytest

# Import after build
try:
    from xtea_cython import encrypt, decrypt, encrypt_block, decrypt_block, BLOCK_SIZE
except ImportError:
    pytestmark = pytest.mark.skip(reason="xtea_cython not built")


class TestBlockEncrypt:
    """Test raw block encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Basic encrypt/decrypt should be reversible."""
        key = b"0123456789abcdef"  # 16 bytes
        data = b"12345678"  # 8 bytes

        encrypted = encrypt_block(data, key)
        decrypted = decrypt_block(encrypted, key)

        assert decrypted == data

    def test_encrypt_produces_different_output(self):
        """Encryption should change the data."""
        key = b"0123456789abcdef"
        data = b"12345678"

        encrypted = encrypt_block(data, key)

        assert encrypted != data
        assert len(encrypted) == 8

    def test_same_input_same_output(self):
        """Same input should produce same output (deterministic)."""
        key = b"0123456789abcdef"
        data = b"12345678"

        encrypted1 = encrypt_block(data, key)
        encrypted2 = encrypt_block(data, key)

        assert encrypted1 == encrypted2

    def test_invalid_data_length(self):
        """Should reject non-8-byte data."""
        key = b"0123456789abcdef"

        with pytest.raises(ValueError, match="8 bytes"):
            encrypt_block(b"short", key)

        with pytest.raises(ValueError, match="8 bytes"):
            encrypt_block(b"toolongdata!", key)

    def test_invalid_key_length(self):
        """Should reject non-16-byte keys."""
        data = b"12345678"

        with pytest.raises(ValueError, match="16 bytes"):
            encrypt_block(data, b"short")

        with pytest.raises(ValueError, match="16 bytes"):
            encrypt_block(data, b"thiskeyiswaytoolong1234567890")


class TestCBCMode:
    """Test CBC mode encryption/decryption."""

    def test_cbc_roundtrip(self):
        """CBC encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Hello, World!"

        encrypted = encrypt(data, key, iv)
        decrypted = decrypt(encrypted, key, iv)

        assert decrypted == data

    def test_cbc_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)
        iv = os.urandom(8)

        encrypted = encrypt(b"", key, iv)
        decrypted = decrypt(encrypted, key, iv)

        assert decrypted == b""

    def test_cbc_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"A" * 100  # 100 bytes = 13 blocks with padding

        encrypted = encrypt(data, key, iv)
        decrypted = decrypt(encrypted, key, iv)

        assert decrypted == data
        assert len(encrypted) % BLOCK_SIZE == 0

    def test_cbc_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)
        data = b"Same data"

        encrypted1 = encrypt(data, key, iv1)
        encrypted2 = encrypt(data, key, iv2)

        assert encrypted1 != encrypted2

    def test_cbc_same_iv_same_ciphertext(self):
        """Same IV should produce same ciphertext."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Test data"

        encrypted1 = encrypt(data, key, iv)
        encrypted2 = encrypt(data, key, iv)

        assert encrypted1 == encrypted2

    def test_cbc_wrong_key(self):
        """Decryption with wrong key should fail."""
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        iv = os.urandom(8)
        data = b"Secret message"

        encrypted = encrypt(data, key1, iv)

        with pytest.raises(ValueError):
            decrypt(encrypted, key2, iv)

    def test_cbc_wrong_iv(self):
        """Decryption with wrong IV should produce garbage."""
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)
        data = b"Secret message"

        encrypted = encrypt(data, key, iv1)
        decrypted = decrypt(encrypted, key, iv2)

        assert decrypted != data


class TestPadding:
    """Test PKCS#7 padding."""

    def test_pad_empty(self):
        """Padding empty data should add one full block."""
        from xtea_cython import pkcs7_pad

        padded = pkcs7_pad(b"")
        assert len(padded) == 8
        assert padded == b"\x08" * 8  # 8 bytes of padding value 8

    def test_pad_exact_block(self):
        """Exact block size should add full padding block."""
        from xtea_cython import pkcs7_pad

        data = b"12345678"  # exactly 8 bytes
        padded = pkcs7_pad(data)

        assert len(padded) == 16
        assert padded[-1] == 8

    def test_unpad_valid(self):
        """Valid padding should be removed correctly."""
        from xtea_cython import pkcs7_unpad

        data = b"123456" + b"\x02\x02"
        unpadded = pkcs7_unpad(data)

        assert unpadded == b"123456"

    def test_unpad_invalid(self):
        """Invalid padding should raise error."""
        from xtea_cython import pkcs7_unpad

        with pytest.raises(ValueError):
            pkcs7_unpad(b"12345678")  # No valid padding


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
