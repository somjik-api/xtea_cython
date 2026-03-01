"""Tests for all encryption modes."""

import os
import pytest

# Import after build
try:
    from xtea_cython import (
        encrypt_cbc,
        decrypt_cbc,
        encrypt_ecb,
        decrypt_ecb,
        encrypt_ctr,
        decrypt_ctr,
        encrypt_cfb,
        decrypt_cfb,
        encrypt_ofb,
        decrypt_ofb,
        BLOCK_SIZE,
    )
except ImportError:
    pytestmark = pytest.mark.skip(reason="xtea_cython not built")


class TestECBMode:
    """Test ECB mode encryption/decryption."""

    def test_ecb_roundtrip(self):
        """ECB encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        data = b"Hello, World!"

        encrypted = encrypt_ecb(data, key, auto_pad=True)
        decrypted = decrypt_ecb(encrypted, key, auto_unpad=True)

        assert decrypted == data

    def test_ecb_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)

        encrypted = encrypt_ecb(b"", key, auto_pad=True)
        decrypted = decrypt_ecb(encrypted, key, auto_unpad=True)

        assert decrypted == b""

    def test_ecb_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        data = b"A" * 100  # 100 bytes = 13 blocks with padding

        encrypted = encrypt_ecb(data, key, auto_pad=True)
        decrypted = decrypt_ecb(encrypted, key, auto_unpad=True)

        assert decrypted == data
        assert len(encrypted) % BLOCK_SIZE == 0

    def test_ecb_same_input_same_output(self):
        """Same input should produce same output (deterministic)."""
        key = os.urandom(16)
        data = b"Test data"

        encrypted1 = encrypt_ecb(data, key, auto_pad=True)
        encrypted2 = encrypt_ecb(data, key, auto_pad=True)

        assert encrypted1 == encrypted2


class TestCBCMode:
    """Test CBC mode encryption/decryption."""

    def test_cbc_roundtrip(self):
        """CBC encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Hello, World!"

        encrypted = encrypt_cbc(data, key, iv, auto_pad=True)
        decrypted = decrypt_cbc(encrypted, key, iv, auto_unpad=True)

        assert decrypted == data

    def test_cbc_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)
        iv = os.urandom(8)

        encrypted = encrypt_cbc(b"", key, iv, auto_pad=True)
        decrypted = decrypt_cbc(encrypted, key, iv, auto_unpad=True)

        assert decrypted == b""

    def test_cbc_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"A" * 100

        encrypted = encrypt_cbc(data, key, iv, auto_pad=True)
        decrypted = decrypt_cbc(encrypted, key, iv, auto_unpad=True)

        assert decrypted == data
        assert len(encrypted) % BLOCK_SIZE == 0

    def test_cbc_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)
        data = b"Same data"

        encrypted1 = encrypt_cbc(data, key, iv1, auto_pad=True)
        encrypted2 = encrypt_cbc(data, key, iv2, auto_pad=True)

        assert encrypted1 != encrypted2

    def test_cbc_same_iv_same_ciphertext(self):
        """Same IV should produce same ciphertext."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Test data"

        encrypted1 = encrypt_cbc(data, key, iv, auto_pad=True)
        encrypted2 = encrypt_cbc(data, key, iv, auto_pad=True)

        assert encrypted1 == encrypted2


class TestCFBMode:
    """Test CFB mode encryption/decryption."""

    def test_cfb_roundtrip(self):
        """CFB encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Hello, World!"

        encrypted = encrypt_cfb(data, key, iv)
        decrypted = decrypt_cfb(encrypted, key, iv)

        assert decrypted == data

    def test_cfb_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)
        iv = os.urandom(8)

        encrypted = encrypt_cfb(b"", key, iv)
        decrypted = decrypt_cfb(encrypted, key, iv)

        assert encrypted == b""
        assert decrypted == b""

    def test_cfb_partial_block(self):
        """Should handle data not aligned to block size."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"1234567"  # 7 bytes, not 8

        encrypted = encrypt_cfb(data, key, iv)
        decrypted = decrypt_cfb(encrypted, key, iv)

        assert decrypted == data
        assert len(encrypted) == len(data)

    def test_cfb_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"A" * 100

        encrypted = encrypt_cfb(data, key, iv)
        decrypted = decrypt_cfb(encrypted, key, iv)

        assert decrypted == data
        assert len(encrypted) == len(data)  # CFB preserves length

    def test_cfb_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)
        data = b"Same data"

        encrypted1 = encrypt_cfb(data, key, iv1)
        encrypted2 = encrypt_cfb(data, key, iv2)

        assert encrypted1 != encrypted2

    def test_cfb_various_lengths(self):
        """Test CFB with various data lengths."""
        key = os.urandom(16)
        iv = os.urandom(8)

        for length in [1, 7, 8, 9, 15, 16, 17, 100, 1000]:
            data = os.urandom(length)
            encrypted = encrypt_cfb(data, key, iv)
            decrypted = decrypt_cfb(encrypted, key, iv)
            assert decrypted == data, f"Failed for length {length}"


class TestOFBMode:
    """Test OFB mode encryption/decryption."""

    def test_ofb_roundtrip(self):
        """OFB encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"Hello, World!"

        encrypted = encrypt_ofb(data, key, iv)
        decrypted = decrypt_ofb(encrypted, key, iv)

        assert decrypted == data

    def test_ofb_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)
        iv = os.urandom(8)

        encrypted = encrypt_ofb(b"", key, iv)
        decrypted = decrypt_ofb(encrypted, key, iv)

        assert encrypted == b""
        assert decrypted == b""

    def test_ofb_partial_block(self):
        """Should handle data not aligned to block size."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"1234567"  # 7 bytes

        encrypted = encrypt_ofb(data, key, iv)
        decrypted = decrypt_ofb(encrypted, key, iv)

        assert decrypted == data
        assert len(encrypted) == len(data)

    def test_ofb_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        iv = os.urandom(8)
        data = b"A" * 100

        encrypted = encrypt_ofb(data, key, iv)
        decrypted = decrypt_ofb(encrypted, key, iv)

        assert decrypted == data
        assert len(encrypted) == len(data)

    def test_ofb_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        key = os.urandom(16)
        iv1 = os.urandom(8)
        iv2 = os.urandom(8)
        data = b"Same data"

        encrypted1 = encrypt_ofb(data, key, iv1)
        encrypted2 = encrypt_ofb(data, key, iv2)

        assert encrypted1 != encrypted2

    def test_ofb_various_lengths(self):
        """Test OFB with various data lengths."""
        key = os.urandom(16)
        iv = os.urandom(8)

        for length in [1, 7, 8, 9, 15, 16, 17, 100, 1000]:
            data = os.urandom(length)
            encrypted = encrypt_ofb(data, key, iv)
            decrypted = decrypt_ofb(encrypted, key, iv)
            assert decrypted == data, f"Failed for length {length}"


class TestCTRMode:
    """Test CTR mode encryption/decryption."""

    def test_ctr_roundtrip(self):
        """CTR encrypt/decrypt should be reversible."""
        key = os.urandom(16)
        nonce = os.urandom(8)
        data = b"Hello, World!"

        encrypted = encrypt_ctr(data, key, nonce)
        decrypted = decrypt_ctr(encrypted, key, nonce)

        assert decrypted == data

    def test_ctr_empty_data(self):
        """Should handle empty data."""
        key = os.urandom(16)
        nonce = os.urandom(8)

        encrypted = encrypt_ctr(b"", key, nonce)
        decrypted = decrypt_ctr(encrypted, key, nonce)

        assert encrypted == b""
        assert decrypted == b""

    def test_ctr_partial_block(self):
        """Should handle data not aligned to block size."""
        key = os.urandom(16)
        nonce = os.urandom(8)
        data = b"1234567"  # 7 bytes

        encrypted = encrypt_ctr(data, key, nonce)
        decrypted = decrypt_ctr(encrypted, key, nonce)

        assert decrypted == data
        assert len(encrypted) == len(data)

    def test_ctr_multiple_blocks(self):
        """Should handle data spanning multiple blocks."""
        key = os.urandom(16)
        nonce = os.urandom(8)
        data = b"A" * 100

        encrypted = encrypt_ctr(data, key, nonce)
        decrypted = decrypt_ctr(encrypted, key, nonce)

        assert decrypted == data
        assert len(encrypted) == len(data)

    def test_ctr_different_nonce_different_ciphertext(self):
        """Different nonces should produce different ciphertexts."""
        key = os.urandom(16)
        nonce1 = os.urandom(8)
        nonce2 = os.urandom(8)
        data = b"Same data"

        encrypted1 = encrypt_ctr(data, key, nonce1)
        encrypted2 = encrypt_ctr(data, key, nonce2)

        assert encrypted1 != encrypted2

    def test_ctr_various_lengths(self):
        """Test CTR with various data lengths."""
        key = os.urandom(16)
        nonce = os.urandom(8)

        for length in [1, 7, 8, 9, 15, 16, 17, 100, 1000]:
            data = os.urandom(length)
            encrypted = encrypt_ctr(data, key, nonce)
            decrypted = decrypt_ctr(encrypted, key, nonce)
            assert decrypted == data, f"Failed for length {length}"

    def test_ctr_counter_wraparound(self):
        """Test that counter wrap-around raises ValueError."""
        from xtea_cython.modes import _increment_counter

        # Max counter value (all 0xFF) - incrementing should raise
        max_counter = b'\xff\xff\xff\xff\xff\xff\xff\xff'
        with pytest.raises(ValueError, match="wrap-around"):
            _increment_counter(max_counter)

        # Normal increment should work
        normal_counter = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        result = _increment_counter(normal_counter)
        assert result == b'\x00\x00\x00\x00\x00\x00\x00\x01'


class TestModeValidation:
    """Test parameter validation for all modes."""

    def test_invalid_key_length(self):
        """Should reject keys that are not 16 bytes."""
        data = b"test"
        iv = os.urandom(8)

        with pytest.raises(ValueError, match="Key"):
            encrypt_ecb(data, b"short")

        with pytest.raises(ValueError, match="Key"):
            encrypt_cbc(data, b"short", iv)

        with pytest.raises(ValueError, match="Key"):
            encrypt_cfb(data, b"short", iv)

        with pytest.raises(ValueError, match="Key"):
            encrypt_ofb(data, b"short", iv)

        with pytest.raises(ValueError, match="Key"):
            encrypt_ctr(data, b"short", iv)

    def test_invalid_iv_length(self):
        """Should reject IVs that are not 8 bytes."""
        key = os.urandom(16)
        data = b"test"
        bad_iv = b"short"

        with pytest.raises(ValueError, match="IV"):
            encrypt_cbc(data, key, bad_iv)

        with pytest.raises(ValueError, match="IV"):
            encrypt_cfb(data, key, bad_iv)

        with pytest.raises(ValueError, match="IV"):
            encrypt_ofb(data, key, bad_iv)

    def test_invalid_nonce_length(self):
        """Should reject nonces that are not 8 bytes."""
        key = os.urandom(16)
        data = b"test"
        bad_nonce = b"short"

        with pytest.raises(ValueError, match="Nonce"):
            encrypt_ctr(data, key, bad_nonce)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
