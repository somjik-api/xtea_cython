"""Compatibility tests with PyPI xtea library."""

import pytest

# Import after build
try:
    from xtea_cython import (
        encrypt_block,
        decrypt_block,
        encrypt_cbc,
        decrypt_cbc,
        encrypt_ecb,
        decrypt_ecb,
        pkcs7_pad,
    )
except ImportError:
    pytestmark = pytest.mark.skip(reason="xtea_cython not built")


class TestXTEACompatibility:
    """Test compatibility with PyPI xtea library."""

    def test_raw_block_compatibility(self):
        """Test raw block encryption matches xtea library."""
        try:
            import xtea
        except ImportError:
            pytest.skip("xtea library not installed")

        key = b"0123456789abcdef"  # 16 bytes
        data = b"12345678"  # 8 bytes

        # Our implementation
        our_encrypted = encrypt_block(data, key)
        our_decrypted = decrypt_block(our_encrypted, key)

        # PyPI xtea library
        cipher = xtea.new(key, mode=xtea.MODE_ECB)
        their_encrypted = cipher.encrypt(data)
        their_decrypted = cipher.decrypt(their_encrypted)

        # Check roundtrip
        assert our_decrypted == data
        assert their_decrypted == data

        # Check compatibility
        assert our_encrypted == their_encrypted, f"Our: {our_encrypted.hex()}, Their: {their_encrypted.hex()}"

    def test_ecb_mode_compatibility(self):
        """Test ECB mode compatibility."""
        try:
            import xtea
        except ImportError:
            pytest.skip("xtea library not installed")

        key = b"0123456789abcdef"
        data = b"Hello, World! Test message."

        # Our implementation (with automatic padding)
        our_encrypted = encrypt_ecb(data, key)
        our_decrypted = decrypt_ecb(our_encrypted, key)

        # PyPI xtea library (manual padding needed)
        padded = pkcs7_pad(data)
        cipher = xtea.new(key, mode=xtea.MODE_ECB)
        their_encrypted = cipher.encrypt(padded)

        # Check roundtrip
        assert our_decrypted == data

        # Check compatibility
        assert our_encrypted == their_encrypted, f"Our: {our_encrypted.hex()}, Their: {their_encrypted.hex()}"

    def test_cbc_mode_compatibility(self):
        """Test CBC mode compatibility."""
        try:
            import xtea
        except ImportError:
            pytest.skip("xtea library not installed")

        key = b"0123456789abcdef"
        iv = b"abcdefgh"  # 8 bytes
        data = b"Hello, World! Test message."

        # Our implementation (with automatic padding)
        our_encrypted = encrypt_cbc(data, key, iv)
        our_decrypted = decrypt_cbc(our_encrypted, key, iv)

        # PyPI xtea library (manual padding needed)
        padded = pkcs7_pad(data)
        cipher = xtea.new(key, mode=xtea.MODE_CBC, IV=iv)
        their_encrypted = cipher.encrypt(padded)

        # Check roundtrip
        assert our_decrypted == data

        # Check compatibility
        assert our_encrypted == their_encrypted, f"Our: {our_encrypted.hex()}, Their: {their_encrypted.hex()}"

    def test_multiple_test_vectors(self):
        """Test multiple test vectors."""
        try:
            import xtea
        except ImportError:
            pytest.skip("xtea library not installed")

        test_cases = [
            (b"0123456789abcdef", b"12345678"),
            (b"\x00" * 16, b"\x00" * 8),
            (b"\xff" * 16, b"\xff" * 8),
            (b"DeadBeefCafeBabe", b"FeedFac0"),  # 8 bytes
        ]

        for key, data in test_cases:
            our_encrypted = encrypt_block(data, key)
            our_decrypted = decrypt_block(our_encrypted, key)

            cipher = xtea.new(key, mode=xtea.MODE_ECB)
            their_encrypted = cipher.encrypt(data)

            assert our_encrypted == their_encrypted, f"Key: {key.hex()}, Data: {data.hex()}"
            assert our_decrypted == data


class TestKnownTestVectors:
    """Test against known XTEA test vectors."""

    def test_zero_vector(self):
        """
        Test with all zeros.
        Key: 00000000 00000000 00000000 00000000
        Plaintext: 00000000 00000000
        """
        key = b"\x00" * 16
        plaintext = b"\x00" * 8

        encrypted = encrypt_block(plaintext, key)
        decrypted = decrypt_block(encrypted, key)

        assert decrypted == plaintext

        # Verify with xtea library if available
        try:
            import xtea
            cipher = xtea.new(key, mode=xtea.MODE_ECB)
            their_encrypted = cipher.encrypt(plaintext)
            assert encrypted == their_encrypted
        except ImportError:
            pass

    def test_various_keys(self):
        """Test with various keys to ensure algorithm correctness."""
        test_cases = [
            # (key, plaintext) - we verify roundtrip
            (b"\x00" * 16, b"\x00" * 8),
            (b"\xff" * 16, b"\xff" * 8),
            (b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
             b"\x01\x23\x45\x67\x89\xab\xcd\xef"),
        ]

        for key, plaintext in test_cases:
            encrypted = encrypt_block(plaintext, key)
            decrypted = decrypt_block(encrypted, key)
            assert decrypted == plaintext, f"Roundtrip failed for key {key.hex()}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
