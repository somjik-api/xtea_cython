"""
xtea_cython - XTEA encryption with multiple modes.

A high-performance XTEA implementation using Cython with support for
ECB, CBC, CFB, OFB, and CTR modes.

Usage:
    import os
    from xtea_cython import encrypt_cbc, decrypt_cbc

    key = os.urandom(16)  # 128-bit key
    iv = os.urandom(8)    # 64-bit IV

    plaintext = b"Hello, World!"
    ciphertext = encrypt_cbc(plaintext, key, iv)
    decrypted = decrypt_cbc(ciphertext, key, iv)

    assert plaintext == decrypted
"""

from .core import encrypt_block, decrypt_block, SecurityWarning
from .modes import (
    # Helpers
    generate_key,
    generate_iv,
    # Padding
    pkcs7_pad,
    pkcs7_unpad,
    BLOCK_SIZE,
    # ECB mode
    encrypt_ecb,
    decrypt_ecb,
    # CBC mode
    encrypt_cbc,
    decrypt_cbc,
    # CFB mode
    encrypt_cfb,
    decrypt_cfb,
    # OFB mode
    encrypt_ofb,
    decrypt_ofb,
    # CTR mode
    encrypt_ctr,
    decrypt_ctr,
    # Backward compatibility (CBC as default)
    encrypt,
    decrypt,
)

__version__ = "0.1.0"
__all__ = [
    # Core
    "encrypt_block",
    "decrypt_block",
    "BLOCK_SIZE",
    # Helpers
    "generate_key",
    "generate_iv",
    # Padding
    "pkcs7_pad",
    "pkcs7_unpad",
    # ECB mode
    "encrypt_ecb",
    "decrypt_ecb",
    # CBC mode
    "encrypt_cbc",
    "decrypt_cbc",
    # CFB mode
    "encrypt_cfb",
    "decrypt_cfb",
    # OFB mode
    "encrypt_ofb",
    "decrypt_ofb",
    # CTR mode
    "encrypt_ctr",
    "decrypt_ctr",
    # Backward compatibility
    "encrypt",
    "decrypt",
    # Security
    "SecurityWarning",
]
