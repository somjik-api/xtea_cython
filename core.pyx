# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
# cython: nonecheck=False
# cython: profile=False
"""
XTEA (Extended TEA) core implementation in Cython.

XTEA is a block cipher operating on 8-byte blocks with a 16-byte key.
This implementation is compatible with the PyPI xtea library.
"""

import warnings
from libc.stdint cimport uint32_t


class SecurityWarning(UserWarning):
    """Warning for security-related issues."""
    pass

cdef uint32_t DELTA = 0x9e3779b9
cdef uint32_t DEFAULT_ROUNDS = 32  # 32 cycles = 64 rounds
cdef uint32_t MIN_ROUNDS = 8  # Minimum secure rounds


cdef inline void xtea_encrypt_block(
    uint32_t *v0,
    uint32_t *v1,
    uint32_t *key,
    uint32_t rounds
) noexcept nogil:
    """
    XTEA encryption for a single 8-byte block.

    Args:
        v0, v1: Two 32-bit integers to encrypt (in-place)
        key: 128-bit key as 4 x 32-bit integers
        rounds: Number of cycles (0 = default: 32)
    """
    cdef uint32_t sum_val = 0
    cdef uint32_t i
    cdef uint32_t n = rounds if rounds > 0 else DEFAULT_ROUNDS

    for i in range(n):
        v0[0] = v0[0] + ((((v1[0] << 4) ^ (v1[0] >> 5)) + v1[0]) ^ (sum_val + key[sum_val & 3]))
        sum_val = sum_val + DELTA
        v1[0] = v1[0] + ((((v0[0] << 4) ^ (v0[0] >> 5)) + v0[0]) ^ (sum_val + key[(sum_val >> 11) & 3]))


cdef inline void xtea_decrypt_block(
    uint32_t *v0,
    uint32_t *v1,
    uint32_t *key,
    uint32_t rounds
) noexcept nogil:
    """
    XTEA decryption for a single 8-byte block.

    Args:
        v0, v1: Two 32-bit integers to decrypt (in-place)
        key: 128-bit key as 4 x 32-bit integers
        rounds: Number of cycles (0 = default: 32)
    """
    cdef uint32_t n = rounds if rounds > 0 else DEFAULT_ROUNDS
    cdef uint32_t sum_val = n * DELTA
    cdef uint32_t i

    for i in range(n):
        v1[0] = v1[0] - ((((v0[0] << 4) ^ (v0[0] >> 5)) + v0[0]) ^ (sum_val + key[(sum_val >> 11) & 3]))
        sum_val = sum_val - DELTA
        v0[0] = v0[0] - ((((v1[0] << 4) ^ (v1[0] >> 5)) + v1[0]) ^ (sum_val + key[sum_val & 3]))


cdef inline void bytes_to_uints_be(const unsigned char *data, uint32_t *out, int n) noexcept nogil:
    """Convert n*4 bytes to n unsigned integers (big-endian)."""
    cdef int i
    for i in range(n):
        out[i] = (<uint32_t>data[4*i] << 24) | (<uint32_t>data[4*i + 1] << 16) | (<uint32_t>data[4*i + 2] << 8) | <uint32_t>data[4*i + 3]


cdef inline void uints_to_bytes_be(uint32_t *data, unsigned char *out, int n) noexcept nogil:
    """Convert n unsigned integers to n*4 bytes (big-endian)."""
    cdef int i
    for i in range(n):
        out[4*i] = (data[i] >> 24) & 0xFF
        out[4*i + 1] = (data[i] >> 16) & 0xFF
        out[4*i + 2] = (data[i] >> 8) & 0xFF
        out[4*i + 3] = data[i] & 0xFF


# Public Python API

def encrypt_block(bytes data not None, bytes key not None, unsigned int rounds=0):
    """
    Encrypt a single 8-byte block using XTEA.

    Args:
        data: 8 bytes of data to encrypt
        key: 16-byte encryption key
        rounds: Number of cycles (0 = default: 32)

    Returns:
        8 bytes of encrypted data

    Raises:
        ValueError: If data or key length is invalid

    Note:
        For security, use modes like CBC or CTR instead of raw block encryption.
    """
    if len(data) != 8:
        raise ValueError("Data must be exactly 8 bytes")
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes")

    # Allow 0 for default, but warn for very low rounds
    effective_rounds = rounds if rounds > 0 else DEFAULT_ROUNDS
    if 0 < rounds < MIN_ROUNDS:
        warnings.warn(
            f"Using {rounds} rounds is insecure. Minimum recommended: {MIN_ROUNDS}. "
            f"Security may be compromised.",
            SecurityWarning,
            stacklevel=2
        )

    cdef uint32_t v0, v1
    cdef uint32_t k[4]
    cdef unsigned char out[8]
    cdef const unsigned char *data_ptr = data
    cdef const unsigned char *key_ptr = key

    # Parse data as big-endian
    v0 = (<uint32_t>data_ptr[0] << 24) | (<uint32_t>data_ptr[1] << 16) | (<uint32_t>data_ptr[2] << 8) | <uint32_t>data_ptr[3]
    v1 = (<uint32_t>data_ptr[4] << 24) | (<uint32_t>data_ptr[5] << 16) | (<uint32_t>data_ptr[6] << 8) | <uint32_t>data_ptr[7]

    # Parse key as big-endian
    bytes_to_uints_be(key_ptr, k, 4)

    with nogil:
        xtea_encrypt_block(&v0, &v1, k, rounds)

    # Output as big-endian
    out[0] = (v0 >> 24) & 0xFF
    out[1] = (v0 >> 16) & 0xFF
    out[2] = (v0 >> 8) & 0xFF
    out[3] = v0 & 0xFF
    out[4] = (v1 >> 24) & 0xFF
    out[5] = (v1 >> 16) & 0xFF
    out[6] = (v1 >> 8) & 0xFF
    out[7] = v1 & 0xFF

    return bytes(out[:8])


def decrypt_block(bytes data not None, bytes key not None, unsigned int rounds=0):
    """
    Decrypt a single 8-byte block using XTEA.

    Args:
        data: 8 bytes of data to decrypt
        key: 16-byte decryption key
        rounds: Number of cycles (0 = default: 32)

    Returns:
        8 bytes of decrypted data

    Raises:
        ValueError: If data or key length is invalid
    """
    if len(data) != 8:
        raise ValueError("Data must be exactly 8 bytes")
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes")

    cdef uint32_t v0, v1
    cdef uint32_t k[4]
    cdef unsigned char out[8]
    cdef const unsigned char *data_ptr = data
    cdef const unsigned char *key_ptr = key

    # Parse data as big-endian
    v0 = (<uint32_t>data_ptr[0] << 24) | (<uint32_t>data_ptr[1] << 16) | (<uint32_t>data_ptr[2] << 8) | <uint32_t>data_ptr[3]
    v1 = (<uint32_t>data_ptr[4] << 24) | (<uint32_t>data_ptr[5] << 16) | (<uint32_t>data_ptr[6] << 8) | <uint32_t>data_ptr[7]

    # Parse key as big-endian
    bytes_to_uints_be(key_ptr, k, 4)

    with nogil:
        xtea_decrypt_block(&v0, &v1, k, rounds)

    # Output as big-endian
    out[0] = (v0 >> 24) & 0xFF
    out[1] = (v0 >> 16) & 0xFF
    out[2] = (v0 >> 8) & 0xFF
    out[3] = v0 & 0xFF
    out[4] = (v1 >> 24) & 0xFF
    out[5] = (v1 >> 16) & 0xFF
    out[6] = (v1 >> 8) & 0xFF
    out[7] = v1 & 0xFF

    return bytes(out[:8])
