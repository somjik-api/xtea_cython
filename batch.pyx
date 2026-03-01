# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
"""
XTEA batch processing module - interleaved execution for better ILP.
"""

cdef extern from "xtea_batch.h":
    void xtea_encrypt_blocks_interleaved(
        const unsigned char *data,
        unsigned char *out,
        const unsigned char *key,
        unsigned int num_blocks,
        unsigned int rounds
    )
    void xtea_decrypt_blocks_interleaved(
        const unsigned char *data,
        unsigned char *out,
        const unsigned char *key,
        unsigned int num_blocks,
        unsigned int rounds
    )


def encrypt_blocks_batch(bytes data not None, bytes key not None, unsigned int rounds=0):
    """
    Encrypt multiple 8-byte blocks using interleaved batch processing.

    This uses interleaved execution for better instruction-level parallelism (ILP).
    Processes 2 blocks at a time for improved CPU pipelining.

    Args:
        data: Multiple of 8 bytes (8, 16, 24, ...)
        key: 16-byte encryption key
        rounds: Number of XTEA cycles (0 = default: 32, max: 256)

    Returns:
        Encrypted data (same length as input)
    """
    cdef:
        size_t data_len = len(data)
        size_t key_len = len(key)
        unsigned int num_blocks
        unsigned int effective_rounds
        bytearray result

    if data_len == 0:
        return b""

    if data_len % 8 != 0:
        raise ValueError("Data length must be a multiple of 8 bytes")

    if key_len != 16:
        raise ValueError("Key must be exactly 16 bytes")

    # Bounds check to prevent integer overflow in C code
    effective_rounds = rounds if rounds > 0 else 32
    if effective_rounds > 256:
        raise ValueError("Rounds must be <= 256 to prevent overflow")

    num_blocks = data_len // 8
    result = bytearray(data_len)

    xtea_encrypt_blocks_interleaved(
        <const unsigned char *>data,
        <unsigned char *>result,
        <const unsigned char *>key,
        num_blocks,
        rounds
    )

    return bytes(result)


def decrypt_blocks_batch(bytes data not None, bytes key not None, unsigned int rounds=0):
    """
    Decrypt multiple 8-byte blocks using interleaved batch processing.

    This uses interleaved execution for better instruction-level parallelism (ILP).

    Args:
        data: Multiple of 8 bytes (8, 16, 24, ...)
        key: 16-byte decryption key
        rounds: Number of XTEA cycles (0 = default: 32, max: 256)

    Returns:
        Decrypted data (same length as input)
    """
    cdef:
        size_t data_len = len(data)
        size_t key_len = len(key)
        unsigned int num_blocks
        unsigned int effective_rounds
        bytearray result

    if data_len == 0:
        return b""

    if data_len % 8 != 0:
        raise ValueError("Data length must be a multiple of 8 bytes")

    if key_len != 16:
        raise ValueError("Key must be exactly 16 bytes")

    # Bounds check to prevent integer overflow in C code
    effective_rounds = rounds if rounds > 0 else 32
    if effective_rounds > 256:
        raise ValueError("Rounds must be <= 256 to prevent overflow")

    num_blocks = data_len // 8
    result = bytearray(data_len)

    xtea_decrypt_blocks_interleaved(
        <const unsigned char *>data,
        <unsigned char *>result,
        <const unsigned char *>key,
        num_blocks,
        rounds
    )

    return bytes(result)
