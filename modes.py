"""
Encryption modes for XTEA.

Provides ECB, CBC, CFB, OFB, and CTR modes with security hardening.
"""

import os
import warnings

from .core import encrypt_block, decrypt_block, SecurityWarning


BLOCK_SIZE = 8  # XTEA block size in bytes
KEY_SIZE = 16   # XTEA key size in bytes
DEFAULT_ROUNDS = 32  # Default secure rounds
MIN_SECURE_ROUNDS = 8  # Minimum recommended rounds


def generate_key(size: int = KEY_SIZE) -> bytes:
    """
    Generate a cryptographically secure random key.

    Args:
        size: Key size in bytes (default: 16 for XTEA)

    Returns:
        Random key of specified size.

    Note:
        XTEA requires 16-byte keys. Only override size for compatibility
        with other systems.
    """
    return os.urandom(size)


def generate_iv(size: int = BLOCK_SIZE) -> bytes:
    """
    Generate a cryptographically secure random IV/nonce.

    Args:
        size: IV size in bytes (default: 8 for XTEA block size)

    Returns:
        Random IV of specified size.

    Note:
        XTEA uses 8-byte blocks, so IV should be 8 bytes for CBC, CFB, OFB.
        CTR mode uses 8-byte nonces.
    """
    return os.urandom(size)


def _validate_key(key: bytes) -> None:
    """Validate encryption key."""
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes")


def _validate_iv(iv: bytes, name: str = "IV") -> None:
    """Validate initialization vector/nonce."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"{name} must be exactly {BLOCK_SIZE} bytes")


def _validate_rounds(rounds: int) -> int:
    """Validate and return rounds, using default if 0. Warns if below minimum secure rounds."""
    if rounds == 0:
        return DEFAULT_ROUNDS
    if 0 < rounds < MIN_SECURE_ROUNDS:
        warnings.warn(
            f"Using {rounds} rounds is insecure. Minimum recommended: {MIN_SECURE_ROUNDS}. "
            f"Security may be compromised.",
            SecurityWarning,
            stacklevel=3
        )
    return rounds


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length.

    Args:
        a: First byte string
        b: Second byte string (must be same length as a)

    Returns:
        XOR of the two byte strings
    """
    # Use bytearray for efficiency
    return bytes(bytearray(x ^ y for x, y in zip(a, b)))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to data.

    Args:
        data: Data to pad
        block_size: Block size for padding (default: 8)

    Returns:
        Padded data with length multiple of block_size
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.

    Uses constant-time comparison to prevent timing attacks.
    Always processes all BLOCK_SIZE bytes to maintain constant time.
    """
    if not data:
        raise ValueError("Cannot unpad empty data")

    pad_len = data[-1]

    # Validate padding length range (this is not part of constant-time check)
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")

    # True constant-time padding validation without data-dependent branches
    # Always process all BLOCK_SIZE bytes with the same operations
    mask = 0
    for i in range(BLOCK_SIZE):
        byte_val = data[-(i + 1)]
        # Create conditional mask without branching:
        # int(i < pad_len) -> 1 if in padding, 0 otherwise
        # -in_padding -> 0xFF if in padding, 0 otherwise
        in_padding = int(i < pad_len)
        byte_mask = -in_padding
        # XOR gives 0 if equal, non-zero otherwise
        # AND with byte_mask to only include bytes in actual padding
        diff = (byte_val ^ pad_len) & byte_mask
        mask |= diff

    if mask != 0:
        raise ValueError("Invalid padding")

    return data[:-pad_len]


# ============== ECB Mode ==============

def encrypt_ecb(data: bytes, key: bytes, rounds: int = 0) -> bytes:
    """
    Encrypt data using XTEA in ECB mode with PKCS#7 padding.

    .. warning::
        ECB mode is **NOT SECURE** for most use cases!
        - Same plaintext blocks produce same ciphertext blocks
        - Patterns in plaintext are visible in ciphertext
        - Use CBC or CTR mode instead

    Args:
        data: Plaintext data to encrypt
        key: 16-byte encryption key
        rounds: Number of XTEA cycles (0 = default: 32, min recommended: 8)

    Returns:
        Encrypted ciphertext
    """
    _validate_key(key)
    rounds = _validate_rounds(rounds)

    warnings.warn(
        "ECB mode is not secure. Same plaintext blocks produce same ciphertext blocks. "
        "Use CBC or CTR mode instead.",
        SecurityWarning,
        stacklevel=2
    )

    padded = pkcs7_pad(data)
    result = bytearray()

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        result.extend(encrypt_block(block, key, rounds))

    return bytes(result)


def decrypt_ecb(data: bytes, key: bytes, rounds: int = 0) -> bytes:
    """
    Decrypt data using XTEA in ECB mode.

    Args:
        data: Ciphertext to decrypt
        key: 16-byte decryption key
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Decrypted plaintext
    """
    _validate_key(key)
    rounds = _validate_rounds(rounds)

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(f"Data length must be a multiple of {BLOCK_SIZE} bytes")

    if not data:
        return b""

    result = bytearray()

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        result.extend(decrypt_block(block, key, rounds))

    return pkcs7_unpad(bytes(result))


# ============== CBC Mode ==============

def encrypt_cbc(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Encrypt data using XTEA in CBC mode with PKCS#7 padding.

    Args:
        data: Plaintext data to encrypt
        key: 16-byte encryption key
        iv: 8-byte initialization vector (must be unpredictable and unique)
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Encrypted ciphertext

    Note:
        The IV must be unpredictable and never reused with the same key.
        Use os.urandom(8) to generate a secure IV.
    """
    _validate_key(key)
    _validate_iv(iv, "IV")
    rounds = _validate_rounds(rounds)

    padded = pkcs7_pad(data)
    result = bytearray()
    prev = iv

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = xor_bytes(block, prev)
        encrypted = encrypt_block(xored, key, rounds)
        result.extend(encrypted)
        prev = encrypted

    return bytes(result)


def decrypt_cbc(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Decrypt data using XTEA in CBC mode with PKCS#7 padding.

    Args:
        data: Ciphertext to decrypt
        key: 16-byte decryption key
        iv: 8-byte initialization vector
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Decrypted plaintext
    """
    _validate_key(key)
    _validate_iv(iv, "IV")
    rounds = _validate_rounds(rounds)

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(f"Data length must be a multiple of {BLOCK_SIZE} bytes")

    if not data:
        return b""

    result = bytearray()
    prev = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        decrypted = decrypt_block(block, key, rounds)
        xored = xor_bytes(decrypted, prev)
        result.extend(xored)
        prev = block

    return pkcs7_unpad(bytes(result))


# ============== CFB Mode ==============

def encrypt_cfb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Encrypt data using XTEA in CFB mode (no padding needed).

    Args:
        data: Plaintext data to encrypt
        key: 16-byte encryption key
        iv: 8-byte initialization vector (must be unpredictable and unique)
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Encrypted ciphertext (same length as data)

    Note:
        CFB mode processes data in segments. The IV must be unpredictable
        and never reused with the same key.
    """
    _validate_key(key)
    _validate_iv(iv, "IV")
    rounds = _validate_rounds(rounds)

    if not data:
        return b""

    result = bytearray()
    prev = iv
    offset = 0

    while offset < len(data):
        keystream = encrypt_block(prev, key, rounds)
        chunk = data[offset:offset + BLOCK_SIZE]
        encrypted = xor_bytes(chunk, keystream[:len(chunk)])
        result.extend(encrypted)
        # Always use the full encrypted block as next feedback (padded if needed)
        if len(chunk) == BLOCK_SIZE:
            prev = encrypted
        else:
            # For partial blocks, pad with zeros for feedback
            prev = encrypted + bytes(BLOCK_SIZE - len(encrypted))
        offset += BLOCK_SIZE

    return bytes(result)


def decrypt_cfb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Decrypt data using XTEA in CFB mode.

    Args:
        data: Ciphertext to decrypt
        key: 16-byte decryption key
        iv: 8-byte initialization vector
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Decrypted plaintext (same length as data)
    """
    _validate_key(key)
    _validate_iv(iv, "IV")
    rounds = _validate_rounds(rounds)

    if not data:
        return b""

    result = bytearray()
    prev = iv
    offset = 0

    while offset < len(data):
        keystream = encrypt_block(prev, key, rounds)
        chunk = data[offset:offset + BLOCK_SIZE]
        decrypted = xor_bytes(chunk, keystream[:len(chunk)])
        result.extend(decrypted)
        # For CFB decryption, feedback uses ciphertext (with padding if needed)
        if len(chunk) == BLOCK_SIZE:
            prev = chunk
        else:
            prev = chunk + bytes(BLOCK_SIZE - len(chunk))
        offset += BLOCK_SIZE

    return bytes(result)


# ============== OFB Mode ==============

def encrypt_ofb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Encrypt data using XTEA in OFB mode (no padding needed).

    Args:
        data: Plaintext data to encrypt
        key: 16-byte encryption key
        iv: 8-byte initialization vector (must be unique per encryption)
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Encrypted ciphertext (same length as data)

    Note:
        OFB mode generates a keystream independent of the plaintext.
        The IV must be unique for each encryption with the same key.
    """
    _validate_key(key)
    _validate_iv(iv, "IV")
    rounds = _validate_rounds(rounds)

    if not data:
        return b""

    result = bytearray()
    prev = iv
    offset = 0

    while offset < len(data):
        keystream = encrypt_block(prev, key, rounds)
        chunk = data[offset:offset + BLOCK_SIZE]
        encrypted = xor_bytes(chunk, keystream[:len(chunk)])
        result.extend(encrypted)
        prev = keystream
        offset += BLOCK_SIZE

    return bytes(result)


def decrypt_ofb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes:
    """
    Decrypt data using XTEA in OFB mode.

    Args:
        data: Ciphertext to decrypt
        key: 16-byte decryption key
        iv: 8-byte initialization vector
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Decrypted plaintext (same length as data)
    """
    # OFB encryption and decryption are identical
    return encrypt_ofb(data, key, iv, rounds)


# ============== CTR Mode ==============

def _increment_counter(counter: bytes) -> bytes:
    """
    Increment a counter (big-endian).

    Args:
        counter: 8-byte counter value

    Returns:
        Incremented counter

    Raises:
        ValueError: If counter wraps around (would cause nonce reuse)
    """
    result = bytearray(counter)
    for i in range(len(result) - 1, -1, -1):
        result[i] = (result[i] + 1) & 0xFF
        if result[i] != 0:
            break
    else:
        # Wrap-around occurred - all bytes became 0
        raise ValueError("Counter wrap-around detected - nonce would repeat!")
    return bytes(result)


def encrypt_ctr(data: bytes, key: bytes, nonce: bytes, rounds: int = 0) -> bytes:
    """
    Encrypt data using XTEA in CTR mode (no padding needed).

    Args:
        data: Plaintext data to encrypt
        key: 16-byte encryption key
        nonce: 8-byte nonce (must be unique per encryption)
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Encrypted ciphertext (same length as data)

    Warning:
        **CRITICAL: Nonce reuse completely destroys security!**

        Never reuse a nonce with the same key. If you encrypt two different
        plaintexts with the same nonce and key, XORing the ciphertexts reveals
        the XOR of the plaintexts, completely breaking confidentiality.

        Use a counter, random value, or combination. The nonce must NEVER repeat
        for the lifetime of the key.

    Note:
        CTR mode requires a unique nonce for each encryption with the same key.
        The nonce can be a counter or random value, but must never repeat.
    """
    _validate_key(key)
    _validate_iv(nonce, "Nonce")
    rounds = _validate_rounds(rounds)

    warnings.warn(
        "CTR mode nonce MUST be unique for each encryption with the same key. "
        "Nonce reuse completely destroys confidentiality. "
        "Consider using a monotonic counter or random nonce.",
        SecurityWarning,
        stacklevel=2
    )

    if not data:
        return b""

    result = bytearray()
    counter = nonce
    offset = 0

    while offset < len(data):
        keystream = encrypt_block(counter, key, rounds)
        chunk = data[offset:offset + BLOCK_SIZE]
        encrypted = xor_bytes(chunk, keystream[:len(chunk)])
        result.extend(encrypted)
        counter = _increment_counter(counter)
        offset += BLOCK_SIZE

    return bytes(result)


def decrypt_ctr(data: bytes, key: bytes, nonce: bytes, rounds: int = 0) -> bytes:
    """
    Decrypt data using XTEA in CTR mode.

    Args:
        data: Ciphertext to decrypt
        key: 16-byte decryption key
        nonce: 8-byte nonce (same as used for encryption)
        rounds: Number of XTEA cycles (0 = default: 32, min: 8)

    Returns:
        Decrypted plaintext (same length as data)

    Note:
        CTR decryption is identical to encryption. Make sure you used a unique
        nonce when the data was encrypted.
    """
    _validate_key(key)
    _validate_iv(nonce, "Nonce")
    rounds = _validate_rounds(rounds)

    if not data:
        return b""

    result = bytearray()
    counter = nonce
    offset = 0

    while offset < len(data):
        keystream = encrypt_block(counter, key, rounds)
        chunk = data[offset:offset + BLOCK_SIZE]
        decrypted = xor_bytes(chunk, keystream[:len(chunk)])
        result.extend(decrypted)
        counter = _increment_counter(counter)
        offset += BLOCK_SIZE

    return bytes(result)


# Backward compatibility aliases (CBC mode as default encrypt/decrypt)
encrypt = encrypt_cbc
decrypt = decrypt_cbc
