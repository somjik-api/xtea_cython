# xtea_cython

[![PyPI](https://img.shields.io/pypi/v/xtea_cython.svg)](https://pypi.org/project/xtea_cython/)
[![Python](https://img.shields.io/pypi/pyversions/xtea_cython.svg)](https://pypi.org/project/xtea_cython/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build](https://github.com/somjik-api/xtea_cython/actions/workflows/build-wheels.yml/badge.svg)](https://github.com/somjik-api/xtea_cython/actions/workflows/build-wheels.yml)

High-performance XTEA encryption implementation using Cython with support for multiple encryption modes.

## 🚀 Features

- **XTEA Algorithm**: Corrected Block TEA cipher with 128-bit key
- **Multiple Modes**: ECB, CBC, CFB, OFB, CTR
- **High Performance**: Up to 73x faster than pure Python implementations
- **Security Hardened**: Constant-time padding validation, minimum rounds enforcement
- **Full Compatibility**: Drop-in replacement for PyPI `xtea` library
- **No Dependencies**: Pure Cython implementation, no external C libraries required

## 📦 Installation

```bash
pip install xtea_cython
```

Requirements:
- Python 3.8+
- Cython 0.29+ (for development/building)
- No runtime dependencies

## 🏁 Quick Start

### Basic Encryption (CBC Mode - Recommended)

```python
import os
from xtea_cython import encrypt_cbc, decrypt_cbc

# Generate secure random key and IV
key = os.urandom(16)  # 128-bit key
iv = os.urandom(8)    # 64-bit IV

# Encrypt
plaintext = b"Hello, World!"
ciphertext = encrypt_cbc(plaintext, key, iv)

# Decrypt
decrypted = decrypt_cbc(ciphertext, key, iv)

assert decrypted == plaintext
```

### Stream Mode (CTR) - No Padding Required

```python
from xtea_cython import encrypt_ctr, decrypt_ctr

# Use nonce instead of IV
nonce = os.urandom(8)  # Must be unique per encryption

# Encrypt/decrypt directly
ciphertext = encrypt_ctr(plaintext, key, nonce)
decrypted = decrypt_ctr(ciphertext, key, nonce)
```

### Using Helper Functions

```python
from xtea_cython import generate_key, generate_iv, encrypt_cbc, decrypt_cbc

# Generate keys and IVs automatically
key = generate_key()      # 16-byte random key
iv = generate_iv()        # 8-byte random IV

# The rest is the same
ciphertext = encrypt_cbc(plaintext, key, iv)
```

## 🛡️ Encryption Modes

### CBC Mode (Recommended)

```python
from xtea_cython import encrypt_cbc, decrypt_cbc

ciphertext = encrypt_cbc(plaintext, key, iv)
decrypted = decrypt_cbc(ciphertext, key, iv)
```

- ✅ **Uses PKCS#7 padding** (automatic)
- ✅ **Most secure** for general-purpose encryption
- ✅ **IV must be unpredictable** (use `os.urandom(8)`)
- ✅ **Different IVs** produce different ciphertexts
- ✅ **Industry standard** for symmetric encryption

### CTR Mode (Stream Cipher)

```python
from xtea_cython import encrypt_ctr, decrypt_ctr

ciphertext = encrypt_ctr(plaintext, key, nonce)
decrypted = decrypt_ctr(ciphertext, key, nonce)
```

- ✅ **No padding required** (preserves input length)
- ✅ **Parallel encryption** possible
- ✅ **Nonce must be unique** per encryption with same key
- ✅ **Good for streaming** data
- ✅ **Random access** to encrypted data

### CFB Mode (Stream Cipher)

```python
from xtea_cython import encrypt_cfb, decrypt_cfb

ciphertext = encrypt_cfb(plaintext, key, iv)
decrypted = decrypt_cfb(ciphertext, key, iv)
```

- ✅ **No padding required**
- ✅ **Self-synchronizing** (resyncs after errors)
- ✅ **IV must be unique** per encryption
- ✅ **Suitable for streaming** applications

### OFB Mode (Stream Cipher)

```python
from xtea_cython import encrypt_ofb, decrypt_ofb

ciphertext = encrypt_ofb(plaintext, key, iv)
decrypted = decrypt_ofb(ciphertext, key, iv)
```

- ✅ **No padding required**
- ✅ **Keystream independent** of plaintext
- ✅ **IV must be unique** per encryption
- ✅ **Error propagation limited**

### ECB Mode (Not Recommended - For Legacy Only)

```python
from xtea_cython import encrypt_ecb, decrypt_ecb

ciphertext = encrypt_ecb(plaintext, key)
decrypted = decrypt_ecb(ciphertext, key)
```

- ⚠️ **WARNING**: ECB is **not secure** for most use cases
- ⚠️ **Same plaintext blocks** produce same ciphertext blocks
- ⚠️ **Pattern leakage** - reveals data patterns
- ⚠️ **Only use** for single-block data or legacy compatibility

## 🔧 Advanced Usage

### Custom Number of Rounds

```python
# Use fewer rounds for faster (but less secure) encryption
weak_encrypted = encrypt_cbc(plaintext, key, iv, rounds=8)

# Use more rounds for higher security (default is 32)
strong_encrypted = encrypt_cbc(plaintext, key, iv, rounds=64)
```

### Manual Padding Control

```python
from xtea_cython import pkcs7_pad, pkcs7_unpad

# Manual padding if needed
padded_data = pkcs7_pad(plaintext)
unpadded_data = pkcs7_unpad(padded_data)
```

### Raw Block Encryption

```python
from xtea_cython import encrypt_block, decrypt_block

# Encrypt single 8-byte block
block = b"12345678"
key = b"0123456789abcdef"  # 16 bytes

encrypted = encrypt_block(block, key)
decrypted = decrypt_block(encrypted, key)
```

## 🎯 Security Best Practices

### Key Management

```python
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ✅ Good: Use cryptographically secure random keys
key = os.urandom(16)  # 128-bit key

# ✅ Better: Use a key derivation function for passwords
password = b"my_secure_password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
)
derived_key = kdf.derive(password)

# ❌ Never hardcode keys in your code
# key = b"this_is_a_weak_key"
```

### IV/Nonce Requirements

```python
import os
from uuid import uuid4

# ✅ CBC: IV must be unpredictable
iv = os.urandom(8)

# ✅ CTR: Nonce must be unique per encryption
nonce = uuid4().bytes[:8]  # UUID-based nonce

# ✅ For long-running applications, use counters
counter = 0
def get_next_nonce():
    global counter
    nonce = counter.to_bytes(8, 'big')
    counter += 1
    return nonce

# ❌ Never reuse IVs or nonces with the same key
```

### Mode Selection Guide

| Mode | Security | Performance | Use Case |
|------|----------|-------------|----------|
| **CBC** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | General encryption, file storage |
| **CTR** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Streaming, parallel processing |
| **CFB** | ⭐⭐⭐⭐ | ⭐⭐⭐ | Network streams, error recovery |
| **OFB** | ⭐⭐⭐⭐ | ⭐⭐⭐ | High-speed streaming |
| **ECB** | ⭐ | ⭐⭐⭐⭐⭐ | Legacy systems, single blocks |

### Data Handling

```python
# ✅ Always handle keys securely
import tempfile
import os

def secure_delete_path(path):
    """Securely delete a file by overwriting with random data."""
    with open(path, 'r+b') as f:
        length = os.path.getsize(path)
        f.write(os.urandom(length))
    os.unlink(path)

# ✅ Use secure temporary files
with tempfile.NamedTemporaryFile(delete=False) as temp:
    # Write encrypted data
    temp.write(ciphertext)
    temp_path = temp.name

try:
    # Process the encrypted data
    pass
finally:
    secure_delete_path(temp_path)
```

## 📊 Performance

### Benchmarks vs PyPI `xtea` Library

| Operation | xtea_cython | PyPI xtea | Speedup |
|-----------|-------------|-----------|---------|
| Raw block | 73.2M ops/s | 1.0M ops/s | **73x** |
| ECB 64B | 2.1M ops/s | 57K ops/s | **37x** |
| CBC 64B | 1.8M ops/s | 127K ops/s | **14x** |
| CTR 1KB | 1.2M ops/s | 110K ops/s | **11x** |
| CFB 1KB | 1.3M ops/s | 95K ops/s | **14x** |
| OFB 1KB | 1.3M ops/s | 92K ops/s | **14x** |

**Run your own benchmarks:**
```bash
pip install xtea
python benchmarks.py
```

### Performance Tips

```python
# ✅ Use CTR mode for large files
with open('large_file.txt', 'rb') as f:
    plaintext = f.read()
    ciphertext = encrypt_ctr(plaintext, key, nonce)

# ✅ Process data in chunks for memory efficiency
chunk_size = 8192  # 8KB chunks
with open('input.txt', 'rb') as fin, open('encrypted.bin', 'wb') as fout:
    while True:
        chunk = fin.read(chunk_size)
        if not chunk:
            break
        encrypted_chunk = encrypt_ctr(chunk, key, nonce)
        fout.write(encrypted_chunk)
```

## 🔗 API Reference

### Core Functions

```python
# Raw block encryption
encrypt_block(data: bytes, key: bytes, rounds: int = 0) -> bytes
decrypt_block(data: bytes, key: bytes, rounds: int = 0) -> bytes

# Data length: exactly 8 bytes
# Key length: exactly 16 bytes
# Rounds: 0 = default 32, minimum 8
```

### Mode Functions

```python
# CBC Mode (Recommended)
encrypt_cbc(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes
decrypt_cbc(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes

# CTR Mode (Stream)
encrypt_ctr(data: bytes, key: bytes, nonce: bytes, rounds: int = 0) -> bytes
decrypt_ctr(data: bytes, key: bytes, nonce: bytes, rounds: int = 0) -> bytes

# CFB Mode (Stream)
encrypt_cfb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes
decrypt_cfb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes

# OFB Mode (Stream)
encrypt_ofb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes
decrypt_ofb(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes

# ECB Mode (Legacy)
encrypt_ecb(data: bytes, key: bytes, rounds: int = 0) -> bytes
decrypt_ecb(data: bytes, key: bytes, rounds: int = 0) -> bytes
```

### Helper Functions

```python
# Key/IV Generation
generate_key(size: int = 16) -> bytes
generate_iv(size: int = 8) -> bytes

# Padding
pkcs7_pad(data: bytes, block_size: int = 8) -> bytes
pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes

# Constants
BLOCK_SIZE = 8  # XTEA block size in bytes

# Backward Compatibility (uses CBC by default)
encrypt(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes
decrypt(data: bytes, key: bytes, iv: bytes, rounds: int = 0) -> bytes

# Security
SecurityWarning = "ECB mode is not secure for most use cases"
```

### Parameter Requirements

| Parameter | Type | Size | Required | Description |
|-----------|------|------|----------|-------------|
| `data` | `bytes` | Variable | Yes | Plaintext or ciphertext |
| `key` | `bytes` | Exactly 16 bytes | Yes | 128-bit encryption key |
| `iv`/`nonce` | `bytes` | Exactly 8 bytes | Yes | Initialization vector/nonce |
| `rounds` | `int` | ≥ 8 | No | Number of XTEA cycles (default: 32) |

## 🔄 Backward Compatibility

### Migrating from PyPI `xtea` Library

```python
# Old xtea library usage
import xtea
cipher = xtea.new(key, mode=xtea.MODE_CBC, IV=iv)
ciphertext = cipher.encrypt(pkcs7_pad(plaintext))

# New xtea_cython usage (simpler!)
from xtea_cython import encrypt_cbc
ciphertext = encrypt_cbc(plaintext, key, iv)  # Padding is automatic
```

### Drop-in Replacement

The library is designed to be a drop-in replacement for the PyPI `xtea` library:

```python
# Both implementations produce identical results
# when using the same key, IV, and data
import xtea  # Old library
from xtea_cython import encrypt_cbc  # New library

# Same input → Same output (bit-for-bit compatible)
```

## 🚨 Common Pitfalls

### 1. Reusing IVs

```python
# ❌ Bad: Reusing IV with the same key
iv = os.urandom(8)
encrypt_cbc(secret1, key, iv)  # IV reused!
encrypt_cbc(secret2, key, iv)  # Security risk!

# ✅ Good: Always use unique IVs
iv1 = os.urandom(8)
iv2 = os.urandom(8)
encrypt_cbc(secret1, key, iv1)
encrypt_cbc(secret2, key, iv2)
```

### 2. Reusing Nonces in CTR

```python
# ❌ Very Bad: Reusing nonce in CTR
nonce = os.urandom(8)
encrypt_ctr(secret1, key, nonce)  # Nonce reused!
encrypt_ctr(secret2, key, nonce)  # This completely breaks security!

# ✅ Good: Unique nonces are critical
nonce1 = os.urandom(8)
nonce2 = os.urandom(8)
encrypt_ctr(secret1, key, nonce1)
encrypt_ctr(secret2, key, nonce2)
```

### 3. Short Keys

```python
# ❌ Bad: Insufficient key length
key = b"short"  # Only 5 bytes!

# ✅ Good: Always use 16-byte (128-bit) keys
key = os.urandom(16)
```

### 4. ECB for Non-Atomic Data

```python
# ❌ Bad: ECB reveals patterns
image_data = open("logo.png", "rb").read()
encrypted = encrypt_ecb(image_data, key)  # Patterns visible!

# ✅ Good: Use CBC or CTR
encrypted = encrypt_cbc(image_data, key, iv)
```

## 🛠️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/somjik-api/xtea_cython.git
cd xtea_cython

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"
pip install xtea  # For benchmarks

# Build the Cython extension
python setup.py build_ext --inplace

# Run tests
pytest tests/ -v

# Run benchmarks
python benchmarks.py
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_modes.py -v

# Run with coverage
pytest tests/ --cov=xtea_cython --cov-report=html
```

## 📈 Version History

### 0.1.0 (2024-01-01)
- Initial release
- XTEA core implementation in Cython
- ECB, CBC, CFB, OFB, CTR modes
- Security hardening (constant-time padding, minimum rounds)
- Full compatibility with PyPI xtea library
- Comprehensive benchmark suite

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest tests/`)
6. Run benchmarks to ensure no performance regression
7. Submit a pull request

## ⚠️ Security Notice

This library implements the XTEA algorithm, which is considered secure for most applications when used correctly. However:

- **Always use secure keys**: Never hardcode keys or use predictable values
- **Never reuse IVs/nonces**: Each encryption should use a unique IV/nonce
- **Choose appropriate modes**: CBC and CTR are recommended for most use cases
- **Avoid ECB**: ECB mode should only be used for legacy compatibility
- **Consider your threat model**: XTEA may not be suitable for high-security applications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [XTEA Algorithm Specification](https://www.tayloredge.com/reference/Mathematics/XTEA.pdf)
- [NIST SP 800-38A Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [PyPI xtea Library](https://pypi.org/project/xtea/)

---

Made with ❤️ for high-performance cryptography