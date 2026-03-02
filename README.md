# xtea_cython

[![PyPI](https://img.shields.io/pypi/v/xtea_cython.svg)](https://pypi.org/project/xtea_cython/)
[![Python](https://img.shields.io/pypi/pyversions/xtea_cython.svg)](https://pypi.org/project/xtea_cython/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build](https://github.com/somjik-api/xtea_cython/actions/workflows/build-wheels.yml/badge.svg)](https://github.com/somjik-api/xtea_cython/actions/workflows/build-wheels.yml)

High-performance XTEA encryption implementation using Cython. Drop-in replacement for the PyPI `xtea` library.

## Installation

```bash
pip install xtea_cython
```

Requirements: Python 3.8+, no runtime dependencies.

## Usage

### Basic Encryption (CBC Mode)

```python
import os
from xtea_cython import encrypt_cbc, decrypt_cbc

key = os.urandom(16)  # 128-bit key
iv = os.urandom(8)    # 64-bit IV

plaintext = b"Hello, World!"

# Encrypt (with automatic padding)
ciphertext = encrypt_cbc(plaintext, key, iv, auto_pad=True)

# Decrypt
decrypted = decrypt_cbc(ciphertext, key, iv, auto_unpad=True)

assert decrypted == plaintext
```

### Without Padding (PyPI xtea Compatible)

```python
from xtea_cython import encrypt_cbc, decrypt_cbc
import xtea

key = b"0123456789abcdef"
iv = b"abcdefgh"
data = b"12345678" * 10  # Must be multiple of 8 bytes

# Both produce identical results
result1 = encrypt_cbc(data, key, iv)
result2 = xtea.new(key, mode=xtea.MODE_CBC, IV=iv).encrypt(data)

assert result1 == result2  # True
```

### Stream Modes (CTR, CFB, OFB) - No Padding Required

```python
from xtea_cython import encrypt_ctr, decrypt_ctr

nonce = os.urandom(8)

ciphertext = encrypt_ctr(plaintext, key, nonce)
decrypted = decrypt_ctr(ciphertext, key, nonce)

assert decrypted == plaintext
```

### Raw Block Encryption

```python
from xtea_cython import encrypt_block, decrypt_block

block = b"12345678"  # Exactly 8 bytes
key = b"0123456789abcdef"  # Exactly 16 bytes

encrypted = encrypt_block(block, key)
decrypted = decrypt_block(encrypted, key)
```

### Manual Padding Control

```python
from xtea_cython import encrypt_cbc, decrypt_cbc, pkcs7_pad, pkcs7_unpad

# Pad manually
padded = pkcs7_pad(plaintext)
ciphertext = encrypt_cbc(padded, key, iv)

# Unpad manually
decrypted_padded = decrypt_cbc(ciphertext, key, iv)
decrypted = pkcs7_unpad(decrypted_padded)
```

### ECB Mode

```python
from xtea_cython import encrypt_ecb, decrypt_ecb

ciphertext = encrypt_ecb(plaintext, key, auto_pad=True)
decrypted = decrypt_ecb(ciphertext, key, auto_unpad=True)
```

⚠️ **Warning**: ECB mode is not secure for most use cases. Same plaintext blocks produce same ciphertext blocks. Use CBC or CTR instead.

### Helper Functions

```python
from xtea_cython import generate_key, generate_iv, pkcs7_pad, pkcs7_unpad

key = generate_key()  # 16-byte random key
iv = generate_iv()    # 8-byte random IV

padded = pkcs7_pad(data)
unpadded = pkcs7_unpad(padded)
```

### Custom Rounds

```python
# Default: 64 Feistel rounds (32 cycles)
ciphertext = encrypt_cbc(plaintext, key, iv, auto_pad=True)

# Faster but less secure
ciphertext = encrypt_cbc(plaintext, key, iv, rounds=32, auto_pad=True)

# More secure
ciphertext = encrypt_cbc(plaintext, key, iv, rounds=128, auto_pad=True)
```

## Performance

Benchmarks vs PyPI `xtea` library:

| Operation | xtea_cython | PyPI xtea | Speedup |
|-----------|-------------|-----------|---------|
| Raw block | 73.2M ops/s | 1.0M ops/s | 73x |
| ECB 64B | 2.1M ops/s | 57K ops/s | 37x |
| CBC 64B | 1.8M ops/s | 127K ops/s | 14x |
| CTR 1KB | 1.2M ops/s | 110K ops/s | 11x |
| CFB 1KB | 1.3M ops/s | 95K ops/s | 14x |
| OFB 1KB | 1.3M ops/s | 92K ops/s | 14x |

Run benchmarks:
```bash
pip install xtea
python benchmarks.py
```

## Development

```bash
git clone https://github.com/somjik-api/xtea_cython.git
cd xtea_cython
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Run `pytest tests/`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.
