"""Benchmarks comparing xtea_cython with PyPI xtea library.

Run with: python benchmarks.py

Requires: pip install xtea
"""

import os
import time
import sys

try:
    import xtea
    XTEA_AVAILABLE = True
except ImportError:
    XTEA_AVAILABLE = False
    print("Warning: xtea library not installed. Install with: pip install xtea")

try:
    from xtea_cython import (
        encrypt_block,
        decrypt_block,
        encrypt_cbc,
        encrypt_ecb,
        encrypt_ctr,
        encrypt_cfb,
        encrypt_ofb,
        pkcs7_pad,
    )
    from xtea_cython.simd import encrypt_blocks_batch, decrypt_blocks_batch
    XTEA_CYTHON_AVAILABLE = True
    SIMD_AVAILABLE = True
except ImportError:
    XTEA_CYTHON_AVAILABLE = False
    print("Error: xtea_cython not built. Run: pip install .")
    sys.exit(1)


def benchmark(func, *args, iterations=10000, label=""):
    """Run a benchmark and return operations per second."""
    # Warmup
    for _ in range(100):
        func(*args)

    # Benchmark
    start = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    elapsed = time.perf_counter() - start

    ops_per_sec = iterations / elapsed
    return ops_per_sec


def format_ops(ops):
    """Format operations per second."""
    if ops >= 1_000_000:
        return f"{ops / 1_000_000:.2f}M ops/s"
    elif ops >= 1_000:
        return f"{ops / 1_000:.2f}K ops/s"
    else:
        return f"{ops:.2f} ops/s"


def run_benchmarks():
    """Run all benchmarks."""
    print("=" * 60)
    print("XTEA Implementation Benchmarks")
    print("=" * 60)
    print()

    key = os.urandom(16)
    iv = os.urandom(8)
    block_data = os.urandom(8)
    small_data = os.urandom(64)  # 8 blocks
    medium_data = os.urandom(1024)  # 128 blocks
    large_data = os.urandom(8192)  # 1024 blocks

    results = {}

    # ============== Raw Block Operations ==============
    print("Raw Block Operations (8 bytes)")
    print("-" * 40)

    our_block_enc = benchmark(encrypt_block, block_data, key, iterations=50000)
    print(f"  xtea_cython encrypt_block: {format_ops(our_block_enc)}")
    results["block_enc"] = our_block_enc

    our_block_dec = benchmark(decrypt_block, block_data, key, iterations=50000)
    print(f"  xtea_cython decrypt_block: {format_ops(our_block_dec)}")
    results["block_dec"] = our_block_dec

    if XTEA_AVAILABLE:
        cipher = xtea.new(key, mode=xtea.MODE_ECB)
        their_block_enc = benchmark(cipher.encrypt, block_data, iterations=50000)
        print(f"  xtea encrypt (ECB, 8 bytes): {format_ops(their_block_enc)}")
        results["xtea_block_enc"] = their_block_enc

        speedup = our_block_enc / their_block_enc
        print(f"  Speedup: {speedup:.2f}x")

    print()

    # ============== ECB Mode ==============
    print("ECB Mode")
    print("-" * 40)

    for data, name in [(small_data, "64B"), (medium_data, "1KB"), (large_data, "8KB")]:
        our_ecb = benchmark(encrypt_ecb, data, key, iterations=1000)
        print(f"  xtea_cython ECB encrypt {name}: {format_ops(our_ecb)}")

        if XTEA_AVAILABLE:
            padded = pkcs7_pad(data)
            cipher = xtea.new(key, mode=xtea.MODE_ECB)
            their_ecb = benchmark(cipher.encrypt, padded, iterations=1000)
            print(f"  xtea ECB encrypt {name}:      {format_ops(their_ecb)}")
            speedup = our_ecb / their_ecb
            print(f"  Speedup: {speedup:.2f}x")
        print()

    # ============== Batch Processing (Interleaved) ==============
    if SIMD_AVAILABLE:
        print("Batch Processing (Interleaved/ILP)")
        print("-" * 40)

        # Test data must be multiple of 8 bytes
        batch_small = pkcs7_pad(small_data)   # 64B -> 72B (9 blocks)
        batch_medium = pkcs7_pad(medium_data)  # 1KB
        batch_large = pkcs7_pad(large_data)    # 8KB

        for data, name in [(batch_small, "72B"), (batch_medium, "1KB+"), (batch_large, "8KB+")]:
            batch_enc = benchmark(encrypt_blocks_batch, data, key, iterations=1000)
            print(f"  Batch encrypt {name}: {format_ops(batch_enc)}")

            # Compare with ECB (same operation)
            ebc_enc = benchmark(encrypt_ecb, data, key, iterations=1000)
            print(f"  ECB encrypt {name}:    {format_ops(ebc_enc)}")
            speedup = batch_enc / ebc_enc
            print(f"  Batch speedup vs ECB: {speedup:.2f}x")
            print()

    # ============== CBC Mode ==============
    print("CBC Mode")
    print("-" * 40)

    for data, name in [(small_data, "64B"), (medium_data, "1KB"), (large_data, "8KB")]:
        our_cbc = benchmark(encrypt_cbc, data, key, iv, iterations=1000)
        print(f"  xtea_cython CBC encrypt {name}: {format_ops(our_cbc)}")

        if XTEA_AVAILABLE:
            padded = pkcs7_pad(data)
            cipher = xtea.new(key, mode=xtea.MODE_CBC, IV=iv)
            their_cbc = benchmark(cipher.encrypt, padded, iterations=1000)
            print(f"  xtea CBC encrypt {name}:      {format_ops(their_cbc)}")
            speedup = our_cbc / their_cbc
            print(f"  Speedup: {speedup:.2f}x")
        print()

    # ============== CTR Mode ==============
    print("CTR Mode")
    print("-" * 40)

    our_ctr = benchmark(encrypt_ctr, medium_data, key, iv, iterations=1000)
    print(f"  xtea_cython CTR encrypt 1KB: {format_ops(our_ctr)}")

    if XTEA_AVAILABLE:
        counter_val = [iv]

        def get_counter():
            result = counter_val[0]
            arr = bytearray(result)
            for j in range(7, -1, -1):
                arr[j] = (arr[j] + 1) & 0xFF
                if arr[j] != 0:
                    break
            counter_val[0] = bytes(arr)
            return result

        cipher = xtea.new(key, mode=xtea.MODE_CTR, counter=get_counter)
        their_ctr = benchmark(cipher.encrypt, medium_data, iterations=1000)
        print(f"  xtea CTR encrypt 1KB:      {format_ops(their_ctr)}")
        speedup = our_ctr / their_ctr
        print(f"  Speedup: {speedup:.2f}x")

    print()

    # ============== CFB Mode ==============
    print("CFB Mode")
    print("-" * 40)

    our_cfb = benchmark(encrypt_cfb, medium_data, key, iv, iterations=1000)
    print(f"  xtea_cython CFB encrypt 1KB: {format_ops(our_cfb)}")

    if XTEA_AVAILABLE:
        cipher = xtea.new(key, mode=xtea.MODE_CFB, IV=iv, segment_size=64)
        their_cfb = benchmark(cipher.encrypt, medium_data, iterations=1000)
        print(f"  xtea CFB encrypt 1KB:      {format_ops(their_cfb)}")
        speedup = our_cfb / their_cfb
        print(f"  Speedup: {speedup:.2f}x")

    print()

    # ============== OFB Mode ==============
    print("OFB Mode")
    print("-" * 40)

    our_ofb = benchmark(encrypt_ofb, medium_data, key, iv, iterations=1000)
    print(f"  xtea_cython OFB encrypt 1KB: {format_ops(our_ofb)}")

    if XTEA_AVAILABLE:
        cipher = xtea.new(key, mode=xtea.MODE_OFB, IV=iv)
        their_ofb = benchmark(cipher.encrypt, medium_data, iterations=1000)
        print(f"  xtea OFB encrypt 1KB:      {format_ops(their_ofb)}")
        speedup = our_ofb / their_ofb
        print(f"  Speedup: {speedup:.2f}x")

    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)

    if XTEA_AVAILABLE:
        print()
        print("Comparison with PyPI xtea library:")
        print(f"  Raw block encryption: xtea_cython is {results['block_enc'] / results['xtea_block_enc']:.2f}x faster")
    else:
        print()
        print("Install xtea library for comparison: pip install xtea")


if __name__ == "__main__":
    run_benchmarks()
