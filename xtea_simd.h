/*
 * XTEA SIMD header
 */

#ifndef XTEA_SIMD_H
#define XTEA_SIMD_H

#include <stdint.h>

void xtea_encrypt_blocks_interleaved(
    const uint8_t *data,
    uint8_t *out,
    const uint8_t *key,
    uint32_t num_blocks,
    uint32_t rounds
);

void xtea_decrypt_blocks_interleaved(
    const uint8_t *data,
    uint8_t *out,
    const uint8_t *key,
    uint32_t num_blocks,
    uint32_t rounds
);

#endif /* XTEA_SIMD_H */
