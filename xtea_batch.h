/*
 * XTEA batch processing header - interleaved execution for better ILP.
 */

#ifndef XTEA_BATCH_H
#define XTEA_BATCH_H

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

#endif /* XTEA_BATCH_H */
