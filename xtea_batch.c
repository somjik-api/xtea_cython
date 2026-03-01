/*
 * XTEA batch processing with interleaved execution.
 * Processes multiple blocks with better instruction-level parallelism.
 *
 * Works on any CPU architecture (x86, ARM, etc.)
 */

#include <stdint.h>

#define DELTA 0x9e3779b9
#define DEFAULT_ROUNDS 32
#define MAX_ROUNDS 256  /* Prevent integer overflow in sum_init = n * DELTA */

/*
 * XTEA encrypt multiple blocks using interleaved scalar processing.
 * Processes 2 blocks at a time for better instruction-level parallelism.
 */
void xtea_encrypt_blocks_interleaved(
    const uint8_t *data,
    uint8_t *out,
    const uint8_t *key,
    uint32_t num_blocks,
    uint32_t rounds
) {
    uint32_t k[4];
    uint32_t n = rounds > 0 ? rounds : DEFAULT_ROUNDS;

    /* Bounds check to prevent integer overflow */
    if (n > MAX_ROUNDS) {
        n = MAX_ROUNDS;
    }

    /* Parse key as big-endian */
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[4*i] << 24) |
               ((uint32_t)key[4*i + 1] << 16) |
               ((uint32_t)key[4*i + 2] << 8) |
               ((uint32_t)key[4*i + 3]);
    }

    /* Process blocks in pairs for better ILP */
    uint32_t i = 0;
    for (; i + 1 < num_blocks; i += 2) {
        /* Load two blocks */
        const uint8_t *d0 = data + i * 8;
        const uint8_t *d1 = data + (i + 1) * 8;
        uint8_t *o0 = out + i * 8;
        uint8_t *o1 = out + (i + 1) * 8;

        /* Parse as big-endian */
        uint32_t v0_0 = ((uint32_t)d0[0] << 24) | (d0[1] << 16) | (d0[2] << 8) | d0[3];
        uint32_t v1_0 = ((uint32_t)d0[4] << 24) | (d0[5] << 16) | (d0[6] << 8) | d0[7];
        uint32_t v0_1 = ((uint32_t)d1[0] << 24) | (d1[1] << 16) | (d1[2] << 8) | d1[3];
        uint32_t v1_1 = ((uint32_t)d1[4] << 24) | (d1[5] << 16) | (d1[6] << 8) | d1[7];

        uint32_t sum0 = 0, sum1 = 0;

        /* Interleaved rounds - CPU can pipeline these */
        for (uint32_t r = 0; r < n; r++) {
            /* Block 0 round */
            v0_0 += (((v1_0 << 4) ^ (v1_0 >> 5)) + v1_0) ^ (sum0 + k[sum0 & 3]);
            sum0 += DELTA;
            v1_0 += (((v0_0 << 4) ^ (v0_0 >> 5)) + v0_0) ^ (sum0 + k[(sum0 >> 11) & 3]);

            /* Block 1 round */
            v0_1 += (((v1_1 << 4) ^ (v1_1 >> 5)) + v1_1) ^ (sum1 + k[sum1 & 3]);
            sum1 += DELTA;
            v1_1 += (((v0_1 << 4) ^ (v0_1 >> 5)) + v0_1) ^ (sum1 + k[(sum1 >> 11) & 3]);
        }

        /* Store results */
        o0[0] = (v0_0 >> 24) & 0xFF; o0[1] = (v0_0 >> 16) & 0xFF;
        o0[2] = (v0_0 >> 8) & 0xFF;  o0[3] = v0_0 & 0xFF;
        o0[4] = (v1_0 >> 24) & 0xFF; o0[5] = (v1_0 >> 16) & 0xFF;
        o0[6] = (v1_0 >> 8) & 0xFF;  o0[7] = v1_0 & 0xFF;

        o1[0] = (v0_1 >> 24) & 0xFF; o1[1] = (v0_1 >> 16) & 0xFF;
        o1[2] = (v0_1 >> 8) & 0xFF;  o1[3] = v0_1 & 0xFF;
        o1[4] = (v1_1 >> 24) & 0xFF; o1[5] = (v1_1 >> 16) & 0xFF;
        o1[6] = (v1_1 >> 8) & 0xFF;  o1[7] = v1_1 & 0xFF;
    }

    /* Handle remaining single block */
    if (i < num_blocks) {
        const uint8_t *d = data + i * 8;
        uint8_t *o = out + i * 8;

        uint32_t v0 = ((uint32_t)d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
        uint32_t v1 = ((uint32_t)d[4] << 24) | (d[5] << 16) | (d[6] << 8) | d[7];
        uint32_t sum = 0;

        for (uint32_t r = 0; r < n; r++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
            sum += DELTA;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        }

        o[0] = (v0 >> 24) & 0xFF; o[1] = (v0 >> 16) & 0xFF;
        o[2] = (v0 >> 8) & 0xFF;  o[3] = v0 & 0xFF;
        o[4] = (v1 >> 24) & 0xFF; o[5] = (v1 >> 16) & 0xFF;
        o[6] = (v1 >> 8) & 0xFF;  o[7] = v1 & 0xFF;
    }
}

/*
 * XTEA decrypt multiple blocks using interleaved scalar processing.
 */
void xtea_decrypt_blocks_interleaved(
    const uint8_t *data,
    uint8_t *out,
    const uint8_t *key,
    uint32_t num_blocks,
    uint32_t rounds
) {
    uint32_t k[4];
    uint32_t n = rounds > 0 ? rounds : DEFAULT_ROUNDS;

    /* Bounds check to prevent integer overflow */
    if (n > MAX_ROUNDS) {
        n = MAX_ROUNDS;
    }

    /* Parse key as big-endian */
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[4*i] << 24) |
               ((uint32_t)key[4*i + 1] << 16) |
               ((uint32_t)key[4*i + 2] << 8) |
               ((uint32_t)key[4*i + 3]);
    }

    uint32_t sum_init = n * DELTA;

    /* Process blocks in pairs */
    uint32_t i = 0;
    for (; i + 1 < num_blocks; i += 2) {
        const uint8_t *d0 = data + i * 8;
        const uint8_t *d1 = data + (i + 1) * 8;
        uint8_t *o0 = out + i * 8;
        uint8_t *o1 = out + (i + 1) * 8;

        uint32_t v0_0 = ((uint32_t)d0[0] << 24) | (d0[1] << 16) | (d0[2] << 8) | d0[3];
        uint32_t v1_0 = ((uint32_t)d0[4] << 24) | (d0[5] << 16) | (d0[6] << 8) | d0[7];
        uint32_t v0_1 = ((uint32_t)d1[0] << 24) | (d1[1] << 16) | (d1[2] << 8) | d1[3];
        uint32_t v1_1 = ((uint32_t)d1[4] << 24) | (d1[5] << 16) | (d1[6] << 8) | d1[7];

        uint32_t sum0 = sum_init, sum1 = sum_init;

        for (uint32_t r = 0; r < n; r++) {
            /* Block 0 round */
            v1_0 -= (((v0_0 << 4) ^ (v0_0 >> 5)) + v0_0) ^ (sum0 + k[(sum0 >> 11) & 3]);
            sum0 -= DELTA;
            v0_0 -= (((v1_0 << 4) ^ (v1_0 >> 5)) + v1_0) ^ (sum0 + k[sum0 & 3]);

            /* Block 1 round */
            v1_1 -= (((v0_1 << 4) ^ (v0_1 >> 5)) + v0_1) ^ (sum1 + k[(sum1 >> 11) & 3]);
            sum1 -= DELTA;
            v0_1 -= (((v1_1 << 4) ^ (v1_1 >> 5)) + v1_1) ^ (sum1 + k[sum1 & 3]);
        }

        o0[0] = (v0_0 >> 24) & 0xFF; o0[1] = (v0_0 >> 16) & 0xFF;
        o0[2] = (v0_0 >> 8) & 0xFF;  o0[3] = v0_0 & 0xFF;
        o0[4] = (v1_0 >> 24) & 0xFF; o0[5] = (v1_0 >> 16) & 0xFF;
        o0[6] = (v1_0 >> 8) & 0xFF;  o0[7] = v1_0 & 0xFF;

        o1[0] = (v0_1 >> 24) & 0xFF; o1[1] = (v0_1 >> 16) & 0xFF;
        o1[2] = (v0_1 >> 8) & 0xFF;  o1[3] = v0_1 & 0xFF;
        o1[4] = (v1_1 >> 24) & 0xFF; o1[5] = (v1_1 >> 16) & 0xFF;
        o1[6] = (v1_1 >> 8) & 0xFF;  o1[7] = v1_1 & 0xFF;
    }

    /* Handle remaining single block */
    if (i < num_blocks) {
        const uint8_t *d = data + i * 8;
        uint8_t *o = out + i * 8;

        uint32_t v0 = ((uint32_t)d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
        uint32_t v1 = ((uint32_t)d[4] << 24) | (d[5] << 16) | (d[6] << 8) | d[7];
        uint32_t sum = sum_init;

        for (uint32_t r = 0; r < n; r++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        }

        o[0] = (v0 >> 24) & 0xFF; o[1] = (v0 >> 16) & 0xFF;
        o[2] = (v0 >> 8) & 0xFF;  o[3] = v0 & 0xFF;
        o[4] = (v1 >> 24) & 0xFF; o[5] = (v1 >> 16) & 0xFF;
        o[6] = (v1 >> 8) & 0xFF;  o[7] = v1 & 0xFF;
    }
}
