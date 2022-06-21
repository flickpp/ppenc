#ifndef _PPENC_CPRNG_H
#define _PPENC_CPRNG_H

#include <stdint.h>

struct PPEncChaCha8 {
  uint32_t key[8];
  uint32_t nonce[2];
  uint8_t block[64];
  uint32_t counter;
  uint8_t pos;
};

struct PPEncChaCha20 {
  uint32_t key[8];
  uint32_t nonce[3];
  uint8_t block[64];
  uint32_t counter;
  uint8_t pos;
};

void
ppenc_chacha8_init(struct PPEncChaCha8 *const chacha8,
                   const uint8_t *const key,
                   const uint8_t *const nonce);

void
ppenc_chacha8_nbytes(struct PPEncChaCha8 *const chacha8,
                     uint8_t *const dst,
                     const uint16_t num_bytes);

void
ppenc_chacha20_init(struct PPEncChaCha20 *const chacha20,
                    const uint8_t *const key,
                    const uint8_t *const nonce);

void
ppenc_chacha20_xor_header(struct PPEncChaCha20 *const chacha20, uint8_t *const header);
#endif
