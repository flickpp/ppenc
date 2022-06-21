#ifndef _PPENC_BLOCKCIPHER_H
#define _PPENC_BLOCCIPHER_H

#include <stdint.h>

struct ThreeFishSubKeys {
  uint32_t _0[2];
  uint32_t _1[2];
  uint32_t _2[2];
  uint32_t _3[2];
  uint32_t _4[2];
  uint32_t _5[2];
  uint32_t _6[2];
  uint32_t _7[2];
};

struct ThreeFishKey {
  uint32_t lower, upper;
};

struct ThreeFishBuffer {
  struct ThreeFishSubKeys subkeys[19];
  uint32_t tweaks[6];
  struct ThreeFishKey keys[9];
};

#if defined(PPENC_64BIT)
struct ThreeFishSubKeys64 {
  uint64_t _0, _1, _2, _3, _4, _5, _6, _7;
};

struct ThreeFishBuffer64 {
  struct ThreeFishSubKeys64 subkeys[19];
  uint32_t tweaks[6];
  uint64_t keys[9];
};

#endif

#if defined(PPENC_64BIT)
void ppenc_threefish512_encrypt_64bit(const uint8_t *const key,
                                      const uint8_t *const tweak_seed,
			              uint8_t* const body,
			              const uint32_t num_blocks,
			              struct ThreeFishBuffer64 *const buf3f,
				      uint8_t *const buf64);

void ppenc_threefish512_decrypt_64bit(const uint8_t *const key,
                                      const uint8_t *const tweak_seed,
			              uint8_t* const body,
			              const uint32_t num_blocks,
			              struct ThreeFishBuffer64 *const buf3f,
				      uint8_t *const buf64);
#endif

void ppenc_threefish512_encrypt(const uint8_t *const key,
                                const uint8_t *const tweak_seed,
			        uint8_t* const body,
			        const uint32_t num_blocks,
			        struct ThreeFishBuffer *const buf3f,
				uint8_t *const buf64);

void ppenc_threefish512_decrypt(const uint8_t *const key,
                                const uint8_t *const tweak_seed,
			        uint8_t* const body,
			        const uint32_t num_blocks,
			        struct ThreeFishBuffer *const buf3f,
				uint8_t *const buf64);

/* header guard */
#endif
