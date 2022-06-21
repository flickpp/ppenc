#include "hash.h"

#define SHA_CH(x, y, z) ((x & y) ^ ((~x) & z))
#define SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
/* LE <-> BE */
#define BYTESWAP32(x) ((x >> 24) | ((x & 0x00FF0000) >> 8) | ((x & 0x0000FF00) << 8) | (x << 24))
#define ROT_LEFT32(x, z) ((x << z) | (x >> (32 - z)))

static INLINE void sha256_block(uint32_t* hash_value,
                                const uint32_t *const blocks,
                                uint32_t* message_schedule_buf);
static INLINE uint32_t sha256_Sigma0(const uint32_t x);
static INLINE uint32_t sha256_Sigma1(const uint32_t x);
static INLINE uint32_t sha256_sigma0(const uint32_t x);
static INLINE uint32_t sha256_sigma1(const uint32_t x);

STATIC INLINE void cubehash_rounds(uint32_t *const state, const uint16_t num_rounds);

static const uint32_t SHA256_INITIAL_HASH_VALUE[8] = {\
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
};

static const uint32_t SHA256_CONST[64] = {\
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static const uint32_t CUBEHASH_INIT[32] = {\
  0x781f814f, 0x18f45926, 0x992b7520, 0xc8237df7, 0xe4e3ba88, 0x7b0075ff, 0x51916982,
  0x947c6147, 0x9dc06f0a, 0x4d197eb5, 0xb6e17224, 0x912e1aca, 0x5270f5e1, 0xd9efd0ec,
  0xf0fcf7c8, 0x20d4074f, 0x15547fee, 0xf4839313, 0x17c189c, 0xaf1c332a, 0xde4d7c8c,
  0x84997eec, 0x5bd87a43, 0xb6d3d055, 0x3ae247b0, 0x2b8cb0a6, 0xd9d6ca35, 0x4bf12b94,
  0x97f33a51, 0x62fb84ad, 0x7e70e613, 0x520c709b
};


void
ppenc_sha256_len48(uint8_t *const hash_value,
                   uint8_t *const msg,
                   uint32_t *const message_schedule_buf)
{
  uint16_t i;
  uint32_t *blocks, *hash_value32;
  
  /* length */
  msg[48] = 0x80;
  msg[49] = 0;
  msg[50] = 0;
  msg[51] = 0;
  msg[52] = 0;
  msg[53] = 0;
  msg[54] = 0;
  msg[55] = 0;
  msg[56] = 0;
  msg[57] = 0;
  msg[58] = 0;
  msg[59] = 0;
  msg[60] = 0;
  msg[61] = 0;
  msg[62] = 0x01;
  msg[63] = 0x80;

  blocks = (uint32_t*) msg;
  for (i = 0; i < 16; i++)
    blocks[i] = BYTESWAP32(blocks[i]);

  hash_value32 = (uint32_t*) hash_value;
  sha256_block(hash_value32, blocks, message_schedule_buf);

  for (i = 0; i < 16; i++)
    blocks[i] = BYTESWAP32(blocks[i]);
  
  for (i = 0; i < 8; i++)
    hash_value32[i] = BYTESWAP32(hash_value32[i]);
}

void
ppenc_cubehash(uint8_t *const hash_value,
               uint8_t* const msg,
               uint32_t msg_len)
{
  uint16_t i, j, num_bytes, num_blocks;
  uint32_t *cubehash, *msg32;

  cubehash = (uint32_t*) hash_value;
  for (i = 0; i < 32; i++)
    cubehash[i] = CUBEHASH_INIT[i];

  /* leading padding 0x80 */
  msg[msg_len++] = 0x80;

  num_bytes = 0;
  num_blocks = 0;
  while (num_bytes < msg_len) {
    num_bytes += 32;
    num_blocks += 1;
  }

  /* pad msg */
  for(i = msg_len; i < num_bytes; i++)
    msg[i] = 0;

  /* hash in the message */
  msg32 = (uint32_t*) msg;
  for(i = 0; i < num_blocks; i++) {
    for (j = 0; j < 8; j++)
      cubehash[j] ^= msg32[j];
    cubehash_rounds(cubehash, 16);
    msg32 = msg32 + 8;
  }

  /* finalize */
  cubehash[31] ^= 1;
  cubehash_rounds(cubehash, 32);
}

static INLINE void
sha256_block(uint32_t* hash_value,
             const uint32_t *const blocks,
             uint32_t* message_schedule_buf)
{
  uint16_t t;

  hash_value[0] = SHA256_INITIAL_HASH_VALUE[0];
  hash_value[1] = SHA256_INITIAL_HASH_VALUE[1];
  hash_value[2] = SHA256_INITIAL_HASH_VALUE[2];
  hash_value[3] = SHA256_INITIAL_HASH_VALUE[3];
  hash_value[4] = SHA256_INITIAL_HASH_VALUE[4];
  hash_value[5] = SHA256_INITIAL_HASH_VALUE[5];
  hash_value[6] = SHA256_INITIAL_HASH_VALUE[6];
  hash_value[7] = SHA256_INITIAL_HASH_VALUE[7];

  /* prepare the message schedule */
  for (t = 0; t < 16; t++)
    message_schedule_buf[t] = blocks[t];

  for (; t < 64; t++)
    message_schedule_buf[t] = sha256_sigma1(message_schedule_buf[t - 2])
      + message_schedule_buf[t - 7]
      + sha256_sigma0(message_schedule_buf[t - 15])
      + message_schedule_buf[t - 16];

  for (t = 0; t < 64; t++) {
    uint32_t t1, t2;
    t1 = hash_value[7]
           + sha256_Sigma1(hash_value[4])
           + SHA_CH(hash_value[4], hash_value[5], hash_value[6])
           + SHA256_CONST[t] + message_schedule_buf[t];

    t2 = sha256_Sigma0(hash_value[0]) + SHA_MAJ(hash_value[0], hash_value[1], hash_value[2]);
    hash_value[7] = hash_value[6];
    hash_value[6] = hash_value[5];
    hash_value[5] = hash_value[4];
    hash_value[4] = hash_value[3] + t1;
    hash_value[3] = hash_value[2];
    hash_value[2] = hash_value[1];
    hash_value[1] = hash_value[0];
    hash_value[0] = t1 + t2;
  }

  /* update the hash */
  hash_value[0] += SHA256_INITIAL_HASH_VALUE[0];
  hash_value[1] += SHA256_INITIAL_HASH_VALUE[1];
  hash_value[2] += SHA256_INITIAL_HASH_VALUE[2];
  hash_value[3] += SHA256_INITIAL_HASH_VALUE[3];
  hash_value[4] += SHA256_INITIAL_HASH_VALUE[4];
  hash_value[5] += SHA256_INITIAL_HASH_VALUE[5];
  hash_value[6] += SHA256_INITIAL_HASH_VALUE[6];
  hash_value[7] += SHA256_INITIAL_HASH_VALUE[7];
}

static INLINE uint32_t
sha256_Sigma0(const uint32_t x)
{
  uint32_t ans;
  ans = (x >> 2) | (x << 30);
  ans ^= ((x >> 13) | (x << 19));
  ans ^= ((x >> 22) | (x << 10));

  return ans;
}

static INLINE uint32_t
sha256_Sigma1(const uint32_t x)
{
  uint32_t ans;
  ans = (x >> 6) | (x << 26);
  ans ^= ((x >> 11) | (x << 21));
  ans ^= ((x >> 25) | (x << 7));

  return ans;
}

static INLINE uint32_t
sha256_sigma0(const uint32_t x)
{
  uint32_t ans;
  ans = (x >> 7) | (x << 25);
  ans ^= ((x >> 18) | (x << 14));
  ans ^= (x >> 3);

  return ans;
}

static INLINE uint32_t
sha256_sigma1(const uint32_t x)
{
  uint32_t ans;
  ans = (x >> 17) | (x << 15);
  ans ^= ((x >> 19) | (x << 13));
  ans ^= (x >> 10);

  return ans;
}

STATIC INLINE void
cubehash_rounds(uint32_t *const state, const uint16_t num_rounds)
{
  uint16_t i, j;

#define SWAP(a, b) a ^= b; b ^= a; a ^= b;

  for(j = 0; j < num_rounds; j++) {

    for(i = 0; i < 16; i++) {
      state[i + 16] += state[i];
      state[i] = ROT_LEFT32(state[i], 7);
    }

     SWAP(state[0], state[8])
     SWAP(state[1], state[9])
     SWAP(state[2], state[10])
     SWAP(state[3], state[11])
     SWAP(state[4], state[12])
     SWAP(state[5], state[13])
     SWAP(state[6], state[14])
     SWAP(state[7], state[15])

    for(i = 0; i < 16; i++)
      state[i] ^= state[i + 16];

     SWAP(state[16], state[18])
     SWAP(state[17], state[19])
     SWAP(state[20], state[22])
     SWAP(state[21], state[23])
     SWAP(state[24], state[26])
     SWAP(state[25], state[27])
     SWAP(state[28], state[30])
     SWAP(state[29], state[31])

    for(i = 0; i < 16; i++) {
      state[i + 16] += state[i];
      state[i] = ROT_LEFT32(state[i], 11);
    }

     SWAP(state[0], state[4])
     SWAP(state[1], state[5])
     SWAP(state[2], state[6])
     SWAP(state[3], state[7])
     SWAP(state[8], state[12])
     SWAP(state[9], state[13])
     SWAP(state[10], state[14])
     SWAP(state[11], state[15])

    for(i = 0; i < 16; i++)
      state[i] ^= state[i + 16];

     SWAP(state[16], state[17])
     SWAP(state[18], state[19])
     SWAP(state[20], state[21])
     SWAP(state[22], state[23])
     SWAP(state[24], state[25])
     SWAP(state[26], state[27])
     SWAP(state[28], state[29])
     SWAP(state[30], state[31])
  }

#undef SWAP
}
