 #include "blockcipher.h"

#if defined(PPENC_64BIT)
#define ROT_LEFT64(x, z) ((x << z) | (x >> (64 - z)))
#endif

#define U32_MAX 0xffffffff
static const uint32_t C240_UPPER = 0x1BD11BDA;
static const uint32_t C240_LOWER = 0xA9FC1A22;

#if defined(PPENC_64BIT)
static const uint64_t C240 = 0x1BD11BDAA9FC1A22;
#endif

/* 64 bit functions */
STATIC INLINE void sixty4_add_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper);
STATIC INLINE void sixty4_sub_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper);
STATIC INLINE void sixty4_rotleft_inplace(uint32_t *const lhs, const uint8_t amount);
STATIC INLINE void sixty4_rotright_inplace(uint32_t *const lhs, const uint8_t amount);
STATIC INLINE void sixty4_rotleft_xor_inplace(uint32_t *const lhs,
					      uint32_t rhs_lower,
					      uint32_t rhs_upper,
					      const uint8_t amount);

STATIC INLINE void sixty4_rotright_xor_inplace(uint32_t *const lhs,
					       uint32_t rhs_lower,
					       uint32_t rhs_upper,
					       const uint8_t amount);

STATIC INLINE void sixty4_xor_rotleft_inplace(uint32_t *const lhs,
					      uint32_t rhs_lower,
					      uint32_t rhs_upper,
					      const uint8_t amount);

STATIC INLINE void sixty4_xor_rotright_inplace(uint32_t *const lhs,
					       uint32_t rhs_lower,
					       uint32_t rhs_upper,
					       const uint8_t amount);
STATIC INLINE void sixty4_mult_pcg32_const(uint32_t *const lhs);
static INLINE void sixty4_read_be64(uint32_t *const dst, const uint8_t *const value);

#if defined(PPENC_64BIT)
static INLINE uint64_t read_be64_64bit(const uint8_t *const value);
#endif

/* PCG32 functions */
STATIC INLINE uint32_t pcg32(const uint32_t inc, uint32_t *const state);
static void pcg32_next_tweaks(uint32_t *const tweaks, uint32_t block_num, uint32_t *const state);

#if defined(PPENC_64BIT)
STATIC INLINE uint32_t pcg32_64bit(const uint32_t inc, uint64_t *const state);
static void pcg32_next_tweaks_64bit(uint32_t *const tweaks, uint32_t block_num, uint64_t *const state);
#endif

/* threefish functions */
STATIC void threefish_buf_init(struct ThreeFishBuffer *const buf3f,
                               const uint8_t *const key,
                               uint32_t *const pcg32_state);
STATIC void threefish_encrypt_block(const struct ThreeFishBuffer *const buf3f,
                                    uint32_t *const block,
                                    uint32_t *const block_alt);
STATIC void threefish_decrypt_block(const struct ThreeFishBuffer *const buf3f,
                                    uint32_t *const block,
                                    uint32_t *const block_alt);

#if defined(PPENC_64BIT)
STATIC void
threefish_buf_init_64bit(struct ThreeFishBuffer64 *const buf3f,
                         const uint8_t *const body_key,
			 uint64_t *const pcg32_state);

STATIC void
threefish_encrypt_block_64bit(const struct ThreeFishBuffer64 *const buf3f,
                              uint64_t *const block,
                              uint64_t *const block_alt);
STATIC void
threefish_decrypt_block_64bit(const struct ThreeFishBuffer64 *const buf3f,
                              uint64_t *const block,
                              uint64_t *const block_alt);
#endif


void
ppenc_threefish512_encrypt(const uint8_t *const key,
                           const uint8_t *const tweak_seed,
                           uint8_t* const body,
                           const uint32_t num_blocks,
                           struct ThreeFishBuffer *const buf3f,
                           uint8_t *const buf64)
{
  uint32_t pcg32_state[2];
  uint32_t block_num, s;
  uint32_t* block;

  sixty4_read_be64(pcg32_state, tweak_seed);
  threefish_buf_init(buf3f, key, pcg32_state);

  block = (uint32_t*) body;

  for (block_num = 1; block_num <= num_blocks; block_num++) {
    threefish_encrypt_block(buf3f, block, (uint32_t*) buf64);

    pcg32_next_tweaks(buf3f->tweaks, block_num, pcg32_state);
    for (s = 0; s <= 18; s++) {
      uint16_t tweak_ind;

      tweak_ind = (s % 3) * 2;
      sixty4_add_inplace(buf3f->subkeys[s]._5, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);

      tweak_ind = ((s + 1) % 3) * 2;
      sixty4_add_inplace(buf3f->subkeys[s]._6, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);
    }

    block = block + 16;
  }
}

#if defined(PPENC_64BIT)
void
ppenc_threefish512_encrypt_64bit(const uint8_t *const key,
                                 const uint8_t *const tweak_seed,
                                 uint8_t* const body,
                                 const uint32_t num_blocks,
                                 struct ThreeFishBuffer64 *const buf3f,
                                 uint8_t *const buf64)
{
  uint64_t pcg32_state;
  uint32_t block_num, s;
  uint64_t* block;

  pcg32_state = read_be64_64bit(tweak_seed);
  threefish_buf_init_64bit(buf3f, key, &pcg32_state);

  block = (uint64_t*) body;

  for (block_num = 1; block_num <= num_blocks; block_num++) {
    threefish_encrypt_block_64bit(buf3f, block, (uint64_t*) buf64);

    pcg32_next_tweaks_64bit(buf3f->tweaks, block_num, &pcg32_state);
    for (s = 0; s <= 18; s++) {
      uint16_t tweak_ind;
      uint64_t tmp;
      tweak_ind = (s % 3) * 2;
      tmp = buf3f->tweaks[tweak_ind + 1];
      tmp <<= 32;
      tmp += buf3f->tweaks[tweak_ind];
      buf3f->subkeys[s]._5 += tmp;

      tweak_ind = ((s + 1) % 3) * 2;
      tmp = buf3f->tweaks[tweak_ind+ 1];
      tmp <<= 32;
      tmp += buf3f->tweaks[tweak_ind];
      buf3f->subkeys[s]._6 += tmp;
    }

    block = block + 8;
  }
}
#endif

void
ppenc_threefish512_decrypt(const uint8_t *const key,
                           const uint8_t *const tweak_seed,
                           uint8_t* const body,
                           const uint32_t num_blocks,
                           struct ThreeFishBuffer *const buf3f,
                           uint8_t *const buf64)
{
  uint32_t pcg32_state[2];
  uint32_t block_num, s;
  uint32_t* block;

  sixty4_read_be64(pcg32_state, tweak_seed);
  threefish_buf_init(buf3f, key, pcg32_state);

  block = (uint32_t*) body;

  for (block_num = 1; block_num <= num_blocks; block_num++) {
    threefish_decrypt_block(buf3f, block, (uint32_t*) buf64);

    pcg32_next_tweaks(buf3f->tweaks, block_num, pcg32_state);
    for (s = 0; s <= 18; s++) {
      uint16_t tweak_ind;

      tweak_ind = (s % 3) * 2;
      sixty4_add_inplace(buf3f->subkeys[s]._5, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);

      tweak_ind = ((s + 1) % 3) * 2;
      sixty4_add_inplace(buf3f->subkeys[s]._6, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);
    }

    block = block + 16;
  }
}

#if defined(PPENC_64BIT)
void
ppenc_threefish512_decrypt_64bit(const uint8_t *const key,
                                 const uint8_t *const tweak_seed,
                                 uint8_t* const body,
                                 const uint32_t num_blocks,
                                 struct ThreeFishBuffer64 *const buf3f,
                                 uint8_t *const buf64)
{
  uint64_t pcg32_state;
  uint32_t block_num, s;
  uint64_t* block;

  pcg32_state = read_be64_64bit(tweak_seed);
  threefish_buf_init_64bit(buf3f, key, &pcg32_state);

  block = (uint64_t*) body;

  for (block_num = 1; block_num <= num_blocks; block_num++) {
    threefish_decrypt_block_64bit(buf3f, block, (uint64_t*) buf64);

    pcg32_next_tweaks_64bit(buf3f->tweaks, block_num, &pcg32_state);
    for (s = 0; s <= 18; s++) {
      uint16_t tweak_ind;
      uint64_t tmp;
      tweak_ind = (s % 3) * 2;
      tmp = buf3f->tweaks[tweak_ind + 1];
      tmp <<= 32;
      tmp += buf3f->tweaks[tweak_ind];
      buf3f->subkeys[s]._5 += tmp;

      tweak_ind = ((s + 1) % 3) * 2;
      tmp = buf3f->tweaks[tweak_ind+ 1];
      tmp <<= 32;
      tmp += buf3f->tweaks[tweak_ind];
      buf3f->subkeys[s]._6 += tmp;
    }

    block = block + 8;
  }
}
#endif

STATIC INLINE void
sixty4_add_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper)
{
  lhs[1] += rhs_upper;

  if (lhs[0] > (U32_MAX - rhs_lower))
    lhs[1] += 1;

  lhs[0] += rhs_lower;
}

STATIC INLINE void
sixty4_sub_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper)
{
  rhs_lower = ~rhs_lower;
  rhs_upper = ~rhs_upper;

  if (rhs_lower == U32_MAX)
    rhs_upper += 1;

  rhs_lower += 1;
  sixty4_add_inplace(lhs, rhs_lower, rhs_upper);
}

STATIC INLINE void
sixty4_rotleft_inplace(uint32_t *const lhs, const uint8_t amount)
{
  uint32_t upper;

  upper = (lhs[1] << amount) | (lhs[0] >> (32 - amount));
  lhs[0] = (lhs[0] << amount) | (lhs[1] >> (32 - amount));
  lhs[1] = upper;
}

STATIC INLINE void
sixty4_rotright_inplace(uint32_t *const lhs, const uint8_t amount)
{
  uint32_t lower;

  lower = (lhs[0] >> amount) | (lhs[1] << (32 - amount));
  lhs[1] = (lhs[1] >> amount) | (lhs[0] << (32 - amount));
  lhs[0] = lower;
}

STATIC INLINE void
sixty4_rotleft_xor_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper, const uint8_t amount)
{
  sixty4_rotleft_inplace(lhs, amount);
  lhs[0] ^= rhs_lower;
  lhs[1] ^= rhs_upper;
}

STATIC INLINE void
sixty4_rotright_xor_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper, const uint8_t amount)
{
  sixty4_rotright_inplace(lhs, amount);
  lhs[0] ^= rhs_lower;
  lhs[1] ^= rhs_upper;
}

STATIC INLINE void
sixty4_xor_rotleft_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper, const uint8_t amount)
{
  lhs[0] ^= rhs_lower;
  lhs[1] ^= rhs_upper;
  sixty4_rotleft_inplace(lhs, amount);
}

STATIC INLINE void
sixty4_xor_rotright_inplace(uint32_t *const lhs, uint32_t rhs_lower, uint32_t rhs_upper, const uint8_t amount)
{
  lhs[0] ^= rhs_lower;
  lhs[1] ^= rhs_upper;
  sixty4_rotright_inplace(lhs, amount);
}

STATIC INLINE void
sixty4_mult_pcg32_const(uint32_t *const lhs)
{
  uint64_t ans;
  ans = lhs[1];
  ans <<= 32;
  ans += lhs[0];

  ans *= 6364136223846793005ULL;

  lhs[1] = ans >> 32;
  lhs[0] = ans;
}

static INLINE void
sixty4_read_be64(uint32_t *const dst, const uint8_t *const value)
{
  dst[1] = value[0];
  dst[1] <<= 8;
  dst[1] |= value[1];
  dst[1] <<= 8;
  dst[1] |= value[2];
  dst[1] <<= 8;
  dst[1] |= value[3];

  dst[0] = value[4];
  dst[0] <<= 8;
  dst[0] |= value[5];
  dst[0] <<= 8;
  dst[0] |= value[6];
  dst[0] <<= 8;
  dst[0] |= value[7];
}

#if defined(PPENC_64BIT)
static INLINE uint64_t
read_be64_64bit(const uint8_t *const value)
{
  uint64_t ans;
  ans = value[0];
  ans <<= 8;
  ans |= value[1];
  ans <<= 8;
  ans |= value[2];
  ans <<= 8;
  ans |= value[3];
  ans <<= 8;
  ans |= value[4];
  ans <<= 8;
  ans |= value[5];
  ans <<= 8;
  ans |= value[6];
  ans <<= 8;
  ans |= value[7];

  return ans;
}
#endif

STATIC INLINE uint32_t
pcg32(const uint32_t inc, uint32_t *const state)
{
  uint32_t oldstate[2];
  uint32_t xorshifted[2];
  uint32_t rot;

  oldstate[0] = state[0];
  oldstate[1] = state[1];

  sixty4_mult_pcg32_const(state);

  if (state[0] > (0xffffffff - (inc | 1)))
    state[1] += 1;

  state[0] += inc | 1;
  xorshifted[0] = (oldstate[0] >> 18) | (oldstate[1] << (32 - 18));
  xorshifted[1] = oldstate[1] >> 18;
  xorshifted[0] ^= oldstate[0];
  xorshifted[1] ^= oldstate[1];
  xorshifted[0] = (xorshifted[0] >> 27) | (xorshifted[1] << 5);
  rot = oldstate[0] >> 27;
  rot = oldstate[1] >> 27;
  return (xorshifted[0] >> rot) | (xorshifted[0] << ((-rot) & 31));
}

static void
pcg32_next_tweaks(uint32_t *const tweaks, uint32_t block_num, uint32_t *const state)
{
  block_num *= 4;
  tweaks[0] = pcg32(block_num, state);
  tweaks[1] = pcg32(block_num + 1, state);
  tweaks[2] = pcg32(block_num + 2, state);
  tweaks[3] = pcg32(block_num + 3, state);
  tweaks[4] = tweaks[0] ^ tweaks[2];
  tweaks[5] = tweaks[1] ^ tweaks[3];
}

#if defined(PPENC_64BIT)
STATIC INLINE uint32_t
pcg32_64bit(const uint32_t inc, uint64_t *const state)
{
  uint64_t oldstate;
  uint32_t xorshifted;
  uint32_t rot;

  oldstate = *state;
  *state = oldstate * 6364136223846793005ULL;
  *state += inc | 1;
  xorshifted = ((oldstate >> 18) ^ oldstate) >> 27;
  rot = oldstate >> 59;
  return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

static void
pcg32_next_tweaks_64bit(uint32_t *const tweaks, uint32_t block_num, uint64_t *const state)
{
  block_num *= 4;
  tweaks[0] = pcg32_64bit(block_num, state);
  tweaks[1] = pcg32_64bit(block_num + 1, state);
  tweaks[2] = pcg32_64bit(block_num + 2, state);
  tweaks[3] = pcg32_64bit(block_num + 3, state);
  tweaks[4] = tweaks[0] ^ tweaks[2];
  tweaks[5] = tweaks[1] ^ tweaks[3];
}
#endif

STATIC void
threefish_buf_init(struct ThreeFishBuffer *const buf3f,
                   const uint8_t *const body_key,
		   uint32_t *const pcg32_state)
{
  uint16_t i;

  /* set the tweaks */
  pcg32_next_tweaks(buf3f->tweaks, 0, pcg32_state);

  /* save the keys */
  buf3f->keys[8].lower = C240_LOWER;
  buf3f->keys[8].upper = C240_UPPER;
  for (i = 0; i < 8; i++) {
    buf3f->keys[i].lower = ((uint32_t*) body_key)[i * 2];
    buf3f->keys[i].upper = ((uint32_t*) body_key)[(i * 2) + 1];
    buf3f->keys[8].lower ^= buf3f->keys[i].lower;
    buf3f->keys[8].upper ^= buf3f->keys[i].upper;
  }

  /* compute the subkeys */
  for (i = 0; i <= 18; i++) {
    uint16_t tweak_ind;
    buf3f->subkeys[i]._0[0] = buf3f->keys[i % 9].lower;
    buf3f->subkeys[i]._0[1] = buf3f->keys[i % 9].upper;
    buf3f->subkeys[i]._1[0] = buf3f->keys[(i + 1) % 9].lower;
    buf3f->subkeys[i]._1[1] = buf3f->keys[(i + 1) % 9].upper;
    buf3f->subkeys[i]._2[0] = buf3f->keys[(i + 2) % 9].lower;
    buf3f->subkeys[i]._2[1] = buf3f->keys[(i + 2) % 9].upper;
    buf3f->subkeys[i]._3[0] = buf3f->keys[(i + 3) % 9].lower;
    buf3f->subkeys[i]._3[1] = buf3f->keys[(i + 3) % 9].upper;
    buf3f->subkeys[i]._4[0] = buf3f->keys[(i + 4) % 9].lower;
    buf3f->subkeys[i]._4[1] = buf3f->keys[(i + 4) % 9].upper;
    buf3f->subkeys[i]._5[0] = buf3f->keys[(i + 5) % 9].lower;
    buf3f->subkeys[i]._5[1] = buf3f->keys[(i + 5) % 9].upper;
    buf3f->subkeys[i]._6[0] = buf3f->keys[(i + 6) % 9].lower;
    buf3f->subkeys[i]._6[1] = buf3f->keys[(i + 6) % 9].upper;
    buf3f->subkeys[i]._7[0] = buf3f->keys[(i + 7) % 9].lower;
    buf3f->subkeys[i]._7[1] = buf3f->keys[(i + 7) % 9].upper;

    /* apply tweak0 */
    tweak_ind = (i % 3) * 2;
    sixty4_add_inplace(buf3f->subkeys[i]._5, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);
    tweak_ind = ((i + 1) % 3) * 2;
    sixty4_add_inplace(buf3f->subkeys[i]._6, buf3f->tweaks[tweak_ind], buf3f->tweaks[tweak_ind + 1]);
 
    sixty4_add_inplace(buf3f->subkeys[i]._7, i, 0);
  }
}

#if defined(PPENC_64BIT)
STATIC void
threefish_buf_init_64bit(struct ThreeFishBuffer64 *const buf3f,
                         const uint8_t *const body_key,
			 uint64_t *const pcg32_state)
{
  uint16_t i;

  /* generate the tweaks */
  pcg32_next_tweaks_64bit(buf3f->tweaks, 0, pcg32_state);

  /* save the keys */
  buf3f->keys[8] = C240;
  for (i = 0; i < 8; i++) {
    buf3f->keys[i] = ((uint64_t*) body_key)[i];
    buf3f->keys[8] ^= buf3f->keys[i];
  }

  /* compute the subkeys */
  for (i = 0; i <= 18; i++) {
    uint16_t tweak_ind;
    uint64_t tmp;
    buf3f->subkeys[i]._0 = buf3f->keys[i % 9];
    buf3f->subkeys[i]._1 = buf3f->keys[(i + 1) % 9];
    buf3f->subkeys[i]._2 = buf3f->keys[(i + 2) % 9];
    buf3f->subkeys[i]._3 = buf3f->keys[(i + 3) % 9];
    buf3f->subkeys[i]._4 = buf3f->keys[(i + 4) % 9];
    buf3f->subkeys[i]._5 = buf3f->keys[(i + 5) % 9];
    buf3f->subkeys[i]._6 = buf3f->keys[(i + 6) % 9];
    buf3f->subkeys[i]._7 = buf3f->keys[(i + 7) % 9];

    /* apply tweak0 */
    tweak_ind = (i % 3) * 2;
    tmp = buf3f->tweaks[tweak_ind + 1];
    tmp <<= 32;
    tmp += buf3f->tweaks[tweak_ind];
    buf3f->subkeys[i]._5 += tmp;

    tweak_ind = ((i + 1) % 3) * 2;
    tmp = buf3f->tweaks[tweak_ind+ 1];
    tmp <<= 32;
    tmp += buf3f->tweaks[tweak_ind];
    buf3f->subkeys[i]._6 += tmp;

    buf3f->subkeys[i]._7 += i;
  }
}

#endif

STATIC void
threefish_encrypt_block(const struct ThreeFishBuffer *const buf3f,
                        uint32_t *const block,
                        uint32_t *const block_alt)
{
  uint16_t d, s;
  const struct ThreeFishSubKeys *subkeys;

  subkeys = buf3f->subkeys;

  for (d = 0; d < 72; d += 8) {
    s = d / 4;

    sixty4_add_inplace(block, subkeys[s]._0[0], subkeys[s]._0[1]);
    sixty4_add_inplace(block + 2, subkeys[s]._1[0], subkeys[s]._1[1]);
    sixty4_add_inplace(block + 4, subkeys[s]._2[0], subkeys[s]._2[1]);
    sixty4_add_inplace(block + 6, subkeys[s]._3[0], subkeys[s]._3[1]);
    sixty4_add_inplace(block + 8, subkeys[s]._4[0], subkeys[s]._4[1]);
    sixty4_add_inplace(block + 10, subkeys[s]._5[0], subkeys[s]._5[1]);
    sixty4_add_inplace(block + 12, subkeys[s]._6[0], subkeys[s]._6[1]);
    sixty4_add_inplace(block + 14, subkeys[s]._7[0], subkeys[s]._7[1]);

    /* round 1 */
    sixty4_add_inplace(block, block[2], block[3]);
    sixty4_add_inplace(block + 4, block[6], block[7]);
    sixty4_add_inplace(block + 8, block[10], block[11]);
    sixty4_add_inplace(block + 12, block[14], block[15]);
    sixty4_rotright_xor_inplace(block + 2, block[0], block[1], 18);
    sixty4_rotright_xor_inplace(block + 6, block[4], block[5], 28);
    sixty4_rotleft_xor_inplace(block + 10, block[8], block[9], 19);
    sixty4_rotright_xor_inplace(block + 14, block[12], block[13], 27);

    block_alt[0] = block[4];
    block_alt[1] = block[5];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[8];
    block_alt[5] = block[9];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[12];
    block_alt[9] = block[13];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[0];
    block_alt[13] = block[1];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    /* round 2 */
    sixty4_add_inplace(block_alt, block_alt[2], block_alt[3]);
    sixty4_add_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_add_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_add_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_rotright_xor_inplace(block_alt + 2, block_alt[0], block_alt[1], 31);
    sixty4_rotleft_xor_inplace(block_alt + 6, block_alt[4], block_alt[5], 27);
    sixty4_rotleft_xor_inplace(block_alt + 10, block_alt[8], block_alt[9], 14);
    sixty4_rotright_xor_inplace(block_alt + 14, block_alt[12], block_alt[13], 22);

    block[0] = block_alt[4];
    block[1] = block_alt[5];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[8];
    block[5] = block_alt[9];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[12];
    block[9] = block_alt[13];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[0];
    block[13] = block_alt[1];
    block[14] = block_alt[6];
    block[15] = block_alt[7];


    /* round 3 */
    sixty4_add_inplace(block, block[2], block[3]);
    sixty4_add_inplace(block + 4, block[6], block[7]);
    sixty4_add_inplace(block + 8, block[10], block[11]);
    sixty4_add_inplace(block + 12, block[14], block[15]);
    sixty4_rotleft_xor_inplace(block + 2, block[0], block[1], 17);
    sixty4_rotright_xor_inplace(block + 6, block[4], block[5], 15);
    sixty4_rotright_xor_inplace(block + 10, block[8], block[9], 28);
    sixty4_rotright_xor_inplace(block + 14, block[12], block[13], 25);

    block_alt[0] = block[4];
    block_alt[1] = block[5];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[8];
    block_alt[5] = block[9];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[12];
    block_alt[9] = block[13];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[0];
    block_alt[13] = block[1];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    /* round 4 */
    sixty4_add_inplace(block_alt, block_alt[2], block_alt[3]);
    sixty4_add_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_add_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_add_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_rotright_xor_inplace(block_alt + 2, block_alt[0], block_alt[1], 20);
    sixty4_rotleft_xor_inplace(block_alt + 6, block_alt[4], block_alt[5], 9);
    sixty4_rotright_xor_inplace(block_alt + 10, block_alt[8], block_alt[9], 10);
    sixty4_rotright_xor_inplace(block_alt + 14, block_alt[12], block_alt[13], 8);

    block[0] = block_alt[4];
    block[1] = block_alt[5];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[8];
    block[5] = block_alt[9];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[12];
    block[9] = block_alt[13];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[0];
    block[13] = block_alt[1];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    /* add round subkey a */
    sixty4_add_inplace(block, subkeys[s+1]._0[0], subkeys[s+1]._0[1]);
    sixty4_add_inplace(block + 2, subkeys[s+1]._1[0], subkeys[s+1]._1[1]);
    sixty4_add_inplace(block + 4, subkeys[s+1]._2[0], subkeys[s+1]._2[1]);
    sixty4_add_inplace(block + 6, subkeys[s+1]._3[0], subkeys[s+1]._3[1]);
    sixty4_add_inplace(block + 8, subkeys[s+1]._4[0], subkeys[s+1]._4[1]);
    sixty4_add_inplace(block + 10, subkeys[s+1]._5[0], subkeys[s+1]._5[1]);
    sixty4_add_inplace(block + 12, subkeys[s+1]._6[0], subkeys[s+1]._6[1]);
    sixty4_add_inplace(block + 14, subkeys[s+1]._7[0], subkeys[s+1]._7[1]);

    /* round 1a */
    sixty4_add_inplace(block, block[2], block[3]);
    sixty4_add_inplace(block + 4, block[6], block[7]);
    sixty4_add_inplace(block + 8, block[10], block[11]);
    sixty4_add_inplace(block + 12, block[14], block[15]);
    sixty4_rotright_xor_inplace(block + 2, block[0], block[1], 25);
    sixty4_rotleft_xor_inplace(block + 6, block[4], block[5], 30);
    sixty4_rotright_xor_inplace(block + 10, block[8], block[9], 30);
    sixty4_rotleft_xor_inplace(block + 14, block[12], block[13], 24);

    block_alt[0] = block[4];
    block_alt[1] = block[5];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[8];
    block_alt[5] = block[9];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[12];
    block_alt[9] = block[13];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[0];
    block_alt[13] = block[1];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    /* round 2a */
    sixty4_add_inplace(block_alt, block_alt[2], block_alt[3]);
    sixty4_add_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_add_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_add_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_rotleft_xor_inplace(block_alt + 2, block_alt[0], block_alt[1], 13);
    sixty4_rotright_xor_inplace(block_alt + 6, block_alt[4], block_alt[5], 14);
    sixty4_rotleft_xor_inplace(block_alt + 10, block_alt[8], block_alt[9], 10);
    sixty4_rotleft_xor_inplace(block_alt + 14, block_alt[12], block_alt[13], 17);

    block[0] = block_alt[4];
    block[1] = block_alt[5];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[8];
    block[5] = block_alt[9];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[12];
    block[9] = block_alt[13];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[0];
    block[13] = block_alt[1];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    /* round 3a */
    sixty4_add_inplace(block, block[2], block[3]);
    sixty4_add_inplace(block + 4, block[6], block[7]);
    sixty4_add_inplace(block + 8, block[10], block[11]);
    sixty4_add_inplace(block + 12, block[14], block[15]);
    sixty4_rotleft_xor_inplace(block + 2, block[0], block[1], 25);
    sixty4_rotleft_xor_inplace(block + 6, block[4], block[5], 29);
    sixty4_rotright_xor_inplace(block + 10, block[8], block[9], 25);
    sixty4_rotright_xor_inplace(block + 14, block[12], block[13], 21);

    block_alt[0] = block[4];
    block_alt[1] = block[5];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[8];
    block_alt[5] = block[9];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[12];
    block_alt[9] = block[13];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[0];
    block_alt[13] = block[1];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    /* round 4a */
    sixty4_add_inplace(block_alt, block_alt[2], block_alt[3]);
    sixty4_add_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_add_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_add_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_rotleft_xor_inplace(block_alt + 2, block_alt[0], block_alt[1], 8);
    sixty4_rotright_xor_inplace(block_alt + 6, block_alt[4], block_alt[5], 29);
    sixty4_rotright_xor_inplace(block_alt + 10, block_alt[8], block_alt[9], 8);
    sixty4_rotleft_xor_inplace(block_alt + 14, block_alt[12], block_alt[13], 22);

    block[0] = block_alt[4];
    block[1] = block_alt[5];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[8];
    block[5] = block_alt[9];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[12];
    block[9] = block_alt[13];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[0];
    block[13] = block_alt[1];
    block[14] = block_alt[6];
    block[15] = block_alt[7];
  }

  /* add the final subkey */
  sixty4_add_inplace(block, subkeys[18]._0[0], subkeys[18]._0[1]);
  sixty4_add_inplace(block + 2, subkeys[18]._1[0], subkeys[18]._1[1]);
  sixty4_add_inplace(block + 4, subkeys[18]._2[0], subkeys[18]._2[1]);
  sixty4_add_inplace(block + 6, subkeys[18]._3[0], subkeys[18]._3[1]);
  sixty4_add_inplace(block + 8, subkeys[18]._4[0], subkeys[18]._4[1]);
  sixty4_add_inplace(block + 10, subkeys[18]._5[0], subkeys[18]._5[1]);
  sixty4_add_inplace(block + 12, subkeys[18]._6[0], subkeys[18]._6[1]);
  sixty4_add_inplace(block + 14, subkeys[18]._7[0], subkeys[18]._7[1]);
}

#if defined(PPENC_64BIT)
STATIC void
threefish_encrypt_block_64bit(const struct ThreeFishBuffer64 *const buf3f,
                              uint64_t *const block,
                              uint64_t *const block_alt)
{
  uint32_t d, s;
  const struct ThreeFishSubKeys64 *subkeys;

  subkeys = buf3f->subkeys;

  for(d = 0; d < 72; d += 8) {
    s = d / 4;
    
    block[0] += subkeys[s]._0;
    block[1] += subkeys[s]._1;
    block[2] += subkeys[s]._2;
    block[3] += subkeys[s]._3;
    block[4] += subkeys[s]._4;
    block[5] += subkeys[s]._5;
    block[6] += subkeys[s]._6;
    block[7] += subkeys[s]._7;

    /* round 1 */
    block[0] += block[1];
    block[2] += block[3];
    block[4] += block[5];
    block[6] += block[7];
    block[1] = ROT_LEFT64(block[1], 46) ^ block[0];
    block[3] = ROT_LEFT64(block[3], 36) ^ block[2];
    block[5] = ROT_LEFT64(block[5], 19) ^ block[4];
    block[7] = ROT_LEFT64(block[7], 37) ^ block[6];

    block_alt[0] = block[2];
    block_alt[1] = block[1];
    block_alt[2] = block[4];
    block_alt[3] = block[7];
    block_alt[4] = block[6];
    block_alt[5] = block[5];
    block_alt[6] = block[0];
    block_alt[7] = block[3];

    /* round 2 */
    block_alt[0] += block_alt[1];
    block_alt[2] += block_alt[3];
    block_alt[4] += block_alt[5];
    block_alt[6] += block_alt[7];
    block_alt[1] = ROT_LEFT64(block_alt[1], 33) ^ block_alt[0];
    block_alt[3] = ROT_LEFT64(block_alt[3], 27) ^ block_alt[2];
    block_alt[5] = ROT_LEFT64(block_alt[5], 14) ^ block_alt[4];
    block_alt[7] = ROT_LEFT64(block_alt[7], 42) ^ block_alt[6];

    block[0] = block_alt[2];
    block[1] = block_alt[1];
    block[2] = block_alt[4];
    block[3] = block_alt[7];
    block[4] = block_alt[6];
    block[5] = block_alt[5];
    block[6] = block_alt[0];
    block[7] = block_alt[3];

    /* round 3 */
    block[0] += block[1];
    block[2] += block[3];
    block[4] += block[5];
    block[6] += block[7];
    block[1] = ROT_LEFT64(block[1], 17) ^ block[0];
    block[3] = ROT_LEFT64(block[3], 49) ^ block[2];
    block[5] = ROT_LEFT64(block[5], 36) ^ block[4];
    block[7] = ROT_LEFT64(block[7], 39) ^ block[6];

    block_alt[0] = block[2];
    block_alt[1] = block[1];
    block_alt[2] = block[4];
    block_alt[3] = block[7];
    block_alt[4] = block[6];
    block_alt[5] = block[5];
    block_alt[6] = block[0];
    block_alt[7] = block[3];

    /* round 4 */
    block_alt[0] += block_alt[1];
    block_alt[2] += block_alt[3];
    block_alt[4] += block_alt[5];
    block_alt[6] += block_alt[7];
    block_alt[1] = ROT_LEFT64(block_alt[1], 44) ^ block_alt[0];
    block_alt[3] = ROT_LEFT64(block_alt[3], 9) ^ block_alt[2];
    block_alt[5] = ROT_LEFT64(block_alt[5], 54) ^ block_alt[4];
    block_alt[7] = ROT_LEFT64(block_alt[7], 56) ^ block_alt[6];

    block[0] = block_alt[2];
    block[1] = block_alt[1];
    block[2] = block_alt[4];
    block[3] = block_alt[7];
    block[4] = block_alt[6];
    block[5] = block_alt[5];
    block[6] = block_alt[0];
    block[7] = block_alt[3];

    /* second round key */
    block[0] += subkeys[s+1]._0;
    block[1] += subkeys[s+1]._1;
    block[2] += subkeys[s+1]._2;
    block[3] += subkeys[s+1]._3;
    block[4] += subkeys[s+1]._4;
    block[5] += subkeys[s+1]._5;
    block[6] += subkeys[s+1]._6;
    block[7] += subkeys[s+1]._7;

    /* round 1 */
    block[0] += block[1];
    block[2] += block[3];
    block[4] += block[5];
    block[6] += block[7];
    block[1] = ROT_LEFT64(block[1], 39) ^ block[0];
    block[3] = ROT_LEFT64(block[3], 30) ^ block[2];
    block[5] = ROT_LEFT64(block[5], 34) ^ block[4];
    block[7] = ROT_LEFT64(block[7], 24) ^ block[6];

    block_alt[0] = block[2];
    block_alt[1] = block[1];
    block_alt[2] = block[4];
    block_alt[3] = block[7];
    block_alt[4] = block[6];
    block_alt[5] = block[5];
    block_alt[6] = block[0];
    block_alt[7] = block[3];

    /* round 2 */
    block_alt[0] += block_alt[1];
    block_alt[2] += block_alt[3];
    block_alt[4] += block_alt[5];
    block_alt[6] += block_alt[7];
    block_alt[1] = ROT_LEFT64(block_alt[1], 13) ^ block_alt[0];
    block_alt[3] = ROT_LEFT64(block_alt[3], 50) ^ block_alt[2];
    block_alt[5] = ROT_LEFT64(block_alt[5], 10) ^ block_alt[4];
    block_alt[7] = ROT_LEFT64(block_alt[7], 17) ^ block_alt[6];

    block[0] = block_alt[2];
    block[1] = block_alt[1];
    block[2] = block_alt[4];
    block[3] = block_alt[7];
    block[4] = block_alt[6];
    block[5] = block_alt[5];
    block[6] = block_alt[0];
    block[7] = block_alt[3];

    /* round 3 */
    block[0] += block[1];
    block[2] += block[3];
    block[4] += block[5];
    block[6] += block[7];
    block[1] = ROT_LEFT64(block[1], 25) ^ block[0];
    block[3] = ROT_LEFT64(block[3], 29) ^ block[2];
    block[5] = ROT_LEFT64(block[5], 39) ^ block[4];
    block[7] = ROT_LEFT64(block[7], 43) ^ block[6];

    block_alt[0] = block[2];
    block_alt[1] = block[1];
    block_alt[2] = block[4];
    block_alt[3] = block[7];
    block_alt[4] = block[6];
    block_alt[5] = block[5];
    block_alt[6] = block[0];
    block_alt[7] = block[3];

    /* round 4 */
    block_alt[0] += block_alt[1];
    block_alt[2] += block_alt[3];
    block_alt[4] += block_alt[5];
    block_alt[6] += block_alt[7];
    block_alt[1] = ROT_LEFT64(block_alt[1], 8) ^ block_alt[0];
    block_alt[3] = ROT_LEFT64(block_alt[3], 35) ^ block_alt[2];
    block_alt[5] = ROT_LEFT64(block_alt[5], 56) ^ block_alt[4];
    block_alt[7] = ROT_LEFT64(block_alt[7], 22) ^ block_alt[6];

    block[0] = block_alt[2];
    block[1] = block_alt[1];
    block[2] = block_alt[4];
    block[3] = block_alt[7];
    block[4] = block_alt[6];
    block[5] = block_alt[5];
    block[6] = block_alt[0];
    block[7] = block_alt[3];
  }

  /* add the final key */
  block[0] += subkeys[18]._0;
  block[1] += subkeys[18]._1;
  block[2] += subkeys[18]._2;
  block[3] += subkeys[18]._3;
  block[4] += subkeys[18]._4;
  block[5] += subkeys[18]._5;
  block[6] += subkeys[18]._6;
  block[7] += subkeys[18]._7;
}

#endif

STATIC void
threefish_decrypt_block(const struct ThreeFishBuffer *const buf3f,
                        uint32_t *const block,
                        uint32_t *const block_alt)
{
  uint32_t d, s;
  const struct ThreeFishSubKeys *subkeys;

  subkeys = buf3f->subkeys;

  /* subtract the final key */
  sixty4_sub_inplace(block, subkeys[18]._0[0], subkeys[18]._0[1]);
  sixty4_sub_inplace(block + 2, subkeys[18]._1[0], subkeys[18]._1[1]);
  sixty4_sub_inplace(block + 4, subkeys[18]._2[0], subkeys[18]._2[1]);
  sixty4_sub_inplace(block + 6, subkeys[18]._3[0], subkeys[18]._3[1]);
  sixty4_sub_inplace(block + 8, subkeys[18]._4[0], subkeys[18]._4[1]);
  sixty4_sub_inplace(block + 10, subkeys[18]._5[0], subkeys[18]._5[1]);
  sixty4_sub_inplace(block + 12, subkeys[18]._6[0], subkeys[18]._6[1]);
  sixty4_sub_inplace(block + 14, subkeys[18]._7[0], subkeys[18]._7[1]);

  for (d = 72; d > 0; d-= 8) {
    s = (d - 8) / 4;

    /* round 4a */
    block_alt[0] = block[12];
    block_alt[1] = block[13];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[0];
    block_alt[5] = block[1];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[4];
    block_alt[9] = block[5];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[8];
    block_alt[13] = block[9];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    sixty4_xor_rotright_inplace(block_alt + 14, block_alt[12], block_alt[13], 22);
    sixty4_xor_rotleft_inplace(block_alt + 10, block_alt[8], block_alt[9], 8);
    sixty4_xor_rotleft_inplace(block_alt + 6, block_alt[4], block_alt[5], 29);
    sixty4_xor_rotright_inplace(block_alt + 2, block_alt[0], block_alt[1], 8);
    sixty4_sub_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_sub_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_sub_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_sub_inplace(block_alt, block_alt[2], block_alt[3]);

    /* round 3a */
    block[0] = block_alt[12];
    block[1] = block_alt[13];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[0];
    block[5] = block_alt[1];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[4];
    block[9] = block_alt[5];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[8];
    block[13] = block_alt[9];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    sixty4_xor_rotleft_inplace(block + 14, block[12], block[13], 21);
    sixty4_xor_rotleft_inplace(block + 10, block[8], block[9], 25);
    sixty4_xor_rotright_inplace(block + 6, block[4], block[5], 29);
    sixty4_xor_rotright_inplace(block + 2, block[0], block[1], 25);
    sixty4_sub_inplace(block + 12, block[14], block[15]);
    sixty4_sub_inplace(block + 8, block[10], block[11]);
    sixty4_sub_inplace(block + 4, block[6], block[7]);
    sixty4_sub_inplace(block, block[2], block[3]);

     /* round 2a */
    block_alt[0] = block[12];
    block_alt[1] = block[13];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[0];
    block_alt[5] = block[1];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[4];
    block_alt[9] = block[5];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[8];
    block_alt[13] = block[9];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    sixty4_xor_rotright_inplace(block_alt + 14, block_alt[12], block_alt[13], 17);
    sixty4_xor_rotright_inplace(block_alt + 10, block_alt[8], block_alt[9], 10);
    sixty4_xor_rotleft_inplace(block_alt + 6, block_alt[4], block_alt[5], 14);
    sixty4_xor_rotright_inplace(block_alt + 2, block_alt[0], block_alt[1], 13);
    sixty4_sub_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_sub_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_sub_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_sub_inplace(block_alt, block_alt[2], block_alt[3]);

    /* round 1a */
    block[0] = block_alt[12];
    block[1] = block_alt[13];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[0];
    block[5] = block_alt[1];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[4];
    block[9] = block_alt[5];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[8];
    block[13] = block_alt[9];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    sixty4_xor_rotright_inplace(block + 14, block[12], block[13], 24);
    sixty4_xor_rotleft_inplace(block + 10, block[8], block[9], 30);
    sixty4_xor_rotright_inplace(block + 6, block[4], block[5], 30);
    sixty4_xor_rotleft_inplace(block + 2, block[0], block[1], 25);
    sixty4_sub_inplace(block + 12, block[14], block[15]);
    sixty4_sub_inplace(block + 8, block[10], block[11]);
    sixty4_sub_inplace(block + 4, block[6], block[7]);
    sixty4_sub_inplace(block, block[2], block[3]);

    /* subtract subkey */
    sixty4_sub_inplace(block, subkeys[s+1]._0[0], subkeys[s+1]._0[1]);
    sixty4_sub_inplace(block + 2, subkeys[s+1]._1[0], subkeys[s+1]._1[1]);
    sixty4_sub_inplace(block + 4, subkeys[s+1]._2[0], subkeys[s+1]._2[1]);
    sixty4_sub_inplace(block + 6, subkeys[s+1]._3[0], subkeys[s+1]._3[1]);
    sixty4_sub_inplace(block + 8, subkeys[s+1]._4[0], subkeys[s+1]._4[1]);
    sixty4_sub_inplace(block + 10, subkeys[s+1]._5[0], subkeys[s+1]._5[1]);
    sixty4_sub_inplace(block + 12, subkeys[s+1]._6[0], subkeys[s+1]._6[1]);
    sixty4_sub_inplace(block + 14, subkeys[s+1]._7[0], subkeys[s+1]._7[1]);

    /* round 4 */
    block_alt[0] = block[12];
    block_alt[1] = block[13];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[0];
    block_alt[5] = block[1];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[4];
    block_alt[9] = block[5];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[8];
    block_alt[13] = block[9];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    sixty4_xor_rotleft_inplace(block_alt + 14, block_alt[12], block_alt[13], 8);
    sixty4_xor_rotleft_inplace(block_alt + 10, block_alt[8], block_alt[9], 10);
    sixty4_xor_rotright_inplace(block_alt + 6, block_alt[4], block_alt[5], 9);
    sixty4_xor_rotleft_inplace(block_alt + 2, block_alt[0], block_alt[1], 20);
    sixty4_sub_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_sub_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_sub_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_sub_inplace(block_alt, block_alt[2], block_alt[3]);

    /* round 3 */
    block[0] = block_alt[12];
    block[1] = block_alt[13];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[0];
    block[5] = block_alt[1];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[4];
    block[9] = block_alt[5];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[8];
    block[13] = block_alt[9];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    sixty4_xor_rotleft_inplace(block + 14, block[12], block[13], 25);
    sixty4_xor_rotleft_inplace(block + 10, block[8], block[9], 28);
    sixty4_xor_rotleft_inplace(block + 6, block[4], block[5], 15);
    sixty4_xor_rotright_inplace(block + 2, block[0], block[1], 17);
    sixty4_sub_inplace(block + 12, block[14], block[15]);
    sixty4_sub_inplace(block + 8, block[10], block[11]);
    sixty4_sub_inplace(block + 4, block[6], block[7]);
    sixty4_sub_inplace(block, block[2], block[3]);

     /* round 2 */
    block_alt[0] = block[12];
    block_alt[1] = block[13];
    block_alt[2] = block[2];
    block_alt[3] = block[3];
    block_alt[4] = block[0];
    block_alt[5] = block[1];
    block_alt[6] = block[14];
    block_alt[7] = block[15];
    block_alt[8] = block[4];
    block_alt[9] = block[5];
    block_alt[10] = block[10];
    block_alt[11] = block[11];
    block_alt[12] = block[8];
    block_alt[13] = block[9];
    block_alt[14] = block[6];
    block_alt[15] = block[7];

    sixty4_xor_rotleft_inplace(block_alt + 14, block_alt[12], block_alt[13], 22);
    sixty4_xor_rotright_inplace(block_alt + 10, block_alt[8], block_alt[9], 14);
    sixty4_xor_rotright_inplace(block_alt + 6, block_alt[4], block_alt[5], 27);
    sixty4_xor_rotleft_inplace(block_alt + 2, block_alt[0], block_alt[1], 31);
    sixty4_sub_inplace(block_alt + 12, block_alt[14], block_alt[15]);
    sixty4_sub_inplace(block_alt + 8, block_alt[10], block_alt[11]);
    sixty4_sub_inplace(block_alt + 4, block_alt[6], block_alt[7]);
    sixty4_sub_inplace(block_alt, block_alt[2], block_alt[3]);

    /* round 1 */
    block[0] = block_alt[12];
    block[1] = block_alt[13];
    block[2] = block_alt[2];
    block[3] = block_alt[3];
    block[4] = block_alt[0];
    block[5] = block_alt[1];
    block[6] = block_alt[14];
    block[7] = block_alt[15];
    block[8] = block_alt[4];
    block[9] = block_alt[5];
    block[10] = block_alt[10];
    block[11] = block_alt[11];
    block[12] = block_alt[8];
    block[13] = block_alt[9];
    block[14] = block_alt[6];
    block[15] = block_alt[7];

    sixty4_xor_rotleft_inplace(block + 14, block[12], block[13], 27);
    sixty4_xor_rotright_inplace(block + 10, block[8], block[9], 19);
    sixty4_xor_rotleft_inplace(block + 6, block[4], block[5], 28);
    sixty4_xor_rotleft_inplace(block + 2, block[0], block[1], 18);
    sixty4_sub_inplace(block + 12, block[14], block[15]);
    sixty4_sub_inplace(block + 8, block[10], block[11]);
    sixty4_sub_inplace(block + 4, block[6], block[7]);
    sixty4_sub_inplace(block, block[2], block[3]);

    /* subtract subkey */
    sixty4_sub_inplace(block, subkeys[s]._0[0], subkeys[s]._0[1]);
    sixty4_sub_inplace(block + 2, subkeys[s]._1[0], subkeys[s]._1[1]);
    sixty4_sub_inplace(block + 4, subkeys[s]._2[0], subkeys[s]._2[1]);
    sixty4_sub_inplace(block + 6, subkeys[s]._3[0], subkeys[s]._3[1]);
    sixty4_sub_inplace(block + 8, subkeys[s]._4[0], subkeys[s]._4[1]);
    sixty4_sub_inplace(block + 10, subkeys[s]._5[0], subkeys[s]._5[1]);
    sixty4_sub_inplace(block + 12, subkeys[s]._6[0], subkeys[s]._6[1]);
    sixty4_sub_inplace(block + 14, subkeys[s]._7[0], subkeys[s]._7[1]);
  }
  
}

#if defined(PPENC_64BIT)
STATIC void
threefish_decrypt_block_64bit(const struct ThreeFishBuffer64 *const buf3f,
                              uint64_t *const block,
                              uint64_t *const block_alt)
{
  uint32_t d, s;
  const struct ThreeFishSubKeys64 *subkeys;

  subkeys = buf3f->subkeys;

  /* subtract the final key */
  block[0] -= subkeys[18]._0;
  block[1] -= subkeys[18]._1;
  block[2] -= subkeys[18]._2;
  block[3] -= subkeys[18]._3;
  block[4] -= subkeys[18]._4;
  block[5] -= subkeys[18]._5;
  block[6] -= subkeys[18]._6;
  block[7] -= subkeys[18]._7;

  for (d = 72; d > 0; d -= 8) {
    s = (d - 8) / 4;

    /* round 4 */
    block_alt[0] = block[6];
    block_alt[1] = block[1];
    block_alt[2] = block[0];
    block_alt[3] = block[7];
    block_alt[4] = block[2];
    block_alt[5] = block[5];
    block_alt[6] = block[4];
    block_alt[7] = block[3];

    block_alt[1] ^= block_alt[0];
    block_alt[1] = ROT_LEFT64(block_alt[1], (64 - 8));
    block_alt[3] ^= block_alt[2];
    block_alt[3] = ROT_LEFT64(block_alt[3], (64 - 35));
    block_alt[5] ^= block_alt[4];
    block_alt[5] = ROT_LEFT64(block_alt[5], (64 - 56));
    block_alt[7] ^= block_alt[6];
    block_alt[7] = ROT_LEFT64(block_alt[7], (64 - 22));
    block_alt[0] -= block_alt[1];
    block_alt[2] -= block_alt[3];
    block_alt[4] -= block_alt[5];
    block_alt[6] -= block_alt[7];

    /* round 3 */
    block[0] = block_alt[6];
    block[1] = block_alt[1];
    block[2] = block_alt[0];
    block[3] = block_alt[7];
    block[4] = block_alt[2];
    block[5] = block_alt[5];
    block[6] = block_alt[4];
    block[7] = block_alt[3];

    block[1] ^= block[0];
    block[1] = ROT_LEFT64(block[1], (64 - 25));
    block[3] ^= block[2];
    block[3] = ROT_LEFT64(block[3], (64 - 29));
    block[5] ^= block[4];
    block[5] = ROT_LEFT64(block[5], (64 - 39));
    block[7] ^= block[6];
    block[7] = ROT_LEFT64(block[7], (64 - 43));
    block[0] -= block[1];
    block[2] -= block[3];
    block[4] -= block[5];
    block[6] -= block[7];

    /* round 2 */
    block_alt[0] = block[6];
    block_alt[1] = block[1];
    block_alt[2] = block[0];
    block_alt[3] = block[7];
    block_alt[4] = block[2];
    block_alt[5] = block[5];
    block_alt[6] = block[4];
    block_alt[7] = block[3];

    block_alt[1] ^= block_alt[0];
    block_alt[1] = ROT_LEFT64(block_alt[1], (64 - 13));
    block_alt[3] ^= block_alt[2];
    block_alt[3] = ROT_LEFT64(block_alt[3], (64 - 50));
    block_alt[5] ^= block_alt[4];
    block_alt[5] = ROT_LEFT64(block_alt[5], (64 - 10));
    block_alt[7] ^= block_alt[6];
    block_alt[7] = ROT_LEFT64(block_alt[7], (64 - 17));
    block_alt[0] -= block_alt[1];
    block_alt[2] -= block_alt[3];
    block_alt[4] -= block_alt[5];
    block_alt[6] -= block_alt[7];

    /* round 1 */
    block[0] = block_alt[6];
    block[1] = block_alt[1];
    block[2] = block_alt[0];
    block[3] = block_alt[7];
    block[4] = block_alt[2];
    block[5] = block_alt[5];
    block[6] = block_alt[4];
    block[7] = block_alt[3];

    block[1] ^= block[0];
    block[1] = ROT_LEFT64(block[1], (64 - 39));
    block[3] ^= block[2];
    block[3] = ROT_LEFT64(block[3], (64 - 30));
    block[5] ^= block[4];
    block[5] = ROT_LEFT64(block[5], (64 - 34));
    block[7] ^= block[6];
    block[7] = ROT_LEFT64(block[7], (64 - 24));
    block[0] -= block[1];
    block[2] -= block[3];
    block[4] -= block[5];
    block[6] -= block[7];

    /* subtract subkey */
    block[0] -= subkeys[s+1]._0;
    block[1] -= subkeys[s+1]._1;
    block[2] -= subkeys[s+1]._2;
    block[3] -= subkeys[s+1]._3;
    block[4] -= subkeys[s+1]._4;
    block[5] -= subkeys[s+1]._5;
    block[6] -= subkeys[s+1]._6;
    block[7] -= subkeys[s+1]._7;

    /* round 4 */
    block_alt[0] = block[6];
    block_alt[1] = block[1];
    block_alt[2] = block[0];
    block_alt[3] = block[7];
    block_alt[4] = block[2];
    block_alt[5] = block[5];
    block_alt[6] = block[4];
    block_alt[7] = block[3];

    block_alt[1] ^= block_alt[0];
    block_alt[1] = ROT_LEFT64(block_alt[1], (64 - 44));
    block_alt[3] ^= block_alt[2];
    block_alt[3] = ROT_LEFT64(block_alt[3], (64 - 9));
    block_alt[5] ^= block_alt[4];
    block_alt[5] = ROT_LEFT64(block_alt[5], (64 - 54));
    block_alt[7] ^= block_alt[6];
    block_alt[7] = ROT_LEFT64(block_alt[7], (64 - 56));
    block_alt[0] -= block_alt[1];
    block_alt[2] -= block_alt[3];
    block_alt[4] -= block_alt[5];
    block_alt[6] -= block_alt[7];

    /* round 3 */
    block[0] = block_alt[6];
    block[1] = block_alt[1];
    block[2] = block_alt[0];
    block[3] = block_alt[7];
    block[4] = block_alt[2];
    block[5] = block_alt[5];
    block[6] = block_alt[4];
    block[7] = block_alt[3];

    block[1] ^= block[0];
    block[1] = ROT_LEFT64(block[1], (64 - 17));
    block[3] ^= block[2];
    block[3] = ROT_LEFT64(block[3], (64 - 49));
    block[5] ^= block[4];
    block[5] = ROT_LEFT64(block[5], (64 - 36));
    block[7] ^= block[6];
    block[7] = ROT_LEFT64(block[7], (64 - 39));
    block[0] -= block[1];
    block[2] -= block[3];
    block[4] -= block[5];
    block[6] -= block[7];

    /* round 2 */
    block_alt[0] = block[6];
    block_alt[1] = block[1];
    block_alt[2] = block[0];
    block_alt[3] = block[7];
    block_alt[4] = block[2];
    block_alt[5] = block[5];
    block_alt[6] = block[4];
    block_alt[7] = block[3];

    block_alt[1] ^= block_alt[0];
    block_alt[1] = ROT_LEFT64(block_alt[1], (64 - 33));
    block_alt[3] ^= block_alt[2];
    block_alt[3] = ROT_LEFT64(block_alt[3], (64 - 27));
    block_alt[5] ^= block_alt[4];
    block_alt[5] = ROT_LEFT64(block_alt[5], (64 - 14));
    block_alt[7] ^= block_alt[6];
    block_alt[7] = ROT_LEFT64(block_alt[7], (64 - 42));
    block_alt[0] -= block_alt[1];
    block_alt[2] -= block_alt[3];
    block_alt[4] -= block_alt[5];
    block_alt[6] -= block_alt[7];

    /* round 1 */
    block[0] = block_alt[6];
    block[1] = block_alt[1];
    block[2] = block_alt[0];
    block[3] = block_alt[7];
    block[4] = block_alt[2];
    block[5] = block_alt[5];
    block[6] = block_alt[4];
    block[7] = block_alt[3];

    block[1] ^= block[0];
    block[1] = ROT_LEFT64(block[1], (64 - 46));
    block[3] ^= block[2];
    block[3] = ROT_LEFT64(block[3], (64 - 36));
    block[5] ^= block[4];
    block[5] = ROT_LEFT64(block[5], (64 - 19));
    block[7] ^= block[6];
    block[7] = ROT_LEFT64(block[7], (64 - 37));
    block[0] -= block[1];
    block[2] -= block[3];
    block[4] -= block[5];
    block[6] -= block[7];

    /* subtract subkey */
    block[0] -= subkeys[s]._0;
    block[1] -= subkeys[s]._1;
    block[2] -= subkeys[s]._2;
    block[3] -= subkeys[s]._3;
    block[4] -= subkeys[s]._4;
    block[5] -= subkeys[s]._5;
    block[6] -= subkeys[s]._6;
    block[7] -= subkeys[s]._7;
  }
}

#endif
