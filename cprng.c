#include "cprng.h"

#define ROT_LEFT32(x, z) ((x << z) | (x >> (32 - z)))
#define QUARTERROUND(a, b, c, d)       \
  a += b;  d = ROT_LEFT32((d ^ a), 16);	      \
  c += d;  b = ROT_LEFT32((b ^ c), 12);	      \
  a += b;  d = ROT_LEFT32((d ^ a),  8);	      \
  c += d;  b = ROT_LEFT32((b ^ c),  7)

static const uint32_t CHACHA_CONST[4] = {\
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static void chacha8_compute(struct PPEncChaCha8 *const chacha8);
static void chacha20_compute(struct PPEncChaCha20 *const chacha20);

void
ppenc_chacha8_init(struct PPEncChaCha8 *const chacha8,
                   const uint8_t *const key,
                   const uint8_t *const nonce)
{
  uint16_t i;

  for (i = 0; i < 8; i++)
    chacha8->key[i] = ((uint32_t*) key)[i];
  chacha8->nonce[0] = ((uint32_t*) nonce)[0];
  chacha8->nonce[1] = ((uint32_t*) nonce)[1];

  chacha8->counter = 0;
  /* set pos to 64 to force computation on first call */
  chacha8->pos = 64;
}

void
ppenc_chacha20_init(struct PPEncChaCha20 *const chacha20,
                    const uint8_t *const key,
                    const uint8_t *const nonce)
{
  uint16_t i;

  for (i = 0; i < 8; i++)
    chacha20->key[i] = ((uint32_t*) key)[i];
  chacha20->nonce[0] = ((uint32_t*) nonce)[0];
  chacha20->nonce[1] = ((uint32_t*) nonce)[1];
  chacha20->nonce[2] = ((uint32_t*) nonce)[2];

  chacha20->counter = 0;
  chacha20->pos = 2;
}

void
ppenc_chacha8_nbytes(struct PPEncChaCha8 *const chacha8,
                     uint8_t *const dst,
                     const uint16_t num_bytes)
{
  uint16_t i;

  for (i = 0; i < num_bytes; i++) {
    if (chacha8->pos == 64) {
      chacha8_compute(chacha8);
      chacha8->pos = 0;
    }

    dst[i] = chacha8->block[chacha8->pos++];
  }
}

void
ppenc_chacha20_xor_header(struct PPEncChaCha20 *const chacha20, uint8_t *const header)
{
  uint16_t i;
  uint8_t* key;

  if (chacha20->pos == 2) {
    chacha20_compute(chacha20);
    chacha20->pos = 0;
  }

  key = chacha20->block + (chacha20->pos * 32);

  for (i = 0; i < 32; i++)
    header[i] ^= key[i];

  chacha20->pos += 1;
}

static void
chacha8_compute(struct PPEncChaCha8 *const chacha8)
{
  uint16_t i;
  uint32_t *buf;

  buf = (uint32_t*) chacha8->block;

  buf[0] = CHACHA_CONST[0];
  buf[1] = CHACHA_CONST[1];
  buf[2] = CHACHA_CONST[2];
  buf[3] = CHACHA_CONST[3];

  for (i = 0; i < 8; i++)
    buf[i + 4] = chacha8->key[i];

  buf[12] = chacha8->counter;
  buf[13] = 0;
  buf[14] = chacha8->nonce[0];
  buf[15] = chacha8->nonce[1];

  for (i = 0; i < 4; i++) {
    QUARTERROUND(buf[0], buf[4], buf[8], buf[12]);
    QUARTERROUND(buf[1], buf[5], buf[9], buf[13]);
    QUARTERROUND(buf[2], buf[6], buf[10], buf[14]);
    QUARTERROUND(buf[3], buf[7], buf[11], buf[15]);

    QUARTERROUND(buf[0], buf[5], buf[10], buf[15]);
    QUARTERROUND(buf[1], buf[6], buf[11], buf[12]);
    QUARTERROUND(buf[2], buf[7], buf[8], buf[13]);
    QUARTERROUND(buf[3], buf[4], buf[9], buf[14]);
  }

  buf[0] += CHACHA_CONST[0];
  buf[1] += CHACHA_CONST[1];
  buf[2] += CHACHA_CONST[2];
  buf[3] += CHACHA_CONST[3];

  for (i = 0; i < 8; i++)
    buf[i + 4] += chacha8->key[i];

  buf[12] += chacha8->counter;
  buf[14] += chacha8->nonce[0];
  buf[15] += chacha8->nonce[1];

  chacha8->counter += 1;
}

static void
chacha20_compute(struct PPEncChaCha20 *const chacha20)
{
  uint16_t i;
  uint32_t *buf;

  buf = (uint32_t*) chacha20->block;

  buf[0] = CHACHA_CONST[0];
  buf[1] = CHACHA_CONST[1];
  buf[2] = CHACHA_CONST[2];
  buf[3] = CHACHA_CONST[3];

  for (i = 0; i < 8; i++)
    buf[i + 4] = chacha20->key[i];

  buf[12] = chacha20->counter;
  buf[13] = chacha20->nonce[0];
  buf[14] = chacha20->nonce[1];
  buf[15] = chacha20->nonce[2];

  for (i = 0; i < 10; i++) {
    QUARTERROUND(buf[0], buf[4], buf[8], buf[12]);
    QUARTERROUND(buf[1], buf[5], buf[9], buf[13]);
    QUARTERROUND(buf[2], buf[6], buf[10], buf[14]);
    QUARTERROUND(buf[3], buf[7], buf[11], buf[15]);

    QUARTERROUND(buf[0], buf[5], buf[10], buf[15]);
    QUARTERROUND(buf[1], buf[6], buf[11], buf[12]);
    QUARTERROUND(buf[2], buf[7], buf[8], buf[13]);
    QUARTERROUND(buf[3], buf[4], buf[9], buf[14]);
  }

  buf[0] += CHACHA_CONST[0];
  buf[1] += CHACHA_CONST[1];
  buf[2] += CHACHA_CONST[2];
  buf[3] += CHACHA_CONST[3];

  for (i = 0; i < 8; i++)
    buf[i + 4] += chacha20->key[i];

  buf[12] += chacha20->counter;
  buf[13] += chacha20->nonce[0];
  buf[14] += chacha20->nonce[1];
  buf[15] += chacha20->nonce[2];

  chacha20->counter += 1;
}
