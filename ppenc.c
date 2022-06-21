#include "ppenc.h"
#include "hash.h"
#include "blockcipher.h"
#include "cprng.h"

static void
session_init(struct PPEncSession *const session,
             const uint8_t *const header_salt,
             const uint8_t *const header_state_init,
             const uint8_t *const header_rng_nonce,
             const uint8_t *const body_salt,
             const uint8_t *const body_state0,
             uint8_t *const buf1400);

static void
session_body_key_next(struct PPEncSession *const session,
                      uint8_t *const buf320);

static void session_compute_response_mac(struct PPEncSession *const session,
                                         uint8_t *const response_mac,
                                         uint8_t *const inner_salt,
                                         uint8_t *const body,
                                         const uint32_t body_len,
                                         uint8_t *const buf256,
                                         uint8_t *const buf64);
					 

static INLINE void header_scramble_and_encrypt(struct PPEncSession *const session, uint8_t *const header_buf);
STATIC INLINE void header_scramble(uint8_t *const header_buf);
STATIC INLINE void header_scramble_inverse(uint8_t *const header_buf);
static void compute_body_checksum(uint8_t *const body_checksum,
                                  const uint8_t *const body,
                                  const uint32_t body_padded_len);
static void write_be32(uint8_t *const dst, const uint32_t val);
static void write_be24(uint8_t *const dst, const uint32_t val);
static void write_be16(uint8_t *const dst, const uint16_t val);
static uint32_t read_be32(uint8_t *const src);
static uint32_t read_be24(uint8_t *const src);
static uint16_t read_be16(uint8_t *const src);

void
ppenc_sender_init(struct PPEncSender *const sender,
                  PPEncSenderRng *const sender_rng,
                  const uint8_t *const header_salt,
                  const uint8_t *const header_state_init,
                  const uint8_t *const header_rng_nonce,
                  const uint8_t *const body_salt,
                  const uint8_t *const body_state0,
                  uint8_t *const buf1400)
{
  sender->sender_rng = (struct PPEncChaCha8*) sender_rng;
  session_init(&(sender->session),
               header_salt,
               header_state_init,
               header_rng_nonce,
               body_salt,
               body_state0,
               buf1400);
}

uint32_t
ppenc_sizeof_sender()
{
  return sizeof(struct PPEncSender);
}

void
ppenc_sender_new_body_key(struct PPEncSender *const sender, uint8_t *const buf1400)
{
  session_body_key_next(&(sender->session), buf1400);
}

uint32_t
ppenc_sender_new_msg(struct PPEncSender *const sender,
                     uint8_t *const header_buf,
                     uint8_t *const body,
                     const uint32_t body_len,
                     uint8_t *const response_mac,
                     uint8_t *const buf1400)
{
  uint32_t body_len_padded;
  uint8_t *tweek_seed, *body_checksum, *inner_salt;

  body_len_padded = ppenc_body_padded_len(body_len);

  /* populate the header_buf (in rows of 8 bytes) *
   * version(1) seq_numn(3) body_length(4)       *
   * body_key_num(2) inner_salt(6)               *
   * tweek_seed(8)                               *
   * body_checksum(8)                            */
  header_buf[0] = 0;
  write_be24(header_buf + 1, sender->session.seq_num);
  write_be32(header_buf + 4, body_len);
  write_be16(header_buf + 8, sender->session.body_key_num);
  inner_salt = header_buf + 10;
  tweek_seed = header_buf + 16;
  body_checksum = header_buf + 24;
 
  /* generate inner salt */
  ppenc_chacha8_nbytes(sender->sender_rng, inner_salt, 6);

  /* compute the response mac (sha256(response_mac_salt + cubehash(inner_salt XOR body))) */
  session_compute_response_mac(&(sender->session),
                               response_mac,
                               inner_salt,
                               body,
                               body_len,
                               buf1400,
                               buf1400 + 256);

  /* append our padding */
  ppenc_chacha8_nbytes(sender->sender_rng,
                       body + body_len,
                       body_len_padded - body_len);

  /* generate + write tweek_seed into header */
  ppenc_chacha8_nbytes(sender->sender_rng, tweek_seed, 8);

  /* compute + write body_checksum into header */
  compute_body_checksum(body_checksum, body, body_len_padded);

#if defined(PPENC_64BIT)
  ppenc_threefish512_encrypt_64bit(sender->session.body_key,
                                   tweek_seed,
                                   body,
                                   body_len_padded / 64,
                                   (struct ThreeFishBuffer64*) (buf1400 + 64),
                                   buf1400);
#else
  ppenc_threefish512_encrypt(sender->session.body_key,
                             tweek_seed,
                             body,
                             body_len_padded / 64,
                             (struct ThreeFishBuffer*) (buf1400 + 64),
                             buf1400);
#endif

  /* scramble and encrypt the header */
  header_scramble_and_encrypt(&(sender->session), header_buf);

  sender->session.seq_num += 1;

  return body_len_padded;
}

void
ppenc_sender_rng_init(PPEncSenderRng *const rng,
                      const uint8_t *const key,
                      const uint8_t *const nonce)
{
  ppenc_chacha8_init((struct PPEncChaCha8*) rng, key, nonce);
}

uint32_t
ppenc_sizeof_sender_rng()
{
  return sizeof(PPEncSenderRng);
}

void
ppenc_sender_rng_nbytes(PPEncSenderRng *const sender_rng,
                        uint8_t *const buf,
                        const uint16_t num_bytes)
{
  ppenc_chacha8_nbytes((struct PPEncChaCha8*) sender_rng, buf, num_bytes);
}

uint32_t
ppenc_body_padded_len(uint32_t body_len)
{
  uint32_t body_len_padded;

  body_len_padded = 0;
  body_len += 8;
  while (body_len_padded < body_len)
    body_len_padded += 64;

  return body_len_padded;
}

void
ppenc_receiver_init(struct PPEncReceiver *const receiver,
                    const uint8_t *const header_salt,
                    const uint8_t *const header_state_init,
                    const uint8_t *const header_rng_nonce,
                    const uint8_t *const body_salt,
                    const uint8_t *const body_state0,
                    uint8_t *const buf1400)
{
  session_init(&(receiver->session),
               header_salt,
               header_state_init,
               header_rng_nonce,
               body_salt,
               body_state0,
               buf1400);
}

uint32_t
ppenc_sizeof_receiver()
{
  return sizeof(struct PPEncReceiver);
}

ppenc_err_t
ppenc_receiver_read_header(struct PPEncReceiver *const receiver,
                           struct PPEncHeader *const header,
                           uint8_t *const raw_header)
{
  /* decrypt the header */
  ppenc_chacha20_xor_header(&(receiver->session.header_key_rng), raw_header);
  header_scramble_inverse(raw_header);

  /* check the version is correct */
  if (raw_header[0] != 0)
    return PPENC_ERR_BAD_VERSION;

  header->seq_num = read_be24(raw_header + 1);
  if (header->seq_num != receiver->session.seq_num)
    return PPENC_ERR_BAD_SEQ_NUM;

  header->body_len = read_be32(raw_header + 4);
  header->body_key_num = read_be16(raw_header + 8);
  header->inner_salt = raw_header + 10;
  header->tweek_seed = raw_header + 16;
  header->body_checksum = raw_header + 24;

  return PPENC_OK;
}

ppenc_err_t
ppenc_receiver_read_body(struct PPEncReceiver *const receiver,
                         struct PPEncHeader *const header,
                         uint8_t *const body,
                         uint8_t *const response_mac,
                         uint8_t *const buf1400)
{
  uint32_t body_len_padded;
  uint16_t i;
  uint8_t body_checksum[8];

  body_len_padded = ppenc_body_padded_len(header->body_len);

  /* body key num may not be in the past */
  if (header->body_key_num < receiver->session.body_key_num)
    return PPENC_ERR_BAD_BODY_KEY_NUM;

  /* advance to appropriate body key */
  while(receiver->session.body_key_num < header->body_key_num)
    session_body_key_next(&(receiver->session), buf1400);

  /* decrypt the body */
#if defined(PPENC_64BIT)
  ppenc_threefish512_decrypt_64bit(receiver->session.body_key,
                                   header->tweek_seed,
                                   body,
                                   body_len_padded / 64,
                                   (struct ThreeFishBuffer64*) (buf1400 + 64),
                                   buf1400);
#else
  ppenc_threefish512_decrypt(receiver->session.body_key,
                             header->tweek_seed,
                             body,
                             body_len_padded / 64,
                             (struct ThreeFishBuffer*) (buf1400 + 64),
                             buf1400);
#endif

  /* check the body checksum is correct */
  compute_body_checksum(body_checksum, body, body_len_padded);
  for (i = 0; i < 8; i++)
    if (body_checksum[i] != header->body_checksum[i])
      return PPENC_ERR_BAD_BODY_CHECKSUM;

  /* compute the response mac */
  session_compute_response_mac(&(receiver->session),
                               response_mac,
                               header->inner_salt,
                               body,
                               header->body_len,
                               buf1400,
                               buf1400 + 256);

  /* expect next seq_num next time */
  receiver->session.seq_num += 1;
  return PPENC_OK;
}


static void
session_init(struct PPEncSession *const session,
             const uint8_t *const header_salt,
             const uint8_t *const header_state_init,
             const uint8_t *const header_rng_nonce,
             const uint8_t *const body_salt,
             const uint8_t *const body_state0,
             uint8_t *const buf1400)
{
  uint16_t i;

  /* compute sha256(header_salt + header_state_init) */
  for (i = 0; i < 16; i++)
    buf1400[i + 32] = header_salt[i];
  for (; i < 48; i++)
    buf1400[i + 32] = header_state_init[i - 16];
  ppenc_sha256_len48(buf1400, buf1400 + 32, (uint32_t*) (buf1400 + 96));

  /* init header_key_rng */
  ppenc_chacha20_init(&(session->header_key_rng), buf1400, header_rng_nonce);

  /* body key */
  for(i = 0; i < 32; i++)
    session->body_key_state[i] = body_state0[i];
  for(i = 0; i < 16; i++)
    session->body_key_salt[i] = body_salt[i];

  session->body_key_num = 0;
  session_body_key_next(session, buf1400);
  /* body_key_num is now 1 */

  session->seq_num = 1;
}

static void
session_body_key_next(struct PPEncSession *const session,
                      uint8_t *const buf320)
{
  uint16_t i;
  uint8_t last_state_byte;

  /* copy salt + state into buffer */
  for (i = 0; i < 16; i++)
    buf320[i] = session->body_key_salt[i];
  for(; i < 48; i++)
    buf320[i] = session->body_key_state[i - 16];

  /* body_key_state[n] = sha256(salt + state[n-1] */
  ppenc_sha256_len48(session->body_key_state, buf320, (uint32_t*) (buf320 + 64));
  last_state_byte = session->body_key_state[31];


  /* compute cubehash(body_key_state[n] */
  ppenc_cubehash(buf320, session->body_key_state, 31);
  session->body_key_state[31] = last_state_byte;

  /* the first 64 bytes is the key, the next 16 bytes is the response mac salt */
  for(i = 0; i < 64; i++)
    session->body_key[i] = buf320[i];
  for(i = 0; i < 16; i++)
    session->response_mac_salt[i] = buf320[i + 64];

  session->body_key_num += 1;
}

static void
header_scramble_and_encrypt(struct PPEncSession *const session, uint8_t *const header_buf)
{
  header_scramble(header_buf);
  ppenc_chacha20_xor_header(&(session->header_key_rng), header_buf);
}

static void
compute_body_checksum(uint8_t *const body_checksum,
                      const uint8_t *const body,
                      const uint32_t body_padded_len)
{
  uint32_t i;
  for (i = 0; i < body_padded_len && i < 8; i++)
    body_checksum[i] = body[i];

  for(; i < body_padded_len; i++)
    body_checksum[i % 8] ^= body[i];
}

static void
session_compute_response_mac(struct PPEncSession *const session,
                             uint8_t *const response_mac,
                             uint8_t *const inner_salt,
                             uint8_t *const body,
                             const uint32_t body_len,
                             uint8_t *const buf256,
                             uint8_t *const buf64)
{
  uint16_t i;

  /* XOR first 6 bytes of body with inner_salt *
   * the purpose of doing this is to generate a *
   * unique value if body and response_mac are the same */
  for (i = 0; i < 6 && i < body_len; i++)
    body[i] ^= inner_salt[i];

  ppenc_cubehash(buf256, body, body_len);

  for(i = 0; i < 16; i++)
    buf64[i] = session->response_mac_salt[i];
  for (; i < 48; i++)
    buf64[i] = buf256[i];

  ppenc_sha256_len48(response_mac, buf64, (uint32_t*) buf256);

  /* undo the XOR body with inner salt */
  for (i = 0; i < 6 && i < body_len; i++)
    body[i] ^= inner_salt[i];
}

static void
write_be32(uint8_t *const dst, const uint32_t val)
{
  dst[0] = val >> 24;
  dst[1] = val >> 16;
  dst[2] = val >> 8;
  dst[3] = val;
}

static void
write_be24(uint8_t *const dst, const uint32_t val)
{
  dst[0] = val >> 16;
  dst[1] = val >> 8;
  dst[2] = val;
}

static void
write_be16(uint8_t *const dst, const uint16_t val)
{
  dst[0] = val >> 8;
  dst[1] = val;
}

STATIC INLINE void
header_scramble(uint8_t *const header)
{
  uint32_t *header32, scramble_const;
  uint16_t* header16;
  uint8_t i;

  header32 = (uint32_t*) header;
  header16 = (uint16_t*) header;
  scramble_const = 0;

  for (i = 0; i < 8; i++)
    scramble_const ^= header32[i];

  for (i = 0; i < 8; i++) {
    uint8_t odd, even, j;

    even = (scramble_const >> (i * 4)) & 0x0f;
    if ((even & 1) != 0) {
      odd = even;
      even = (~odd) & 0x0f;
    } else {
      odd = (~even) & 0x0f;
    }

    /* swap the 16 bit values */
    j = i * 2;
    if (j == even)
      even = (even + 8) % 16;
    header16[j] ^= header16[even]; header16[even] ^= header16[j]; header16[j] ^= header16[even];
    j = j + 1;
    if (j == odd)
      odd = (odd + 8) % 16;
    header16[j] ^= header16[odd]; header16[odd] ^= header16[j]; header16[j] ^= header16[odd];
  }
}

STATIC INLINE void
header_scramble_inverse(uint8_t *const header)
{
  uint32_t *header32, scramble_const;
  uint16_t* header16;
  uint8_t i;

  header32 = (uint32_t*) header;
  header16 = (uint16_t*) header;
  scramble_const = 0;

  for (i = 0; i < 8; i++)
    scramble_const ^= header32[i];

  for (i = 8; i > 0; i--) {
    uint8_t odd, even, j;

    even = (scramble_const >> ((i - 1) * 4)) & 0x0f;
    if ((even & 1) != 0) {
      odd = even;
      even = (~odd) & 0x0f;
    } else {
      odd = (~even) & 0x0f;
    }

    /* swap the 16 bit values */
    j = (i - 1) * 2;
    if (j == even)
      even = (even + 8) % 16;
    header16[j] ^= header16[even]; header16[even] ^= header16[j]; header16[j] ^= header16[even];
    j = j + 1;
    if (j == odd)
      odd = (odd + 8) % 16;
    header16[j] ^= header16[odd]; header16[odd] ^= header16[j]; header16[j] ^= header16[odd];
  }
}

static uint32_t
read_be32(uint8_t *const src)
{
  uint32_t val;
  val = src[0]; val <<= 8;
  val |= src[1]; val <<= 8;
  val |= src[2]; val <<= 8;
  return val | src[3];
}

static uint32_t
read_be24(uint8_t *const src)
{
  uint32_t val;
  val = src[0]; val <<= 8;
  val |= src[1]; val <<= 8;
  return val | src[2];
}

static uint16_t
read_be16(uint8_t *const src)
{
  uint16_t val;
  val = src[0]; val <<= 8;
  return val | src[1];
}
