#ifndef _PPENC_H
#define _PPENC_H

#include <stdint.h>

#include "cprng.h"

/* errors */
#define ppenc_err_t uint16_t
#define PPENC_OK 0
#define PPENC_ERR_BAD_VERSION 1
#define PPENC_ERR_BAD_SEQ_NUM 2
#define PPENC_ERR_BAD_BODY_CHECKSUM 3
#define PPENC_ERR_BAD_BODY_KEY_NUM 4


struct PPEncSession {
  uint8_t body_key_salt[16];
  uint8_t body_key_state[32];
  uint8_t body_key[64];
  uint16_t body_key_num;
  uint8_t response_mac_salt[16];
  struct PPEncChaCha20 header_key_rng;
  uint32_t seq_num;
};

struct PPEncSender {
  struct PPEncSession session;
  struct PPEncChaCha8 *sender_rng;
};

struct PPEncReceiver {
  struct PPEncSession session;
};

typedef struct PPEncChaCha8 PPEncSenderRng;

struct PPEncHeader {
  uint32_t seq_num;
  uint32_t body_len;
  uint16_t body_key_num;
  uint8_t* inner_salt;
  uint8_t* tweek_seed;
  uint8_t* body_checksum;
};

uint32_t ppenc_sizeof_sender();

void
ppenc_sender_rng_nbytes(PPEncSenderRng *const sender_rng,
                        uint8_t *const buf,
                        const uint16_t num_bytes);

void
ppenc_sender_init(struct PPEncSender *const sender,
                  PPEncSenderRng *const sender_rng,
                  const uint8_t *const header_salt,
                  const uint8_t *const header_state_init,
                  const uint8_t *const header_rng_nonce,
                  const uint8_t *const body_salt,
                  const uint8_t *const body_state0,
                  uint8_t *const buf1400);

void ppenc_sender_rng_init(PPEncSenderRng *const rng,
                           const uint8_t *const key,
                           const uint8_t *const nonce);

uint32_t ppenc_sizeof_sender_rng();

uint32_t ppenc_sender_new_msg(struct PPEncSender *const sender,
                              uint8_t *const header_buf,
                              uint8_t *const body,
                              const uint32_t body_len,
                              uint8_t *const response_mac,
                              uint8_t *const buf1400);

void ppenc_sender_new_body_key(struct PPEncSender *const sender, uint8_t *const buf1400);

uint32_t ppenc_body_padded_len(uint32_t body_len);

void
ppenc_receiver_init(struct PPEncReceiver *const receiver,
                    const uint8_t *const header_salt,
                    const uint8_t *const header_state_init,
                    const uint8_t *const header_rng_nonce,
                    const uint8_t *const body_salt,
                    const uint8_t *const body_state0,
                    uint8_t *const buf1400);

uint32_t ppenc_sizeof_receiver();

ppenc_err_t ppenc_receiver_read_header(struct PPEncReceiver *const receiver,
                                       struct PPEncHeader *const header,
                                       uint8_t *const raw_header);

ppenc_err_t ppenc_receiver_read_body(struct PPEncReceiver *const receiver,
                                     struct PPEncHeader *const header,
                                     uint8_t *const body,
                                     uint8_t *const response_mac,
                                     uint8_t *const buf1400);
#endif
