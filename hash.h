#ifndef _PPENC_HASH_H
#define _PPENC_HASH_H

#include <stdint.h>

void ppenc_sha256_len48(uint8_t *const hash_value,
                        uint8_t *const msg,
                        uint32_t *const message_schedule_buf);

void ppenc_cubehash(uint8_t *const hash_value,
                    uint8_t* const msg,
		    const uint32_t msg_len);

#endif
