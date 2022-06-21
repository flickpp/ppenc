#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../ppenc.h"

#include "msgs.h"

const uint8_t SENDER_RNG_KEY[32] = {\
  114, 18, 249, 44, 237, 127, 113, 14, 198, 82, 79, 51, 96, 149, 117, 107, 151, 196, 229, 113, 69, 56, 237, 181, 45, 53, 173, 127, 248, 131, 254, 130
};

const uint8_t HEADER_SALT[16] = {\
  69, 59, 193, 12, 6, 158, 6, 102, 159, 66, 169, 195, 243, 57, 49, 167
};

const uint8_t BODY_SALT[16] = {\
  225, 47, 207, 136, 141, 36, 224, 15, 163, 142, 89, 53, 51, 97, 249, 149
};

const char TOKEN[100] = {\
  "00.70f78f37bc36973269cd3b044ff15ec46f11c618ea6909452526c46d9173a059.e4f102910b3fea0cacba1923aad556ec"
};

PPEncSenderRng*
seed_rng(PPEncSenderRng* rng)
{
  FILE *urandom;
  uint8_t nonce[8];

  if ((urandom = fopen("/dev/urandom", "rb")) == NULL) {
    fprintf(stderr, "couldn't open /dev/urandom");
    return NULL;
  }

  if (fread(nonce, 8, 1, urandom) < 0) {
    fprintf(stderr, "couldn't read 8 bytes from /dev/urandom");
    return NULL;
  }

  fclose(urandom);

  ppenc_sender_rng_init(rng, SENDER_RNG_KEY, nonce);
  return rng;
}

int
main()
{
  struct PPEncSender sender;
  PPEncSenderRng RNG, *rng;
  uint8_t header_rng_nonce[12], header_state_init[32], body_state0[32], buf1400[1400], response_mac[32];
  struct sockaddr_in addr;
  int sock;
  ssize_t bytes_sent, bytes_recv;
  uint8_t msg_num;
  size_t body_len;
  uint8_t *msg_buf;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "couldn't connect to socket\n");
    exit(1);
  }

  addr.sin_port = htons(8080);
  addr.sin_addr.s_addr = 0;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_family = AF_INET;

  if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    fprintf(stderr, "couldn't connect to socket\n");
    exit(1);
  }

  /* write 100 byte token to network */
  printf("writing token to network\n");
  bytes_sent = 0;
  while (bytes_sent < 100) {
    ssize_t n;
    n = send(sock, ((uint8_t*) TOKEN) + bytes_sent, 100 - bytes_sent, 0);
    if (n < 0) {
      fprintf(stderr, "couldn't send token to server\n");
      exit(2);
    }
    bytes_sent += n;
  }

  rng = seed_rng(&RNG);
  if (rng == NULL) {
    exit(1);
  }

  ppenc_sender_rng_nbytes(rng, header_rng_nonce, 12);

  /* write 12 byte header nonce to network */
  printf("writing header nonce to network\n");
  bytes_sent = 0;
  while (bytes_sent < 12) {
    ssize_t n;
    n = send(sock, header_rng_nonce, 12 - bytes_sent, 0);
    if (n < 0) {
      fprintf(stderr, "couldn't send nonce to server\n");
      exit(2);
    }
    bytes_sent += n;
  }

  /* read 32 byte header_state_init */
  printf("reading header_state_init from network\n");
  bytes_recv = 0;
  while(bytes_recv < 32) {
    ssize_t n;
    n = recv(sock, header_state_init + bytes_recv, 32 - bytes_recv, 0);
    if (n < 0) {
      fprintf(stderr, "couldn't read init state from socket\n");
      exit(2);
    }
    bytes_recv += n;
  }
  

  /* read 32 byte body_state0 */
 printf("reading body_state0 from network\n");
 bytes_recv = 0;
  while(bytes_recv < 32) {
    ssize_t n;
    n = recv(sock, body_state0 + bytes_recv, 32 - bytes_recv, 0);
    if (n < 0) {
      fprintf(stderr, "couldn't read init state from socket\n");
      exit(2);
    }
    bytes_recv += n;
  }

  /* init sender */
  ppenc_sender_init(&sender,
                    rng,
                    HEADER_SALT,
                    header_state_init,
                    header_rng_nonce,
                    BODY_SALT,
                    body_state0,
                    buf1400);

  printf("session established\n");

  msg_num = 0;
  bytes_recv = 0;
  while(1) {
    size_t i;
    uint32_t body_padded_len;
    ssize_t n;

    body_len = MSG_LENS[msg_num];
    msg_buf = (uint8_t*) malloc(body_len + 71 + 32);
    for (i = 0; i < body_len; i++)
      msg_buf[i + 32] = MSGS[msg_num][i];

    /* encrypt the message */
    printf("encrypting msg [%i]\n", msg_num);
    body_padded_len = ppenc_sender_new_msg(&sender,
                                           msg_buf,
                                           msg_buf + 32,
                                           body_len,
                                           response_mac,
                                           buf1400);

    /* send the message */
    printf("sending message [%i]\n", msg_num);
    bytes_sent = 0;
    while (bytes_sent < (body_padded_len + 32)) {
      n = send(sock, msg_buf, (body_padded_len + 32) - bytes_sent, 0);
      if (n < 0) {
	perror("couldn't send message to server");
	exit(2);
      }
      bytes_sent += n;
    }
    free(msg_buf);

    /* we expect a response_mac */
    printf("expecting response_mac = ");
    for(i = 0; i < 32; i++)
      printf("%.2x", response_mac[i]);
    printf("\n");

    /* while the message is on the wire, advance the keys */
    /* ppenc_sender_new_body_key(&sender, buf1400); */

    /* check if we have received any responses */
    if ((n = recv(sock, response_mac + bytes_recv, 32 - bytes_recv, 0)) < 0) {
      perror("couldn't read response_mac from server");
      exit(2);
    }
    bytes_recv += n;

    /* do we have a complete response? */
    if (bytes_recv == 32) {
      printf("received response_mac = ");
      for (i = 0; i < 32; i++)
	printf("%.2x", response_mac[i]);
      printf("\n");
      bytes_recv = 0;
    }

    /* sleep for 2 seconds */
    sleep(2);

    msg_num = (msg_num + 1) % 2;
  }
  return 0;
}
