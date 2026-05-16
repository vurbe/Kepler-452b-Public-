#ifndef ASCON_CXOF_H
#define ASCON_CXOF_H

#include <stddef.h>
#include <stdint.h>

#define ASCON_CXOF128_RATE 8u

typedef struct {
  uint64_t x[5];
} ascon_state_t;

void ascon_cxof128_init(ascon_state_t *s,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *custom, size_t customlen);
void ascon_cxof128_squeeze(uint8_t *out, size_t outlen, ascon_state_t *s);

int crypto_cxof(unsigned char *out, unsigned long long outlen,
                const unsigned char *in, unsigned long long inlen,
                const unsigned char *cs, unsigned long long cslen);
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);

#endif
