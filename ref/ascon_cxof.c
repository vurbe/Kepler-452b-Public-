#include "ascon_cxof.h"

#include <stddef.h>
#include <stdint.h>

#define ASCON_CXOF_VARIANT 4u
#define ASCON_HASH_VARIANT 2u
#define ASCON_PA_ROUNDS 12u
#define ASCON_HASH_PB_ROUNDS 12u
#define ASCON_HASH_RATE 8u
#define ASCON_HASH_SIZE 32u
#define ASCON_CXOF_IV \
  (((uint64_t)(ASCON_CXOF_VARIANT) << 0) | \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) | \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))
#define ASCON_HASH_IV \
  (((uint64_t)(ASCON_HASH_VARIANT) << 0) | \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) | \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_SIZE * 8u) << 24) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

static inline uint64_t ror64(uint64_t x, unsigned int n) {
  return (x >> n) | (x << ((64u - n) & 63u));
}

static inline uint64_t load_bytes(const uint8_t *bytes, size_t n) {
  uint64_t x = 0;
  for (size_t i = 0; i < n; i++) {
    x |= ((uint64_t)bytes[i]) << (8u * i);
  }
  return x;
}

static inline void store_bytes(uint8_t *bytes, uint64_t x, size_t n) {
  for (size_t i = 0; i < n; i++) {
    bytes[i] = (uint8_t)(x >> (8u * i));
  }
}

static inline uint64_t pad(size_t i) {
  return ((uint64_t)0x01u) << (8u * i);
}

static inline void ascon_round(ascon_state_t *s, uint8_t c) {
  ascon_state_t t;

  s->x[2] ^= c;

  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];

  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);

  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];

  s->x[0] = t.x[0] ^ ror64(t.x[0], 19) ^ ror64(t.x[0], 28);
  s->x[1] = t.x[1] ^ ror64(t.x[1], 61) ^ ror64(t.x[1], 39);
  s->x[2] = t.x[2] ^ ror64(t.x[2], 1)  ^ ror64(t.x[2], 6);
  s->x[3] = t.x[3] ^ ror64(t.x[3], 10) ^ ror64(t.x[3], 17);
  s->x[4] = t.x[4] ^ ror64(t.x[4], 7)  ^ ror64(t.x[4], 41);
}

static void p12(ascon_state_t *s) {
  ascon_round(s, 0xf0);
  ascon_round(s, 0xe1);
  ascon_round(s, 0xd2);
  ascon_round(s, 0xc3);
  ascon_round(s, 0xb4);
  ascon_round(s, 0xa5);
  ascon_round(s, 0x96);
  ascon_round(s, 0x87);
  ascon_round(s, 0x78);
  ascon_round(s, 0x69);
  ascon_round(s, 0x5a);
  ascon_round(s, 0x4b);
}

static void absorb_stream(ascon_state_t *s, const uint8_t *in, size_t inlen) {
  while (inlen >= ASCON_HASH_RATE) {
    s->x[0] ^= load_bytes(in, ASCON_HASH_RATE);
    p12(s);
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }

  s->x[0] ^= load_bytes(in, inlen);
  s->x[0] ^= pad(inlen);
  p12(s);
}

void ascon_cxof128_init(ascon_state_t *s,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *custom, size_t customlen) {
  s->x[0] = ASCON_CXOF_IV;
  s->x[1] = 0;
  s->x[2] = 0;
  s->x[3] = 0;
  s->x[4] = 0;
  p12(s);

  s->x[0] ^= (uint64_t)customlen * 8u;
  p12(s);

  absorb_stream(s, custom, customlen);
  absorb_stream(s, msg, msglen);
}

void ascon_cxof128_squeeze(uint8_t *out, size_t outlen, ascon_state_t *s) {
  while (outlen >= ASCON_CXOF128_RATE) {
    store_bytes(out, s->x[0], ASCON_CXOF128_RATE);
    out += ASCON_CXOF128_RATE;
    outlen -= ASCON_CXOF128_RATE;
    p12(s);
  }

  if (outlen > 0) {
    store_bytes(out, s->x[0], outlen);
  }
}

int crypto_cxof(unsigned char *out, unsigned long long outlen,
                const unsigned char *in, unsigned long long inlen,
                const unsigned char *cs, unsigned long long cslen) {
  ascon_state_t s;
  ascon_cxof128_init(&s, in, (size_t)inlen, cs, (size_t)cslen);
  ascon_cxof128_squeeze(out, (size_t)outlen, &s);
  return 0;
}

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen) {
  ascon_state_t s;

  s.x[0] = ASCON_HASH_IV;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  p12(&s);
  absorb_stream(&s, in, (size_t)inlen);
  ascon_cxof128_squeeze(out, ASCON_HASH_SIZE, &s);
  return 0;
}
