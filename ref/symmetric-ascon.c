#include "params.h"
#include "symmetric.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static const uint8_t CS_XOF[]   = "ASCON-KYBER-XOF-v1";
static const uint8_t CS_PRF[]   = "ASCON-KYBER-PRF-v1";
static const uint8_t CS_RKPRF[] = "ASCON-KYBER-RKPRF-v1";
static const uint8_t CS_HASHH[] = "ASCON-KYBER-HASH-H-v1";
static const uint8_t CS_HASHG[] = "ASCON-KYBER-HASH-G-v1";

static void cxof(uint8_t *out, size_t outlen,
                 const uint8_t *in, size_t inlen,
                 const uint8_t *custom, size_t customlen) {
  (void)crypto_cxof(out, (unsigned long long)outlen,
                    in, (unsigned long long)inlen,
                    custom, (unsigned long long)customlen);
}

void xof_absorb(xof_state *state,
                const uint8_t seed[KYBER_SYMBYTES],
                uint8_t x, uint8_t y) {
  uint8_t extseed[KYBER_SYMBYTES + 2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;

  ascon_cxof128_init(&state->s,
                     extseed, sizeof(extseed),
                     CS_XOF, sizeof(CS_XOF) - 1u);
}

void xof_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state) {
  ascon_cxof128_squeeze(out, nblocks * XOF_BLOCKBYTES, &state->s);
}

void prf(uint8_t *out, size_t outlen,
         const uint8_t key[KYBER_SYMBYTES],
         uint8_t nonce) {
  uint8_t in[KYBER_SYMBYTES + 1];

  memcpy(in, key, KYBER_SYMBYTES);
  in[KYBER_SYMBYTES] = nonce;

  cxof(out, outlen, in, sizeof(in), CS_PRF, sizeof(CS_PRF) - 1u);
}

void rkprf(uint8_t out[KYBER_SSBYTES],
           const uint8_t key[KYBER_SYMBYTES],
           const uint8_t *ct) {
  uint8_t in[KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES];

  memcpy(in, key, KYBER_SYMBYTES);
  memcpy(in + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  cxof(out, KYBER_SSBYTES, in, sizeof(in), CS_RKPRF, sizeof(CS_RKPRF) - 1u);
}

void hash_h(uint8_t out[32], const uint8_t *in, size_t inlen) {
  cxof(out, 32, in, inlen, CS_HASHH, sizeof(CS_HASHH) - 1u);
}

void hash_g(uint8_t out[64], const uint8_t *in, size_t inlen) {
  cxof(out, 64, in, inlen, CS_HASHG, sizeof(CS_HASHG) - 1u);
}
