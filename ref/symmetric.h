#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "ascon_cxof.h"

/*
 * Experimental Ascon-Kyber symmetric backend.
 *
 * This keeps Kyber/ML-KEM dimensions and arithmetic unchanged, but replaces the
 * Keccak SHAKE/SHA3 calls with NIST SP 800-232 Ascon-CXOF128.  This variant is
 * not FIPS 203 ML-KEM and will not match FIPS 203 test vectors.
 *
 * Kyber's rejection sampler requires XOF_BLOCKBYTES to be divisible by 3.  The
 * original SHAKE backend uses 168, so this backend keeps that value while
 * internally squeezing 21 Ascon-CXOF128 rate blocks of 8 bytes each.
 */
#define XOF_BLOCKBYTES 168

typedef struct {
  ascon_state_t s;
} xof_state;

void xof_absorb(xof_state *state,
                const uint8_t seed[KYBER_SYMBYTES],
                uint8_t x, uint8_t y);

void xof_squeezeblocks(uint8_t *out, size_t nblocks, xof_state *state);

void prf(uint8_t *out, size_t outlen,
         const uint8_t key[KYBER_SYMBYTES],
         uint8_t nonce);

void rkprf(uint8_t out[KYBER_SSBYTES],
           const uint8_t key[KYBER_SYMBYTES],
           const uint8_t *ct);

void hash_h(uint8_t out[32], const uint8_t *in, size_t inlen);
void hash_g(uint8_t out[64], const uint8_t *in, size_t inlen);

#endif
