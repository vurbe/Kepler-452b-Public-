#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "params.h"
#include "kem.h"

#ifndef TRIALS
#define TRIALS 200
#endif

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static void sort_u64(uint64_t *a, size_t n) {
  for (size_t i = 0; i < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      if (a[j] < a[i]) {
        uint64_t t = a[i];
        a[i] = a[j];
        a[j] = t;
      }
    }
  }
}

static uint64_t median_u64(uint64_t *a, size_t n) {
  sort_u64(a, n);
  return a[n / 2];
}

int main(void) {
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t sk[KYBER_SECRETKEYBYTES];
  uint8_t ct[KYBER_CIPHERTEXTBYTES];
  uint8_t ss1[KYBER_SSBYTES];
  uint8_t ss2[KYBER_SSBYTES];

  uint64_t keypair_ns[TRIALS];
  uint64_t enc_ns[TRIALS];
  uint64_t dec_ns[TRIALS];
  int failures = 0;

  for (int i = 0; i < TRIALS; i++) {
    uint64_t t0, t1;

    t0 = now_ns();
    crypto_kem_keypair(pk, sk);
    t1 = now_ns();
    keypair_ns[i] = t1 - t0;

    t0 = now_ns();
    crypto_kem_enc(ct, ss1, pk);
    t1 = now_ns();
    enc_ns[i] = t1 - t0;

    t0 = now_ns();
    crypto_kem_dec(ss2, ct, sk);
    t1 = now_ns();
    dec_ns[i] = t1 - t0;

    if (memcmp(ss1, ss2, KYBER_SSBYTES) != 0) {
      failures++;
    }
  }

  printf("ASCON-KYBER K=%d TRIALS=%d failures=%d\n", KYBER_K, TRIALS, failures);
  printf("public_key_bytes=%d secret_key_bytes=%d ciphertext_bytes=%d shared_secret_bytes=%d\n",
         CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
         CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES);
  printf("median_ns keypair=%llu encaps=%llu decaps=%llu\n",
         (unsigned long long)median_u64(keypair_ns, TRIALS),
         (unsigned long long)median_u64(enc_ns, TRIALS),
         (unsigned long long)median_u64(dec_ns, TRIALS));

  return failures == 0 ? 0 : 1;
}
