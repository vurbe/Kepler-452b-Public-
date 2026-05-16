#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../ascon_cxof.h"

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t fromhex(uint8_t *out, const char *hex) {
  size_t n = strlen(hex) / 2u;
  for (size_t i = 0; i < n; i++) {
    int hi = hexval(hex[2u * i]);
    int lo = hexval(hex[2u * i + 1u]);
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return n;
}

static int kat(const char *msg_hex, const char *z_hex, const char *md_hex) {
  uint8_t msg[256], z[256], got[64], want[64];
  size_t msglen = fromhex(msg, msg_hex);
  size_t zlen = fromhex(z, z_hex);
  size_t mdlen = fromhex(want, md_hex);

  crypto_cxof(got, mdlen, msg, msglen, z, zlen);
  if (memcmp(got, want, mdlen) != 0) {
    printf("Ascon-CXOF128 KAT failed for msg=%s z=%s\n", msg_hex, z_hex);
    return 1;
  }
  return 0;
}

int main(void) {
  int fail = 0;

  fail |= kat("", "",
      "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC529905"
      "CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74");
  fail |= kat("", "10",
      "0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430"
      "FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6");
  fail |= kat("000102030405060708090A0B0C0D0E0F10111213141516171819", "1011",
      "C520C10DAAF8043080EE798DCAAF5E644F39F3D64A7F3A11B15AAE4FA3BF6C419"
      "62DFC709BFD21239423D011A38472A3864AE2A55C185F47C64079A654B345C2");

  uint8_t msg[33], custom[3] = {0xa0, 0xa1, 0xa2};
  uint8_t one[336], split[336];
  for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
  crypto_cxof(one, sizeof(one), msg, sizeof(msg), custom, sizeof(custom));

  ascon_state_t s;
  ascon_cxof128_init(&s, msg, sizeof(msg), custom, sizeof(custom));
  ascon_cxof128_squeeze(split, 168, &s);
  ascon_cxof128_squeeze(split + 168, 168, &s);
  if (memcmp(one, split, sizeof(one)) != 0) {
    printf("Ascon-CXOF128 streaming squeeze failed\n");
    fail = 1;
  }

  if (!fail) printf("Ascon-CXOF128 KAT and streaming tests passed\n");
  return fail;
}
