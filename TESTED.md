# Local test log

Environment: Linux container, `cc`, `-O3`, portable reference build.

Commands run from `ref/`:

```sh
make clean
make check NTESTS=100
make run-bench TRIALS=200
make shared
make nistkat
cd nistkat
./PQCgenKAT_asconkem512
./PQCgenKAT_asconkem768
./PQCgenKAT_asconkem1024
```

Correctness output summary:

```text
Ascon-CXOF128 KAT and streaming tests passed
KYBER_K=2: test/test_kyber512 exit 0
  CRYPTO_SECRETKEYBYTES:  1632
  CRYPTO_PUBLICKEYBYTES:  800
  CRYPTO_CIPHERTEXTBYTES: 768
KYBER_K=3: test/test_kyber768 exit 0
  CRYPTO_SECRETKEYBYTES:  2400
  CRYPTO_PUBLICKEYBYTES:  1184
  CRYPTO_CIPHERTEXTBYTES: 1088
KYBER_K=4: test/test_kyber1024 exit 0
  CRYPTO_SECRETKEYBYTES:  3168
  CRYPTO_PUBLICKEYBYTES:  1568
  CRYPTO_CIPHERTEXTBYTES: 1568
```

Benchmark output from this container:

```text
ASCON-KYBER K=2 TRIALS=200 failures=0
public_key_bytes=800 secret_key_bytes=1632 ciphertext_bytes=768 shared_secret_bytes=32
median_ns keypair=78902 encaps=84792 decaps=76966

ASCON-KYBER K=3 TRIALS=200 failures=0
public_key_bytes=1184 secret_key_bytes=2400 ciphertext_bytes=1088 shared_secret_bytes=32
median_ns keypair=125259 encaps=133999 decaps=126669

ASCON-KYBER K=4 TRIALS=200 failures=0
public_key_bytes=1568 secret_key_bytes=3168 ciphertext_bytes=1568 shared_secret_bytes=32
median_ns keypair=176553 encaps=188111 decaps=183404
```

NIST-style KAT generator binaries built and generated variant `.rsp` files successfully "FINALLY" \. Those generated files were not committed into the source tree because they are deterministic build artifacts and this variant is not FIPS 203 ML-KEM.
