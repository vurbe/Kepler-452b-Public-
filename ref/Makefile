CC ?= cc
RM ?= rm -f
CFLAGS ?= -O3 -fomit-frame-pointer
CFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -std=gnu99 -Wall -Wextra -Wpedantic \
          -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith \
          -I. -Itest
LDFLAGS ?=
NTESTS ?= 1000
TRIALS ?= 200

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
          symmetric-ascon.c ascon_cxof.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.h verify.h \
          symmetric.h ascon_cxof.h randombytes.h

.PHONY: all correctness check bench run-bench shared nistkat clean

all: correctness bench shared

correctness: test/test_ascon_cxof test/test_kyber512 test/test_kyber768 test/test_kyber1024

check: correctness
	./test/test_ascon_cxof
	./test/test_kyber512
	./test/test_kyber768
	./test/test_kyber1024

test/test_ascon_cxof: ascon_cxof.c ascon_cxof.h test/test_ascon_cxof.c
	$(CC) $(CFLAGS) ascon_cxof.c test/test_ascon_cxof.c -o $@

test/test_kyber512: $(SOURCES) $(HEADERS) randombytes.c test/test_kyber.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -DNTESTS=$(NTESTS) $(SOURCES) randombytes.c test/test_kyber.c -o $@

test/test_kyber768: $(SOURCES) $(HEADERS) randombytes.c test/test_kyber.c
	$(CC) $(CFLAGS) -DKYBER_K=3 -DNTESTS=$(NTESTS) $(SOURCES) randombytes.c test/test_kyber.c -o $@

test/test_kyber1024: $(SOURCES) $(HEADERS) randombytes.c test/test_kyber.c
	$(CC) $(CFLAGS) -DKYBER_K=4 -DNTESTS=$(NTESTS) $(SOURCES) randombytes.c test/test_kyber.c -o $@

bench: test/test_bench_summary512 test/test_bench_summary768 test/test_bench_summary1024

run-bench: bench
	./test/test_bench_summary512
	./test/test_bench_summary768
	./test/test_bench_summary1024

test/test_bench_summary512: $(SOURCES) $(HEADERS) randombytes.c test/test_bench_summary.c
	$(CC) $(CFLAGS) -DKYBER_K=2 -DTRIALS=$(TRIALS) $(SOURCES) randombytes.c test/test_bench_summary.c -o $@

test/test_bench_summary768: $(SOURCES) $(HEADERS) randombytes.c test/test_bench_summary.c
	$(CC) $(CFLAGS) -DKYBER_K=3 -DTRIALS=$(TRIALS) $(SOURCES) randombytes.c test/test_bench_summary.c -o $@

test/test_bench_summary1024: $(SOURCES) $(HEADERS) randombytes.c test/test_bench_summary.c
	$(CC) $(CFLAGS) -DKYBER_K=4 -DTRIALS=$(TRIALS) $(SOURCES) randombytes.c test/test_bench_summary.c -o $@

shared: lib/libpqcrystals_asconkyber512_ref.so lib/libpqcrystals_asconkyber768_ref.so lib/libpqcrystals_asconkyber1024_ref.so

lib/libpqcrystals_asconkyber512_ref.so: $(SOURCES) $(HEADERS) randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=2 $(SOURCES) randombytes.c -o $@

lib/libpqcrystals_asconkyber768_ref.so: $(SOURCES) $(HEADERS) randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=3 $(SOURCES) randombytes.c -o $@

lib/libpqcrystals_asconkyber1024_ref.so: $(SOURCES) $(HEADERS) randombytes.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=4 $(SOURCES) randombytes.c -o $@

nistkat: nistkat/PQCgenKAT_asconkem512 nistkat/PQCgenKAT_asconkem768 nistkat/PQCgenKAT_asconkem1024

nistkat/PQCgenKAT_asconkem512: $(SOURCES) $(HEADERS) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCES) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto -o $@

nistkat/PQCgenKAT_asconkem768: $(SOURCES) $(HEADERS) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto -o $@

nistkat/PQCgenKAT_asconkem1024: $(SOURCES) $(HEADERS) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCES) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto -o $@

clean:
	-$(RM) test/test_ascon_cxof test/test_kyber512 test/test_kyber768 test/test_kyber1024
	-$(RM) test/test_bench_summary512 test/test_bench_summary768 test/test_bench_summary1024
	-$(RM) nistkat/PQCgenKAT_asconkem512 nistkat/PQCgenKAT_asconkem768 nistkat/PQCgenKAT_asconkem1024
	-$(RM) nistkat/*.req nistkat/*.rsp *.o *.gcno *.gcda *.lcov
	-$(RM) -r lib
