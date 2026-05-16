#!/usr/bin/env sh
set -e

make clean
make test/test_ntt_timing512 test/test_ntt_timing768 test/test_ntt_timing1024 \
     test/test_bench_summary512 test/test_bench_summary768 test/test_bench_summary1024

echo "=== NTT / POLY microbench ==="
./test/test_ntt_timing512
./test/test_ntt_timing768
./test/test_ntt_timing1024

echo "=== Enc/Dec summary (medians) ==="
./test/test_bench_summary512
./test/test_bench_summary768
./test/test_bench_summary1024