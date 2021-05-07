#!/usr/bin/env bash

set -eux
cd $(dirname $0)/..

export CARGO_TARGET_DIR=$(pwd)/target

pushd ./example
cargo rustc \
      --release \
      -- \
      -Cpasses='sancov' \
      -Cllvm-args=-sanitizer-coverage-level=4 \
      -Cllvm-args=-sanitizer-coverage-trace-compares \
      -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
      -Cllvm-args=-sanitizer-coverage-stack-depth \
      -Cllvm-args=-sanitizer-coverage-trace-geps \
      -Cllvm-args=-sanitizer-coverage-prune-blocks=0 \
      -Zsanitizer=address
(! $CARGO_TARGET_DIR/release/example -runs=100000)
popd

pushd ./example_arbitrary
cargo rustc \
      --release \
      -- \
      -Cpasses='sancov' \
      -Cllvm-args=-sanitizer-coverage-level=4 \
      -Cllvm-args=-sanitizer-coverage-trace-compares \
      -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
      -Cllvm-args=-sanitizer-coverage-stack-depth \
      -Cllvm-args=-sanitizer-coverage-trace-geps \
      -Cllvm-args=-sanitizer-coverage-prune-blocks=0 \
      -Zsanitizer=address
(! $CARGO_TARGET_DIR/release/example_arbitrary -runs=10000000)
RUST_LIBFUZZER_DEBUG_PATH=$(pwd)/debug_output \
    $CARGO_TARGET_DIR/release/example_arbitrary \
    $(ls ./crash-* | head -n 1)
cat $(pwd)/debug_output
grep -q Rgb $(pwd)/debug_output
popd
