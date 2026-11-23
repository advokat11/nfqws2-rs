#!/bin/sh
# Cross-build nfqws2: cross/build.sh aarch64|mipsel  (binary lands in target/<triple>/release)
set -e
cd "$(dirname "$0")/.."
docker build -t nfqws2-cross cross
case "$1" in
  aarch64)
    docker run --rm -v "$PWD":/src -e PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig \
      nfqws2-cross cargo build --release --locked --target aarch64-unknown-linux-gnu ;;
  mipsel)
    docker run --rm -v "$PWD":/src -e PKG_CONFIG_LIBDIR=/opt/mipsel/lib/pkgconfig \
      -e RUSTC_BOOTSTRAP=1 nfqws2-cross cargo build --release --locked --target mipsel-unknown-linux-gnu -Zbuild-std=std,panic_abort ;;
  *) echo "usage: $0 aarch64|mipsel" >&2; exit 2 ;;
esac
