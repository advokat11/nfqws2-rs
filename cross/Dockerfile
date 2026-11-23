# Cross-build image for nfqws2 (Debian 12, x86-64 host):
#   aarch64-unknown-linux-gnu  - stable Rust, Debian arm64 multiarch libraries
#   mipsel-unknown-linux-gnu   - nightly Rust (-Zbuild-std, tier-3 target), C libraries
#                                built from Debian sources by deps-mipsel.sh
# Usage: see cross/build.sh
FROM debian:bookworm
RUN dpkg --add-architecture arm64 \
 && sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl ca-certificates dpkg-dev autoconf automake libtool \
    libc6-dev-i386 lib32gcc-12-dev qemu-user \
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross gcc-mipsel-linux-gnu libc6-dev-mipsel-cross \
    libnetfilter-queue-dev:arm64 libnfnetlink-dev:arm64 libmnl-dev:arm64 zlib1g-dev:arm64 libluajit-5.1-dev:arm64 \
 && rm -rf /var/lib/apt/lists/*
COPY deps-mipsel.sh /usr/local/bin/
RUN sh /usr/local/bin/deps-mipsel.sh
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.88.0 \
 && /root/.cargo/bin/rustup target add aarch64-unknown-linux-gnu \
 && /root/.cargo/bin/rustup toolchain install nightly --profile minimal -c rust-src
ENV PATH=/root/.cargo/bin:$PATH \
    PKG_CONFIG_ALLOW_CROSS=1 \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_LINKER=mipsel-linux-gnu-gcc \
    CC_mipsel_unknown_linux_gnu=mipsel-linux-gnu-gcc \
    CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_RUSTFLAGS="-L /opt/mipsel/lib"
WORKDIR /src
