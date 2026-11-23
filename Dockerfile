# Build nfqws2 in a Debian 12 container (the binary links the system LuaJIT, zlib and
# libnetfilter_queue, like the C original). Usage:
#   docker build -t nfqws2-rs . && docker run --rm -v "$PWD/out":/out nfqws2-rs
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config curl ca-certificates \
    libnetfilter-queue-dev libnfnetlink-dev libmnl-dev zlib1g-dev libluajit-5.1-dev \
 && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.100.0
ENV PATH=/root/.cargo/bin:$PATH
WORKDIR /src
COPY . .
RUN cargo build --release --locked
CMD ["sh", "-c", "mkdir -p /out && cp target/release/nfqws2 /out/ && echo copied to /out/nfqws2"]
