#!/bin/sh
# Build the C libraries nfqws2 links (zlib, libmnl, libnfnetlink, libnetfilter_queue,
# LuaJIT) for mipsel/glibc from Debian 12 sources into /opt/mipsel.
# Debian 12's mipsel multiarch packages are not installable, hence the source build.
set -e
P=/opt/mipsel; H=mipsel-linux-gnu
mkdir -p /tmp/deps && cd /tmp/deps
apt-get update -qq
apt-get source -qq zlib libmnl libnfnetlink libnetfilter-queue luajit
cd /tmp/deps/zlib-*/
CC=$H-gcc ./configure --prefix=$P && make -j"$(nproc)" && make install
for d in libmnl libnfnetlink libnetfilter-queue; do
  cd /tmp/deps/$d-*/
  [ -x configure ] || autoreconf -fi
  PKG_CONFIG_PATH=$P/lib/pkgconfig ./configure --host=$H --prefix=$P
  make -j"$(nproc)" && make install
done
cd /tmp/deps/luajit-*/
# The host part of LuaJIT's build must be 32-bit like the target.
make -j"$(nproc)" HOST_CC="gcc -m32 -I/usr/include/x86_64-linux-gnu" CROSS=$H- TARGET_SYS=Linux PREFIX=$P
make install PREFIX=$P
rm -rf /tmp/deps /var/lib/apt/lists/*
