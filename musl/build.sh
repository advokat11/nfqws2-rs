#!/bin/bash
# Static musl build of nfqws2 for routers, in the format nfqws2-keenetic packages:
#   musl/build.sh <arch>   arch: arm64 arm mips64 mipselsf mipssf ppc x86 x86_64
# Produces out/musl/nfqws2-<arch>.tar.gz with binaries/linux-<arch>/nfqws2 (UPX-packed except
# mips64) and, in the arm64 archive, lua/ (gzipped) from the zapret2 revision the port follows.
#
# Toolchains, library versions and flags follow zapret2's release recipe as used by
# nfqws2-keenetic (bol-van/musl-cross, OpenResty luajit2 with FFI disabled, libmnl,
# libnfnetlink, libnetfilter_queue, zlib), except: dependencies are built without -flto,
# and x86 uses LuaJIT (the C recipe uses PUC Lua 5.5 there), so it needs an SSE2 CPU.
# Needs on the build host (Debian/Ubuntu x86-64): gcc-multilib curl xz-utils bzip2 pigz,
# rustup with the 1.100.0 toolchain.
set -euo pipefail
ARCH=$1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$ROOT/out/musl; mkdir -p "$W/src" "$W/tools"
ZAPRET2_REV=31b245059d18a4ef939b87ef7de7588ebf490ed3
LUAJIT2_TAG=v2.1-20250826
UPX_VER=4.2.4
# MIPS targets are tier 3: std is built from source with the pinned toolchain
# (RUSTC_BOOTSTRAP=1 enables -Zbuild-std; a 2026-11 nightly miscompiled mips64 C calls).
TC=+1.100.0; BSTD=; RFLAGS=; T64=1; CPU=; RELOC=static
case $ARCH in
  arm64)    TOOL=aarch64-unknown-linux-musl;   RT=aarch64-unknown-linux-musl; T64= ;;
  arm)      TOOL=armv6-unknown-linux-musleabi; RT=arm-unknown-linux-musleabi; CPU="-mcpu=arm1176jzf-s -mthumb"; RFLAGS="-C target-cpu=arm1176jzf-s" ;;
  mips64)   TOOL=mips64-unknown-linux-musl;    RT=mips64-unknown-linux-muslabi64; BSTD=1; T64=; RFLAGS="-C target-cpu=mips64"; RELOC=pic ;;
  mipselsf) TOOL=mipsel-unknown-linux-muslsf;  RT=mipsel-unknown-linux-musl; BSTD=1; RFLAGS="-C target-cpu=mips32 -C target-feature=-mips32r2,+mips32,+soft-float" ;;
  mipssf)   TOOL=mips-unknown-linux-muslsf;    RT=mips-unknown-linux-musl; BSTD=1; RFLAGS="-C target-cpu=mips32 -C target-feature=-mips32r2,+mips32,+soft-float" ;;
  x86)      TOOL=i586-unknown-linux-musl;      RT=i586-unknown-linux-musl ;;
  x86_64)   TOOL=x86_64-unknown-linux-musl;    RT=x86_64-unknown-linux-musl; T64= ;;
  ppc)      TOOL=powerpc-unknown-linux-musl;   RT=powerpc-unknown-linux-musl; BSTD=1 ;;
  *) echo "usage: $0 arm64|arm|mips64|mipselsf|mipssf|ppc|x86|x86_64" >&2; exit 2 ;;
esac

fetch() { [ -s "$W/src/$2" ] || curl -fsSL "$1" -o "$W/src/$2"; }
[ -d "$W/tools/$TOOL" ] || curl -fsSL "https://github.com/bol-van/musl-cross/releases/download/latest/$TOOL.tar.xz" | tar -C "$W/tools" -xJ
fetch "https://github.com/openresty/luajit2/archive/refs/tags/$LUAJIT2_TAG.tar.gz" luajit2.tar.gz
fetch https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2 libnfnetlink.tar.bz2
fetch https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 libmnl.tar.bz2
fetch https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2 libnetfilter_queue.tar.bz2
fetch https://github.com/madler/zlib/archive/refs/tags/v1.4.tar.gz zlib.tar.gz
fetch "https://codeload.github.com/bol-van/zapret2/tar.gz/$ZAPRET2_REV" zapret2.tar.gz
fetch "https://github.com/upx/upx/releases/download/v$UPX_VER/upx-$UPX_VER-amd64_linux.tar.xz" upx.tar.xz
export PATH=$W/tools/$TOOL/bin:$PATH

# --- C dependencies (static) ---
DEPS=$W/deps/$ARCH; B=$W/build/$ARCH
rm -rf "$DEPS" "$B"; mkdir -p "$DEPS" "$B"; cd "$B"
CC=$TOOL-gcc; AR=$TOOL-ar; STRIP=$TOOL-strip
MINSIZE="-Oz -ffunction-sections -fdata-sections"; LDMINSIZE="-Wl,--gc-sections"
SYSMALLOC=-DLUAJIT_USE_SYSMALLOC; case $ARCH in arm64|mips64) SYSMALLOC= ;; esac
case $ARCH in *64*) HOSTCC=cc ;; *) HOSTCC="cc -m32" ;; esac
tar -xzf "$W/src/luajit2.tar.gz"
( cd luajit2-*
  make BUILDMODE=static XCFLAGS="$SYSMALLOC -DLUAJIT_DISABLE_FFI" HOST_CC="$HOSTCC" CROSS= CC="$CC" \
    TARGET_AR="$AR rcus" TARGET_STRIP=$STRIP TARGET_CFLAGS="$CPU $MINSIZE" TARGET_LDFLAGS="$CPU $LDMINSIZE" -j"$(nproc)"
  make install PREFIX= DESTDIR="$DEPS" )
for i in libmnl libnfnetlink libnetfilter_queue; do
  tar -xjf "$W/src/$i.tar.bz2"
  ( cd $i-*
    CC=$CC AR=$AR CFLAGS="$CPU $MINSIZE" LDFLAGS="$LDMINSIZE" PKG_CONFIG_PATH=$DEPS/lib/pkgconfig \
      ./configure --prefix= --host=$TOOL --enable-static --disable-shared --disable-dependency-tracking
    make install -j"$(nproc)" DESTDIR="$DEPS" )
  sed -i "s|^prefix=.*|prefix=$DEPS|" "$DEPS/lib/pkgconfig/$i.pc"
done
tar -xzf "$W/src/zlib.tar.gz"
( cd zlib-*; CC=$CC AR=$AR CFLAGS="$CPU $MINSIZE" ./configure --prefix= --static; make install -j"$(nproc)" DESTDIR="$DEPS" )
sed -i "s|^prefix=.*|prefix=$DEPS|" "$DEPS"/lib/pkgconfig/*.pc

# --- Rust port (static, non-PIE, toolchain libc) ---
UT=$(echo $RT | tr a-z- A-Z_); LT=$(echo $RT | tr - _)
export CARGO_TARGET_${UT}_LINKER=$TOOL-gcc CC_$LT=$TOOL-gcc AR_$LT=$TOOL-ar CFLAGS_$LT="-I$DEPS/include -L$DEPS/lib"
export PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR=$DEPS/lib/pkgconfig
# 64-bit time_t on 32-bit musl >= 1.2 (the toolchain's libc)
if [ -n "$T64" ]; then export RUST_LIBC_UNSTABLE_MUSL_V1_2_3=1; fi
# libc and crt from the toolchain like the C build; Rust's libunwind.a if it ships one, else libgcc_eh
UW=$W/unwind/$RT; mkdir -p "$UW"
SC=$(rustc $TC --print sysroot)/lib/rustlib/$RT/lib/self-contained
if [ -f "$SC/libunwind.a" ]; then cp "$SC/libunwind.a" "$UW/"; else cp "$($TOOL-gcc -print-file-name=libgcc_eh.a)" "$UW/libunwind.a"; fi
export CARGO_TARGET_${UT}_RUSTFLAGS="-C link-self-contained=no -C relocation-model=$RELOC -C target-feature=+crt-static -L $DEPS/lib -L $UW -C link-arg=-lgcc $RFLAGS"
EXTRA=; if [ -n "$BSTD" ]; then EXTRA="-Zbuild-std=std,panic_abort"; export RUSTC_BOOTSTRAP=1; fi
cd "$ROOT"
if [ -n "$BSTD" ]; then rustup component add rust-src --toolchain 1.100.0 >/dev/null
else rustup target add --toolchain 1.100.0 $RT >/dev/null; fi
CARGO_TARGET_DIR=$W/target/$ARCH cargo $TC build --release --locked --target $RT $EXTRA

# --- package ---
case $ARCH in mipselsf) BIN=linux-mipsel ;; mipssf) BIN=linux-mips ;; *) BIN=linux-$ARCH ;; esac
P=$W/pkg/$ARCH; rm -rf "$P"; mkdir -p "$P/binaries/$BIN"
$TOOL-strip -o "$P/binaries/$BIN/nfqws2" "$W/target/$ARCH/$RT/release/nfqws2"
if [ $ARCH != mips64 ]; then
  [ -x "$W/src/upx-$UPX_VER-amd64_linux/upx" ] || tar -C "$W/src" -xJf "$W/src/upx.tar.xz"
  "$W/src/upx-$UPX_VER-amd64_linux/upx" -q --best --lzma "$P/binaries/$BIN/nfqws2"
fi
if [ $ARCH = arm64 ]; then
  mkdir -p "$P/lua"; tar -xzf "$W/src/zapret2.tar.gz" -C "$P/lua" --strip-components=2 --wildcards "*/lua/*.lua"
  pigz -11 "$P"/lua/*.lua
fi
tar -C "$P" --owner=0 --group=0 -czf "$W/nfqws2-$ARCH.tar.gz" .
echo "built $W/nfqws2-$ARCH.tar.gz"
