# nfqws2-rs

A Rust port of **nfqws2**, the packet manipulation daemon from
[zapret2](https://github.com/bol-van/zapret2) (`nfq2/`), for the Linux NFQUEUE target.

It is a drop-in replacement: same command line, same help text, same log output, same
Lua scripting API. Existing zapret2 Lua scripts (`zapret-lib.lua`, `zapret-antidpi.lua`,
…) run unchanged.

## Status

- Ported: the whole Linux code path of `nfq2` — packet dissection, conntrack, reassembly,
  TLS/HTTP/QUIC/DNS and other protocol detection, QUIC Initial decryption, hostlists,
  ipsets, autohostlist, desync profiles and templates, the Lua C API, timers, raw sending,
  privilege drop, seccomp hardening, nl80211 SSID filtering.
- Not ported: Windows (WinDivert), BSD (divert sockets) and Android targets.
- Ported from upstream commit `31b2450` (2026-11-19).
- Also has `--fastpath-workaround=0|1|auto` from nfqws2-keenetic's
  [patch](https://github.com/nfqws/nfqws2-keenetic/tree/master/patches) (TLS reassembly on
  routers with hardware fastpath, such as MT7621); off by default, as in the patched C.

## Verification

The port was checked against the C original built from the same commit, byte for byte
(stdout, stderr, exit code), with both programs' time and randomness pinned:

- 121 command-line and Lua API cases, including every error path of the Lua bindings and
  fuzzed packets through the desync engine (`--fuzz`), and 10 generated edge cases;
- live NFQUEUE runs in network namespaces with TLS (one and two segments), HTTP with an
  autohostlist-triggering redirect, DNS, UDP and QUIC v1/v2/draft-29 Initials (single,
  split across packets, out-of-order CRYPTO frames, bad tag): identical logs, identical
  packets on the wire, identical autohostlist files.

Not exercised: SSID filtering on real Wi-Fi, `--daemon`, syslog/file logging, SIGHUP
reload, SIGUSR1/SIGUSR2 dumps. Behavior differences that are kept on purpose and design
decisions are listed in [docs/DECISIONS.md](docs/DECISIONS.md).

## Building

Linux only. Needs Rust 1.100+ and the same system libraries as the C version:

```sh
# Debian/Ubuntu
sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev libmnl-dev zlib1g-dev libluajit-5.1-dev pkg-config
cargo build --release
```

The binary is `target/release/nfqws2`. Or build in Docker:

```sh
docker build -t nfqws2-rs .
docker run --rm -v "$PWD/out":/out nfqws2-rs
```

### Other architectures (glibc)

`cross/build.sh aarch64` and `cross/build.sh mipsel` cross-compile dynamically linked glibc
builds in Docker (Debian 12 toolchains; mipsel is a tier-3 Rust target, so std is built from
source with `-Zbuild-std`). The binary is `target/<triple>/release/nfqws2` and needs the
target's LuaJIT, zlib and libnetfilter_queue, like the C build. For routers, use the static
musl builds below. The glibc x86_64 build matches the C one on all 121 cases (Rust 1.100);
aarch64 and mipsel matched it under qemu-user except for the 32-bit `blobs` case described
below and, on hard-float mipsel only, a test that depends on floating point, which qemu
emulates wrongly there. Architecture-specific behavior of the C code that the port follows
is listed in ADR-012.

### Routers (static musl builds, nfqws2-keenetic)

`musl/build.sh <arch>` builds a static binary for `arm64`, `arm` (ARMv6), `mips64`,
`mipselsf`, `mipssf` (soft-float MIPS32), `ppc`, `x86` or `x86_64`, with the toolchains,
library versions and flags of the zapret2 release recipe that
[nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic) uses, and packs it as
`out/musl/nfqws2-<arch>.tar.gz` in that project's layout (`binaries/linux-<arch>/nfqws2`,
UPX-packed except mips64; `lua/` in the arm64 archive). The `musl` workflow builds all of
them and attaches them to the release for a `v*` tag. Differences from the C recipe:
dependencies are built without `-flto`, and x86 uses LuaJIT (the C recipe uses PUC Lua 5.5
there), so the x86 build needs an SSE2 CPU. Not built: riscv64 and lexra (LuaJIT has no
port for them; upstream uses PUC Lua there, which the port does not support).

Each build was compared with the C original (with the same patch) built by the same
toolchain against the same libraries, under qemu-user, Rust 1.100:

| target | corpus (121 cases) |
|---|---|
| arm64, x86, x86_64 | 121/121 identical |
| arm, mipsel, mips, ppc | 120/121 identical |
| mips64 | 120/121 identical |

The `blobs` difference on 32-bit ARM, MIPS and PowerPC is the C code printing a 64-bit
offset with `%zu` (garbage there; the port prints the real offset). The mips64 difference
is `fuzz-antidpi`, where LuaJIT's JIT takes a bus error on an unaligned access under
qemu-user (which, unlike the Linux kernel, does not emulate those); which of the two
programs hits it depends on memory layout, and with the JIT off both outputs are identical.
The x86_64 builds (glibc and musl) also matched the C ones in live NFQUEUE runs with
`--fastpath-workaround=0`, `1` and `auto`, including retransmitted ClientHello fragments and
ACK-only placeholders.

## Usage

Exactly as the original `nfqws2`; see `nfqws2 --help` and the
[zapret2 documentation](https://github.com/bol-van/zapret2/tree/master/docs). Lua scripts
come from the zapret2 `lua/` directory, for example:

```sh
nfqws2 --qnum=200 \
  --lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua \
  --filter-l7=tls --payload=tls_client_hello \
  --lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid
```

## Layout

One crate, one module per C source file of the original (`desync.c` → `src/desync.rs`,
`lua.c` → `src/lua/`, …). The Lua bindings use the raw LuaJIT C API through `mlua::ffi`,
because scripts can observe exact error strings and table construction. All of that goes
through `src/lua/lj.rs`, a small checked layer (stack indices validated, stack space
reserved, strings copied out), so the bindings themselves are safe Rust. The remaining
`unsafe` is thin wrappers around libc, libnetfilter_queue and zlib calls (about 3% of the
code lines).

## License

MIT, like zapret2. See [LICENSE](LICENSE).
