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

Linux only. Needs Rust 1.88+ and the same system libraries as the C version:

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

### Other architectures

`cross/build.sh aarch64` and `cross/build.sh mipsel` cross-compile in Docker (Debian 12
toolchains; mipsel is a tier-3 Rust target and uses nightly `-Zbuild-std`). The binary is
`target/<triple>/release/nfqws2` and needs the target's LuaJIT, zlib and
libnetfilter_queue, like the C build.

Each target was compared with the C original built for the same target (aarch64 and mipsel
under qemu-user):

| target | corpus (121 cases) |
|---|---|
| x86_64 | 121/121 identical |
| aarch64 | 121/121 identical |
| mipsel | 119/121 identical |

The two mipsel differences are not in the port. `blobs`: the C code prints a 64-bit offset
with `%zu`, which shows garbage on 32-bit targets (the port prints the real offset).
`lua-shipped`: LuaJIT's math is broken under qemu-mipsel (`math.floor(3.5)` returns 3.5
even in plain `luajit`), so the random-based test diverges; it needs real MIPS hardware.
Architecture-specific behavior of the C code that the port follows is listed in ADR-012.

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
