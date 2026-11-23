# Decisions for the nfq2 -> Rust port

Written while porting. Mentions of `rust/lab` refer to the verification lab (the C original, a determinism shim and the test corpus), which is not part of this repository.

Upstream reference: bol-van/zapret2 @ 31b245059d18a4ef939b87ef7de7588ebf490ed3 (2026-11-19), directory `nfq2/`.

## ADR-001: Shape and entry point
Status: accepted (2026-11-19)
Context: nfq2 builds one CLI daemon, `nfqws2` (`nfqws.c:main`). `kavl.h` contains a `main` only inside a disabled example.
Decision: The Rust app is one binary, `nfqws2`, with the same CLI.
Consequences: CLI flags, help text, exit codes and log lines are part of the contract.

## ADR-002: Linux (NFQUEUE) only
Status: accepted (2026-11-19)
Context: The original also targets BSD divert sockets, Windows/Cygwin (WinDivert) and Android.
Decision: Port the Linux NFQUEUE target only. `win.c`, `windows/`, `andr/` and the BSD/Cygwin `#ifdef` branches are out of scope.
Consequences: The Rust binary builds and runs on Linux. A later ADR may add other targets.

## ADR-003: Lua stays, embedded with mlua
Status: accepted (2026-11-19)
Context: zapret2 runs its desync strategies as Lua scripts that call the C API in `lua.c` (~4.1k lines).
Decision: Embed Lua with the `mlua` crate and reimplement the same Lua-facing API in Rust, using the same Lua flavour as the reference build (LuaJIT). Existing `.lua` scripts must run unchanged.
Consequences: The Lua globals, function names, argument and return shapes, and error text are part of the contract.

## ADR-004: Equivalence bar
Status: accepted (2026-11-19)
Context: The user wants proof that the port behaves the same.
Decision: Byte-identical on three levels: (1) unit cases for pure functions (checksums, crypto, protocol parsers, packet builders); (2) CLI cases (`--help`, `--version`, `--dry-run`, bad arguments): stdout, stderr and exit code; (3) live replay of packet captures through NFQUEUE in a privileged Linux container, comparing verdicts and emitted packets, with randomness seeded the same way on both sides.
Consequences: Any source of nondeterminism (random, time) needs a seam that both builds share during replay.

## ADR-005: Checkpoints
Status: accepted (2026-11-19)
Decision: No intermediate stops; one report at the end. MAP.md and HANDOFF.md are still kept current so another session can continue.

## ADR-006: Unit proof by a custom differential harness, app proof by rust-anything
Status: accepted (2026-11-19)
Context: `rust-anything bridge` refuses every nfq2 unit: all exports take raw packet pointers (`struct ip*`, `uint8_t*`), so unit-level `record/diff/gate` cannot run. nfqws2 exposes most of its C internals to Lua, and `--intercept=0 --lua-init=...` runs Lua against them without NFQUEUE; `--fuzz=N` drives `dpi_desync_packet` on generated packets.
Decision: Port the whole app as one crate `rust/app` (binary `nfqws2`), structured module-per-C-file. Prove it with `rust-anything app record/replay` on CLI cases, which include deterministic Lua C-API cases and fuzz runs, executed in the `nfq2-lab` Linux container. Skip `front-door`/`wire`: a fallback to the original per invocation does not apply to a daemon. Live NFQUEUE replay is a separate lab script.
Consequences: No per-unit `gate`; the crate gets fmt, clippy -D warnings, cargo test and app replay instead.

## ADR-007: Same system libraries for deterministic sources
Status: accepted (2026-11-19)
Context: Output depends on glibc `random()` (seeded with `srandom(time(NULL))`), `getrandom()`, LuaJIT's `math.random`, and zlib's deflate output.
Decision: The Rust app calls glibc `srandom/random/time/getrandom` through `libc`, links the system LuaJIT through `mlua` (feature `luajit`, not vendored) and the system zlib through `flate2`/`libz-sys`. The lab preloads `rust/lab/detshim.so` into both builds to fix `time()` and `getrandom()`.
Consequences: Byte-identical output under the shim; the Rust binary is Linux/glibc-dynamic, like the original.

## ADR-008: Lua bindings use the raw Lua C API
Status: accepted (2026-11-19)
Context: Scripts observe the bindings' exact behavior: `luaL_check*` error strings, `luaL_error` messages without position prefix, error values that are strings (not userdata), stack-guard errors, registry refs. mlua's high-level API wraps errors in userdata and formats conversion errors differently.
Decision: Port lua.c against `mlua::ffi` (LuaJIT 5.1 C API) function by function, keeping registry refs (`luaL_ref`) as the C code does. Each unsafe block carries a SAFETY comment; the module is the only large unsafe surface.
Consequences: conntrack and timers store registry refs (i32), not mlua handles.

## ADR-009: Preserve observable quirks of the original
Status: accepted (2026-11-19)
Context: Byte-identical output (ADR-004) exposes some accidental behavior of the C code.
Decision: Reproduce it and list it here:
- `NFQWS2_VER` is the empty string in Lua: `main()` writes `params.verstr`, then `init_params()` memsets `params`. The banner line still prints the version.
- An `--lua-desync` error message prints the argument after `\:` escapes were swallowed in place.
- LuaJIT hashes table keys by string IDs assigned in creation order, so `pairs()` order depends on the exact sequence of Lua strings the bindings create; the port creates them in the same order.
- The bindings allocate the same temporary Lua userdata as the C code (tls_mod, brandom, aes_*, hkdf, csum_*, bxor/bor/band, parse_hex, bcryptorandom) and the desync context userdata has the C struct size (56 bytes on 64-bit, 28 on 32-bit targets): the `LUA GARBAGE COLLECT: xK => yK` debug line reports the Lua heap, so those bytes are observable.
Consequences: Fixing any of these is a separate, explicit change.

## ADR-010: SIGUSR1/SIGUSR2 dumps run outside the signal handler
Status: accepted (2026-11-19)
Context: The C handlers call printf and walk the conntrack/hostfail pools inside the handler (not async-signal-safe). In Rust that would re-enter RefCell borrows.
Decision: Handlers set a flag; the dump text is identical and is printed at the next loop iteration (after the interrupted recv/select returns EINTR).
Consequences: The dump can appear a few microseconds later relative to packet logs. Not covered by byte-identical replay.

## ADR-011: Safe Lua layer and narrow FFI wrappers
Status: accepted (2026-11-20)
Context: ADR-008 put about a quarter of the code in `unsafe` (every binding was an `unsafe extern fn` working on a raw `lua_State`). LuaJIT is built without API checks, so a wrong stack index there is undefined behavior, not an error.
Decision: `src/lua/lj.rs` wraps the raw API in a `Copy` handle `L` whose functions are safe: each validates stack indices and reserves stack space (`lua_checkstack`) and raises a Lua error on misuse; strings are returned as owned copies. Bindings are plain `fn(L) -> c_int`, turned into `lua_CFunction`s by the `cfn!` macro (a per-function trampoline, not a closure with an upvalue, so the Lua heap accounting of ADR-009 is unchanged). zlib streams live in a Rust-side table; the Lua userdata keeps the C struct's size and stores a handle. libc calls used by the Lua API go through `src/sys.rs`; other syscall sites use one-call `unsafe` blocks.
Consequences: About 3% of code lines are `unsafe` (was about 25%). Behavior is unchanged: corpus, live NFQUEUE run and the recorded replay are identical to the original.


## ADR-012: Match the C original per target architecture
Status: accepted (2026-11-23)
Context: Built for aarch64 and mipsel and compared with the C original built for the same target, the port showed differences that x86-64 testing could not reveal: the C code's behavior itself depends on the platform.
Decision: Follow what the C build does on each target:
- 64-bit values cross into Lua through lua.h's `*lint` macros: `lua_Integer` on 64-bit targets, `lua_Number` (double) on 32-bit ones, where LuaJIT's `lua_Integer` is 32-bit. `lj::pushlint/checklint/tolint` mirror them, and `pushf_int` (C `lua_pushf_int`, whose value is a `lua_Integer`) is kept apart from `pushf_lint`.
- The seccomp filter's ARCH_NR, syscall list and x32 check are generated by build.rs from the target's own C headers with sec.c's `#ifdef` list (targets without an ARCH_NR get no filter, as `#if ARCH_NR!=0` in C).
- Userdata that only stand in for C structs take the C struct's size on the target (desync context: 56 bytes on 64-bit, 28 on 32-bit).
- Messages the C code formats with `%d`/`%u` are raised with the same `luaL_error` format and arguments: LuaJIT reserves extra room for numbers in its string buffer, which is part of the Lua heap.
- `--fuzz` draws ifin/ifout inside one C argument list; gcc evaluates it right to left on x86, left to right on aarch64 and mips, so the port draws in that order per target.
Consequences: Verified on x86-64 (native) and on aarch64 and mipsel under qemu-user against C builds for those targets. Under qemu the seccomp filter cannot be installed (qemu-user rejects it) in either build.

## ADR-013: nfqws2-keenetic compatibility
Status: accepted (2026-11-23)
Context: nfqws2-keenetic (the Keenetic/OpenWrt packaging of nfqws2) builds zapret2 with its own patch, which adds `--fastpath-workaround=0|1|auto` and which its init script always passes, and ships static musl binaries for seven architectures, soft-float on MIPS.
Decision: Port the patch as part of the C contract (option parsing, help line, the `fastpath workaround` debug line, retransmission handling during incomplete TLS reassembly, ACK-only placeholders). Build static musl binaries with the same toolchains (bol-van/musl-cross), library versions and flags (OpenResty luajit2 with FFI disabled, libmnl, libnfnetlink, libnetfilter_queue, zlib), linked non-PIE against the toolchain's libc, with 64-bit `time_t` on 32-bit musl. MIPS targets use nightly `-Zbuild-std` with the MIPS32 baseline (Rust's targets default to MIPS32r2). Mirror lua.c's ` OpenResty` suffix in the LuaJIT banner. Target-specific fixes the musl builds exposed: random bytes are stored native-endian like C's `*(uint16_t*)` (mips big-endian); socket option numbers come from the target's `<sys/socket.h>` via build.rs, because libc 0.2.191 applies the MIPS values to 32-bit MIPS only; `stat(2)` goes through libc, because `std::fs::metadata` returns a wrong size and mtime on mips64 musl; mips64 is built position-independent (non-PIC code above 4 GiB truncated addresses); ppc test builds are static with the determinism shim linked in, since LuaJIT's PowerPC VM forces bss-plt, which musl's dynamic loader rejects.
Consequences: Dependencies are built without `-flto` (libz-sys detects zlib by linking a test program, which fails against LTO-only archives); x86 uses LuaJIT instead of PUC Lua 5.5 and needs SSE2. Verified per target under qemu-user against the C original built the same way (the runner adds `--uid=0:0` first, since the build host is an LXC container where the default privilege drop fails, for both programs).

## ADR-014: Rust 1.100, edition 2024
Status: accepted (2026-11-23)
Context: The port started on Rust 1.88 and edition 2021.
Decision: Require Rust 1.100 and edition 2024. Apply the edition migration and the newer clippy suggestions (let chains, `as_chunks`, `is_multiple_of`). Tier-3 targets (MIPS, PowerPC) build std from source with the same pinned toolchain and `RUSTC_BOOTSTRAP=1`, not a nightly: a 2026-11 nightly did not sign-extend 32-bit C arguments on mips64.
Consequences: Edition 2024 drops temporaries in tail expressions and `if let` scrutinees earlier; the three places this touches only release `RefCell` borrows or a `File` sooner. All targets were re-verified after the switch.

