# Glossary (original term -> Rust name)

| Original | Meaning | Rust |
|---|---|---|
| nfqws2 | the daemon: reads packets from NFQUEUE, decides a verdict, may send modified/fake packets | `app` crate binary `nfqws2` |
| desync | rewriting/splitting/faking packets so DPI misreads a flow | `desync` |
| dissect | parsed view of an IP/TCP/UDP packet | `Dissect` |
| conntrack | nfqws2's own flow table (not the kernel's) | `conntrack::Table` |
| profile (desync profile) | a set of filters + Lua strategy functions selected per flow | `Profile` |
| hostlist / ipset | domain / address lists for filtering | `hostlist`, `ipset` |
| darkmagic | raw socket packet construction and sending | `darkmagic` |
| fooling | tricks that make a fake packet ignored by the server (bad seq, bad checksum, low TTL) | `fooling` |
| verdict | NF_ACCEPT / NF_DROP / modified packet returned to the kernel | `Verdict` |
