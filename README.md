# RustChain Vintage x86 Miner

A single-file, dependency-free RustChain attestation miner in C89, written to run
on genuinely old PCs: 486, Pentium, Pentium MMX, Pentium II/III, AMD K5/K6, on
Linux kernels as old as 2.0/2.2, with glibc as old as 2.1 and gcc as old as 2.7.

It was written for a specific machine: a **Sun Cobalt Qube 3** (AMD K6-2/450), booted
from its **stock 2001 Cobalt Linux restore image** (kernel 2.2.16, glibc 2.1.3, gcc
2.95.2). If you can get that image on a disk and boot it, this compiles and runs on it
as-is. It should also build on any old Linux/x86 box of that era with a C compiler.

Why C, and why one file with no libraries: a Cobalt Qube 3's factory OS ships **Python
1.5** and no SSH server. Modern miners are Python 3 and assume a modern userland, so they
simply cannot run there. This talks to the same RustChain node using nothing but libc and
BSD sockets, so a 450 MHz chip from 1998 can attest to the chain in 2026.

## What it does

RustChain uses **Proof of Antiquity**: older, real silicon earns a higher reward
multiplier, because you cannot manufacture a new 1998 CPU. To keep that honest, every
miner submits a hardware fingerprint the server validates. This miner:

1. Detects the CPU from `/proc/cpuinfo` (brand, vendor, family, flags).
2. Times a busy loop with the **RDTSC** cycle counter to produce a clock-drift
   fingerprint. Real silicon has natural timing variance; emulated/VM timing is too
   uniform and gets flagged. (Present on Pentium/K6 and up.)
3. Reads MAC addresses via `ioctl` (`SIOCGIFHWADDR`) because kernels this old predate
   sysfs. These bind the attestation to real hardware.
4. Checks `/proc/cpuinfo` for a `hypervisor` flag as an honest anti-emulation signal. A
   real chip has none and passes; a VM is reported truthfully and expected to be flagged
   server-side.
5. POSTs an attestation to the node over plain HTTP (these machines cannot do modern TLS).

## Honest classification

The reported architecture comes from what the chip says about *itself*, never a
self-assigned vintage label:

| CPU | Reported `arch` |
|-----|-----------------|
| 80486 (family 4) | `486` |
| Pentium, Pentium MMX, K5, K6 (family 5) | `retro` |
| Pentium Pro (family 6 + brand) | `pentium_pro` |
| Pentium II (family 6 + brand) | `pentium2` |
| Pentium III (family 6 + brand) | `pentium3` |
| anything else | `modern` |

Family 6 is only tagged vintage when the brand string literally says so, so a modern
Core i-series chip (also family 6) is reported as `modern`, not handed a vintage bonus.
The server independently validates the timing fingerprint regardless.

## Build

On the vintage box itself (the correct place to build, so the binary matches its own
kernel and libc):

```sh
make
# or, if make/flags are too new for an ancient toolchain:
gcc -O2 -o rustchain_cobalt rustchain_cobalt_miner.c
```

To try it on a modern Linux/x86 host first (it also has RDTSC):

```sh
gcc -O2 -o rustchain_cobalt rustchain_cobalt_miner.c
./rustchain_cobalt --self-test
```

There are no external dependencies. `-pedantic` will warn about `long long`; that is a
gcc extension every gcc since 2.x supports, and it is used only for 64-bit variance math.

## Usage

```sh
./rustchain_cobalt --test-only          # print hardware detection, no network
./rustchain_cobalt --dry-run            # print the exact JSON payload, no network
./rustchain_cobalt --self-test          # SHA-1 and math self-tests
./rustchain_cobalt --once               # attest one time and exit
./rustchain_cobalt                      # loop, attest every 30 minutes

./rustchain_cobalt --node host:port     # node address (default 50.28.86.131:8088)
./rustchain_cobalt --wallet id          # wallet / miner id (default cobalt-qube3-scott)
```

`--test-only` and `--dry-run` let you see exactly what the miner detects and exactly what
it would send before anything touches the network. Nothing is hidden.

## Protocol

Two plain-HTTP POSTs, no signatures:

1. `POST /attest/challenge {}` returns a `nonce`.
2. `POST /attest/submit` sends `miner`, `miner_id`, `nonce`, `report`, `device`,
   `signals`, `fingerprint`.

The `fingerprint` block carries the raw RDTSC-derived samples as evidence, not just a
pass/fail verdict, so the server can judge the timing itself.

## Provenance

The wire protocol and the reusable pieces (self-contained SHA-1, the 64-bit entropy
statistics, the JSON builder, the HTTP layer) come from the sibling
[Amiga miner](https://github.com/Scottcjn) for classic AmigaOS. This port swaps the
Amiga-specific parts (ExecBase CPU detection, EClock timing, ROM hashing, bsdsocket) for
their Linux/x86 equivalents (`/proc/cpuinfo`, RDTSC, a CPU signature hash, POSIX sockets).

## License

AGPL-3.0. Copyright (c) 2026 Scott Boudreaux / Elyan Labs LLC.
