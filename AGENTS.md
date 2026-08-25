# AGENTS.md — Operating Rules for Development Agents

This document governs *process* for every agent working in this repository. It is durable: it contains no schedules, milestones, or phase plans (those live in `ROADMAP.md`). It contains no design decisions either (those live in `TDD.md`).

## 1. Project Intent & Boundaries

This repository implements a standalone RFC 8439 ChaCha20-Poly1305 AEAD encryption kernel in hand-tuned x86-64 NASM assembly, using AVX2 (256-bit, 4-block interleave) for ChaCha20 and BMI2/ADX scalar arithmetic for Poly1305, exposed through a System V AMD64 C-compatible entry point (`chacha20_poly1305_encrypt`, see `TDD.md` §3.1).

Boundaries:

- The assembly kernel plus the C test/benchmark harness are the only artifacts. No other languages, frameworks, or build systems without updating this file and `ROADMAP.md` first.
- **No libc inside the kernel.** Assembly sources must not call libc functions. The C harness may use libc freely.
- **No external runtime dependencies of the kernel.** libsodium and OpenSSL are build-time-only differential oracles used by the test/fuzz harnesses; they are never linked into the shipped kernel object.
- Do not modify `TDD.md` as part of implementation work. If the design conflicts with reality, escalate to the human instead of silently deviating.

Instruction precedence: `TDD.md` is the technical spec → `AGENTS.md` governs process → any conflict between them escalates to the human before code is written around it.

## 2. Environment & Toolchain

Verified host facts (do not re-assume differently): x86_64 Linux (Arch-based Omarchy), CPU exposes `avx2`, `bmi2`, `adx`; gcc, clang, make, pkg-config, git are installed; libsodium and OpenSSL dev packages are available to pkg-config. **`nasm` and `cmake` are NOT installed; cmake must stay out of the build.**

Install prerequisites (required before any assembly compiles; verify after installing):

```sh
sudo pacman -S nasm      # Arch/Omarchy
nasm -v                  # verify installation
```

Assembler/linker invocation pattern:

```sh
nasm -f elf64 -g -F dwarf -o obj/foo.o src/foo.asm   # assemble (ELF64, DWARF debug info)
gcc -o bin/app obj/foo.o obj/main.o ...              # link: prefer gcc as linker driver;
                                                     # plain ld only for freestanding tests
```

Build system contract: no Makefile exists yet. The first implementation task (bootstrap in `ROADMAP.md`) MUST create a top-level `Makefile` satisfying this contract, and every later task must keep it passing:

- Targets: `all` (build kernel objects + harness binaries), `test` (run RFC 8439 Appendix A vector suite), `bench` (build/run benchmark harness), `clean`.
- Variables: `CC=gcc`, `AS=nasm`.
- `CFLAGS`: optimization (`-O2` minimum; benchmark builds may use `-O3`) plus ISA flags matching the verified hardware: `-mavx2 -mbmi2 -madx`.
- `ASFLAGS`: `-f elf64` plus debug info (`-g -F dwarf` or equivalent DWARF output).
- Keep flag choices minimal and justified; do not add warning-suppression or convenience flags without recording why.

Do not fabricate paths or targets beyond this contract; until an artifact exists, creating it is part of the owning task, after which keeping it green is everyone's job.

## 3. Quality Gates (every change must pass)

A change is done only when ALL of the following hold:

1. **Vectors:** `make test` passes with the full RFC 8439 Appendix A suite checked in at that point. Never reduce vector coverage or weaken expected values to force a pass.
2. **Differential comparison:** changes touching cryptographic output include evidence from the differential harness comparing kernel output against libsodium (and/or OpenSSL) across varied plaintext/AAD lengths, including length 0 and non-multiple-of-block-size tails.
3. **Constant-time self-review checklist**, confirmed in writing (PR description or commit message):
   - [ ] No branch conditioned on secret data (key, nonce, plaintext, intermediate state, tag bytes pre-comparison).
   - [ ] No memory indexing by secret values (no secret-dependent table lookups or gather).
   - [ ] No variable-time operations on secret data (division, shifts by secret counts, early loop exits over secret-dependent ranges).
   - [ ] All secret registers and stack slots zeroed before return: secret-bearing YMM registers cleared via `vpxor`, stack slots explicitly scrubbed (per TDD §5.1).
   - [ ] `vzeroupper` issued on every return path (SysV ABI duty for AVX code; distinct from secrecy scrubbing above — do not substitute `vzeroall` for it).
4. **ABI conformance:** callee-saved `rbx`, `rbp`, `r12`–`r15` preserved across every exported symbol; direction flag respected; stack alignment per System V AMD64; if the red zone is used, it stays within 128 bytes below `rsp`; stack-passed arguments read at their documented offsets (nonce `[rsp+8]`, key `[rsp+16]` per TDD §3.1). An automated preservation test must exist and pass.
5. **Tail paths exercised:** payload lengths covering 0, 1, 63, 64, 65, 255, 256, 257, and up to ~600 bytes are tested — never merge a change that skips them.

## 4. Prohibited Shortcuts

- Never weaken, skip, or hardcode-around test vectors to make a failing test pass.
- Never state performance claims without reproducible harness output backing them (see §5).
- Never commit binaries, build outputs, keys, or secrets. `.gitignore` must cover `bin/`, `obj/`, and generated corpora before the first commit.
- Never leave tail/fallback paths untested because the fast path works.
- Never add a dependency (tool, library, submodule) without updating this file and `ROADMAP.md` in the same change.
- Never implement around a TDD ambiguity silently — open the decision with the human (see `ROADMAP.md` decision gates).
- Never claim constant-time safety without walking the §3.3 checklist against the actual diff.

## 5. Evidence Expectations

Claims require attached, reproducible evidence — not assertions:

- **Performance claims** (any cycles/byte or speedup figure): paste the benchmark harness output (machine-readable CSV preferred) into the PR description or commit message, including run conditions (CPU governor/frequency handling, iteration count, median-of-N policy per `ROADMAP.md`). Unreproducible numbers do not count.
- **Correctness claims**: attach `make test` summary (vectors passed/total) and differential-fuzz stats (execs, crash count) relevant to the change.
- **Constant-time claims**: the completed §3.3 checklist plus notes on anything the checklist cannot cover.

## 6. Coordination Protocol

- Decompose work along dependency seams; components with disjoint file ownership proceed concurrently (see waves in `ROADMAP.md`).
- One writer per file/component at a time. Claim ownership before editing shared surfaces.
- Integrate in dependency order; after each merge, re-run `make test` and revalidate gates before building further on top.
- Keep coordination state out of code comments and commit messages except where required evidence lives.

## 7. Progress Reporting

Report progress against the metrics defined in `ROADMAP.md`, not narrative status:

- cycles/byte (with run conditions) whenever bench results change materially,
- vector pass count (passed/total),
- fuzz execs / wall-clock hours / crashes (target: 0),
- constant-time checklist status (complete/incomplete + open items),
- ABI conformance test result.

If a gate cannot be met, report the failing evidence verbatim rather than describing intent.

## Agent skills

### Issue tracker

Issues live in Linear — team `HJ`, project `chacha20-avx2` — via the `linear` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical roles with identity-mapped label strings; all five already exist in the workspace. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `CONTEXT.md` + `docs/adr/`. See `docs/agents/domain.md`.
