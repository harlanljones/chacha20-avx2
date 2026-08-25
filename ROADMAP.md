# ROADMAP.md — Execution Plan

Executable plan for building the ChaCha20-Poly1305 AVX2 kernel specified in `TDD.md`. Process rules live in `AGENTS.md`; design decisions live in `TDD.md`. This file owns: current state, scope, metrics, milestones, work items, risks, and decision gates.

## 1. Current State (verified)

- Greenfield repository: `TDD.md` is the only file. No source, no build system, no git history, no test/bench artifacts.
- Host: x86_64 Linux, 28 cores, Arch-based Omarchy.
- CPU features verified in `/proc/cpuinfo`: `avx2`, `bmi2`, `adx` — the full ISA set the TDD assumes.
- Installed and verified via pkg-config: gcc, clang, make, git; libsodium 1.0.22; OpenSSL 3.6.3.
- **Gap:** `nasm` is NOT installed. `cmake` is NOT installed and must stay out of the build (`AGENTS.md` §2). Installing nasm is work item W1.

## 2. Objective & Scope

**Objective:** a standalone RFC 8439 ChaCha20-Poly1305 AEAD kernel (NASM/AVX2 + BMI2/ADX) behind the C-compatible entry point `chacha20_poly1305_encrypt` (TDD §3.1), outperforming a gcc -O3 C reference at large buffer sizes while remaining strictly constant-time.

**In scope:**
- Encrypt-and-authenticate path only as specified by TDD §3.1: ciphertext + 16-byte tag from plaintext, AAD, nonce (12B), key (32B).
- AVX2 4-block-interleave ChaCha20 core with vpshufb rotations and vpshufd diagonalization (TDD §2.1).
- Scalar BMI2/ADX Poly1305 engine (mulx/adcx/adox), clamping at init (TDD §2.2).
- Poly1305 one-time key derivation via ChaCha20 block function with counter=0 over key‖nonce (RFC 8439 §2.6 — **omitted from TDD**; see D7 and W3/W9).
- Scalar fallback/tail handling for payloads < 256 bytes (TDD §4 Phase 4).
- RFC 8439 Appendix A vector suite; differential fuzzing vs libsodium/OpenSSL; benchmark harness.

**Explicit non-goals (unless a decision gate opens them):**
- Other architectures or ISA baselines (SSE-only path, ARM NEON).
- AES-NI / VAES / GFNI variants of either cipher.
- Runtime CPU dispatch / multi-target fat binaries.
- TLS, SSH, or any protocol integration.
- Decrypt/tag-verify API — **unresolved decision D2**; not silently scoped in.
- Streaming/chunked APIs beyond the single-shot signature in TDD §3.1.

## 3. Assumptions

- A1: Host always has `avx2`, `bmi2`, `adx` (verified). The kernel may hard-require these ISAs without runtime detection.
- A2: System V AMD64 ABI applies end-to-end (Linux userland); stack-passed nonce/key offsets per TDD §3.1 are correct as written.
- A3: rdtsc/rdtscp cycle measurement on this host can be stabilized to reproducible medians given fixed-frequency runs (W5 validates this assumption early; risk R4).
- A4: libsodium and OpenSSL AEAD framing can be mapped onto RFC 8439 semantics for differential comparison (W11 validates; risk R5).

## 4. Unresolved Decisions (see also §10 Decision Gates)

| ID | Decision | Why unresolved | Blocks |
| :--- | :--- | :--- | :--- |
| D1 | Poly1305 radix 2^26 vs 2^64 | TDD §2.2 says "Radix-2^64 **or** Radix-2^26" — ambiguous | W8 (Poly1305 engine start) |
| D2 | Decrypt/tag-verify API existence & signature | Absent from TDD entirely | W10 |
| D3 | Fuzzer: AFL++ vs libFuzzer | TDD §5.2 names both | W11 |
| D4 | Primary differential oracle: libsodium vs OpenSSL | TDD §4/§5 name both; both installed | W11 |
| D5 | Baseline comparator: which C reference implementation at gcc -O3 | No baseline number exists yet; must be pinned before perf claims mean anything | W5, W13, M-baseline metric |
| D6 | Diagonal-round shuffle strategy: vpshufd vs vpermd/vpalignr/memory-based | TDD §2.1 asserts vpshufd works; unvalidated on real dependency chains | W6 spike outcome |
| D7 | Confirm Poly1305 one-time-key derivation wiring (ChaCha20 block counter=0, RFC 8439 §2.6) | Omitted from TDD; reference implementation will make it concrete | W9 composition |
| D8 | API semantics: in-place/overlapping buffers allowed or UB; error-code meanings for the `int` return; NULL tolerance; length caps | Absent from TDD §3.1; undocumented aliasing is a classic silent-corruption source | W9 (exported symbol contract) |

## 5. Metrics

Baselines do not exist yet (no code). TBD entries are filled by the owning work item; never invent numbers.

| Metric | Baseline | Target | Measurement method | Owner | Review cadence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| cycles/byte, large-buffer encrypt (≥64 KiB payloads) | TBD — no code exists yet; established by first bench run of C reference (W5/D5) | TBD — speedup goal set after baseline exists (TDD §1 requires beating gcc -O3; margin chosen once baseline is known) | bench harness, rdtsc/rdtscp median of N runs, fixed CPU frequency per R4 mitigation, CSV output | Wave B owner → final comparison W13 | Every bench-affecting merge; formal review at each milestone |
| Correctness: RFC 8439 App A vectors passed | 0 vectors (nothing checked in) | All vectors in the checked-in suite pass (`make test` exit 0); suite grows monotonically, never shrinks | `make test` output "passed/total" | Wave A owner | Every change (quality gate AGENTS §3.1) |
| Differential fuzz: execs / hours / crashes | 0 execs | Crashes = 0 after ≥ agreed soak time; exec count reported verbatim | fuzz harness log stats | Wave E owner | Each fuzz session close-out |
| Constant-time audit checklist completion | Not started | All AGENTS §3.3 items checked against final kernel diff, in writing | Checklist in PR/commit message per AGENTS §3.3 | Wave E owner | Every crypto-output change; final audit W12 |
| ABI conformance: callee-saved preservation test | Test does not exist | Test exists and passes for every exported symbol | Automated harness comparing callee-saved regs before/after calls (part of W14) | Wave A owner | Every exported-symbol change (AGENTS §3.4) |
| Tail-path coverage: lengths 0,1,63,64,65,255,256,257,…~600 tested | None | Full listed set exercised through vectors AND differential harness | test suite length list + fuzz length distribution | Wave A owner | Every change touching tail paths (AGENTS §3.5) |

## 6. Milestones (exit gates, not day counts)

Effort hints in parentheses come from TDD §4's day bands and are estimates only; gates are the binding criteria.

- **M0 — Bootstrap complete.** Exit: git repo initialized; `.gitignore` covers `bin/`, `obj/`, generated corpora; directory skeleton exists (`src/`, `include/`, `test/`, `bench/`, `oracle/`); nasm installed and verified; top-level `Makefile` satisfies the AGENTS §2 contract; `make all` builds an empty-but-valid skeleton; `make clean` works. (≈ TDD Day 1 slice)
- **M1 — Reference correctness.** Exit: C reference ChaCha20-Poly1305 in `src/ref/` passes the full checked-in RFC 8439 Appendix A suite via `make test`; vector suite covers block function, Poly1305, and combined AEAD cases incl. AAD-only and zero-length inputs; ABI preservation test exists and passes against the reference calling convention. (TDD Days 1–3)
- **M2 — Measurement online.** Exit: `make bench` produces a machine-readable CSV with cycles/byte for the C reference across the payload-length matrix; frequency-handling policy implemented and documented in the harness README/output header; D5 resolved (baseline comparator named). (TDD Days 2–3)
- **M3 — ChaCha20 AVX2 core validated.** Exit: assembly ChaCha20 block function passes its App A block-function vectors through the same `make test` runner; keystream differential-matches reference for lengths spanning 0–600+ bytes; diagonalization strategy decided (D6 closed by spike evidence). (TDD Days 4–8)
- **M4 — Poly1305 engine validated.** Exit: scalar BMI2/ADX Poly1305 passes App A authenticator vectors; matches reference tag output across fuzzed message lengths; D1 resolved before first line of engine code. (TDD Days 9–12)
- **M5 — AEAD integrated.** Exit: `chacha20_poly1305_encrypt` (full composition incl. D7 KDF wiring and tail/fallback paths) passes the complete vector suite and full-length-matrix differential comparison; ABI gate green. (TDD Days 13–16)
- **M6 — Hardened & measured.** Exit: fuzz harness running against chosen oracle(s) with 0 crashes over the agreed soak; constant-time audit checklist completed in writing; final cycles/byte CSV recorded vs C baseline; all §5 metrics reviewed and reported per AGENTS §7. (post-TDD close-out)

## 7. Dependency Graph, Critical Path, Concurrency Waves

### Critical path
`W1 bootstrap → W3/W4 reference+vectors → W6 ChaCha20 AVX2 core → W8 Poly1305 → W9 AEAD composition → W11 fuzzing → W12 CT audit → W13 final perf`

W5 (bench) feeds baselines but does not block asm work; it blocks *claims*, not code.

### Concurrency waves (non-overlapping file ownership)

| Wave | Work items | Owns (exclusive) | Can start when |
| :--- | :--- | :--- | :--- |
| Wave A — Reference & tests | W3, W4, W14 | `src/ref/`, `test/`, `include/ref.h` | M0 done |
| Wave B — Bench | W5 | `bench/` | M0 done |
| Wave C — ChaCha20 asm | W6, W7 (asm side) | `src/chacha20_avx2.asm`, `src/chacha20_tail.asm` | M0 done; vectors available from Wave A for validation (may develop against draft vectors) |
| Wave D — Poly1305 asm | W8 | `src/poly1305_bmi2.asm` | M0 done + D1 resolved |
| Wave E — Integration & hardening | W9, W10, W11, W12, W13 | `src/aead.asm` (composition), `fuzz/`, integration glue in `Makefile` | Respective component milestones |

One writer per owned tree at a time (AGENTS §6).

### Integration checkpoints

- **I1 (end M1/M2):** Waves A+B merge. Re-run `make test` + `make bench`; reference numbers recorded; gates revalidated.
- **I2 (end M3):** ChaCha20 asm validated against Wave A's vector runner. Composition files untouched until I3.
- **I3 (end M4):** Poly1305 validated likewise.
- **I4 (end M5):** Composition merged; full suite + differential matrix re-run; Makefile updated by Wave E only.
- **I5 (end M6):** Final revalidation of every quality gate before any performance claim is published.

## 8. Work Items

| ID | Item | Depends on | Suggested role | Exclusive ownership | Deliverable | Validation method | Measurable exit criterion |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| W1 | Bootstrap: install nasm (`sudo pacman -S nasm`, verify `nasm -v`), `git init`, `.gitignore` (bin/, obj/, corpora), skeleton dirs (`src/ include/ test/ bench/ oracle/`), create `Makefile` per AGENTS §2 contract | — | Bootstrap agent | root: `Makefile`, `.gitignore` | Buildable empty skeleton | `make all && make clean` succeeds | M0 exit list fully satisfied |
| W3 | C reference ChaCha20-Poly1305 (correctness oracle): portable scalar C, includes Poly1305 one-time-key derivation via ChaCha20 block counter=0 (RFC 8439 §2.6, closes D7 concretely) | W1 | Wave A owner | `src/ref/`, `include/ref.h` | Reference library used by tests, bench, and fuzzer | Passes W4's suite | M1 vectors all green |
| W4 | Vector harness: check in RFC 8439 Appendix A vectors (block fn, Poly1305, AEAD incl. AAD-only, zero-length, non-block-aligned tails); wire into `make test`; extend coverage to lengths 0…~600 | W1, W3 | Wave A owner | `test/` | `make test` target with passed/total summary | Harness output | M1 exit: full suite passes vs reference |
| W14 | ABI conformance test: automated callee-saved register (rbx, rbp, r12–r15) preservation + stack-alignment checks for every exported symbol | W4 | Wave A owner | `test/abi*` | ABI test binary wired into `make test` | Harness run | Test exists, passes vs reference symbols; later vs kernel symbols |
| W5 | Benchmark harness + methodology: rdtsc/rdtscp timing, payload-length matrix (incl. ≥64 KiB), CSV output; pin CPU governor or otherwise fix frequency; median-of-N policy documented; resolve D5 (name baseline comparator) | W1 | Wave B owner | `bench/` | `make bench` producing cycles/byte CSV | Reproducible repeated runs within stated variance | M2 exit: stable CSV for C reference; methodology documented |
| W6 | AVX2 ChaCha20 4-block core: state setup (YMM_i = word_i × 4 blocks), vpshufb ROL16/ROL8, vpslld/vpsrld/vpor ROL12/ROL7, diagonalization spike (D6: vpshufd vs alternatives — measure, decide, record), 10 double-rounds unrolled | W1, (W4 draft vectors) | Wave C owner | `src/chacha20_avx2.asm` | Assembled object + block-function entry | W4 block vectors + keystream differential vs reference (0–600 B) | M3 exit criteria met; D6 closed with evidence |
| W7 | Tail/scalar fallback path for <256 B payloads and partial final blocks; constant-time length handling (mask-based selects, no secret-dependent branches/exits) | W6 | Wave C owner | `src/chacha20_tail.asm` | Tail-capable keystream path | Differential vs reference at lengths 0,1,63,64,65,127,128,255,256,257,…600 | Full tail-length set bit-exact vs reference |
| W8 | Poly1305 BMI2/ADX engine: mulx/adcx/adox carry-chained multiply-accumulate, clamped r init, finalize (fold + subtract p), padding/tag logic | W1, D1, W4 | Wave D owner | `src/poly1305_bmi2.asm` | Assembled object + MAC entry | App A authenticator vectors + differential vs reference across lengths incl. non-multiple-of-16 tails | M4 exit criteria met |
| W9 | AEAD composition: `chacha20_poly1305_encrypt` entry point per TDD §3.1 (stack args nonce [rsp+8], key [rsp+16]); wire D7 KDF (block 0, counter=0 → otk); interleave keystream gen with MAC consumption; secret zeroing on return (vpxor of secret-bearing regs + stack scrub) and `vzeroupper` on every return path; freeze D8 API contract | W6, W7, W8 | Wave E owner | `src/aead.asm` | Exported kernel symbol | Full W4 suite + W14 ABI test + differential matrix | M5 exit: all vectors + ABI green |
| W10 | Decrypt/tag-verify path — **conditional on D2**; if human declines, item is dropped and scope note updated | W9, D2 | Wave E owner | `src/aead_decrypt.asm` (if approved) | Constant-time tag compare + decrypt entry | Same gate battery as W9 plus tamper cases (flipped-tag/bit rejection rate 100%) | Vectors + tamper tests pass, or item formally closed as declined |
| W11 | Differential fuzz harness vs libsodium/OpenSSL: randomized plaintext/AAD lengths 0–10⁶, framing adapter mapping RFC 8439 ↔ oracle APIs (nonce layout, AAD order, tag placement); resolve D3 (AFL++ vs libFuzzer) and D4 (primary oracle) | W9, D3, D4 | Wave E owner | `fuzz/`, `oracle/` | Fuzz targets + corpus seeds + log stats | Execs/hours/crashes reporting per AGENTS §7 | Soak with crashes = 0; any crash triaged to root cause before M6 |
| W12 | Constant-time review + secret-zeroing audit: walk AGENTS §3.3 checklist against full kernel diff; verify zeroing of ymm/rax-r11 secrets and stack slots; document anything static review cannot cover | W9 | Wave E owner | Audit doc section in PR/commit only (no new runtime artifact) | Written checklist + open-item notes | Human-readable evidence attached | Checklist complete or open items explicitly escalated |
| W13 | Final performance comparison vs C baseline (D5 comparator): same-length matrix, same methodology as W5; publish cycles/byte CSV + speedup ratio with run conditions | W9, W5, W12 | Wave E owner | Updated `bench/` outputs only | Final CSV + claim text meeting AGENTS §5 evidence bar | Independent re-run reproduces within stated variance | M6 perf criterion: published figures have reproducible backing |

*(No W2: numbering reserved to keep IDs stable if the coordinator inserts items.)*

## 9. Risks

| ID | Risk | Trigger / signal | Mitigation |
| :--- | :--- | :--- | :--- |
| R1 | Toolchain gap: nasm missing blocks all asm work | `nasm -v` fails at any point | W1 installs it first; if pacman unavailable, escalate to human immediately rather than substituting another assembler silently |
| R2 | vpshufd diagonalization assumption wrong (dependency-chain latency worse than expected, or lane-crossing needs spill/reload) | W6 spike shows double-round loop slower than modeled or requires memory shuffles | Spike in W6 decides D6 with measurements; fallbacks ready early: vpermd, vpalignr chains, or memory-based shuffle tables kept in .rodata (constant-address = still CT) |
| R3 | Poly1305 radix ambiguity blocks Phase-3-equivalent start | W8 owner reaches design time with D1 open | Resolve D1 at latest by end of M1 (gate below); interim option: implement both radices' inner loops in the C reference so the choice costs nothing extra |
| R4 | rdtsc noise invalidates comparisons (turbo, governor, core migration) | Repeated identical runs vary beyond stated tolerance | W5 pins governor or fixes frequency, warms up, takes median-of-N, records conditions in CSV header; if still unstable, switch to libpfm/perf counters and re-baseline everything measured so far |
| R5 | Fuzz oracle mismatch from framing differences (libsodium appends tag / different arg order / OpenSSL EVP context setup) rather than real bugs | W11 mismatches that reproduce identically for the C reference too | Build the framing adapter against the C reference FIRST; only then point the same adapter at the kernel; treat reference-vs-oracle mismatches as harness bugs, not kernel bugs |
| R6 | Single-maintainer schedule slip (waves serialize unexpectedly) | Any wave blocked > its slack on a predecessor | Waves are deliberately independent (§7); if serialization is forced, cut scope at W10 (D2 likely declines anyway) and W13's matrix size, never at W4/W11 coverage |
| R7 | TDD omissions surface late (KDF wiring, tail semantics) | Integration mismatch at I4 | Already tracked: D7/W3 makes KDF concrete in the reference early; W4's length list pins tail semantics before asm lands |
| R8 | TDD §3.2 register map is internally inconsistent (16 state words need 16 YMMs; map leaves words 8–15 and the feedforward copy unallocated) | W6 design cannot place all state without violating "no spilling" | Resolve during W6 design: masks via `.rodata` memory operands or dedicated regs, initial state spilled once for feedforward — document the actual allocation in W6 evidence and escalate to human if it contradicts TDD §3.2 beyond interpretation (AGENTS §1) |

## 10. Decision Gates

Each gate names the decision, who resolves it, and the deadline in terms of blocking work:

| Gate | Decision | Must be resolved by | Blocked item |
| :--- | :--- | :--- | :--- |
| G-D1 | Poly1305 radix 2^26 vs 2^64 (TDD §2.2 ambiguity) | End of M1 — before W8 writes engine code | W8 |
| G-D2 | Whether decrypt/tag-verify exists, and its exact signature (absent from TDD) | Before M5 planning — W9 leaves room either way | W10 |
| G-D3 | AFL++ vs libFuzzer (TDD §5.2 lists both) | Start of W11 | W11 |
| G-D4 | Primary differential oracle: libsodium or OpenSSL (other stays secondary) | Start of W11 | W11 |
| G-D5 | Which C implementation is the gcc -O3 baseline comparator | Start of W5 | W5, W13, baseline metric |
| G-D6 | Diagonalization shuffle strategy | During W6 spike, before unrolled-loop commit | W6 |
| G-D7 | Ratify RFC 8439 §2.6 KDF wiring (omitted from TDD) | End of M1 — W3 encodes it in the reference; human sign-off requested at that point | W3, W9 |
| G-D8 | API semantics: aliasing/in-place, error codes, NULL, length caps (absent from TDD §3.1) | Before M5 planning — W9 freezes the exported contract | W9, W10 |

Escalation rule: gates are opened to the human with options + recommendation; agents do not pick silently (AGENTS §4).

## 11. Traceability Map

Requirement/critique source → covering work items:

| Source | Requirement / gap | Work items |
| :--- | :--- | :--- |
| TDD §1 | Max throughput vs gcc -O3 | W5, W13 |
| TDD §1 | Side-channel resistance / constant time | W12 (+ every item via AGENTS §3.3) |
| TDD §1 | Zero external runtime deps, SysV ABI | W1, W9, W14 |
| TDD §2.1 | AVX2 4-block layout, vpshufb rotations, vpshufd diagonalization | W6 (spike→D6) |
| TDD §2.2 | Poly1305 scalar BMI2/ADX, clamping | W8 (radix→G-D1) |
| TDD §3.1 | Exact encrypt signature incl. stack-passed nonce/key | W9, W14 |
| TDD §3.1 omissions | Aliasing/in-place, error codes, length caps unspecified | D8/G-D8, W9 |
| TDD §3.2 | Register allocation map (internally inconsistent — see R8) | W6 design resolution + R8; escalate if unresolvable by interpretation |
| TDD §4 Phases 1–4 | Milestone structure | Restructured into M0–M6 (§6); day bands kept as hints only |
| TDD §4 "scalar fallback tail" | Tail handling underspecified | W7 + W4 length list |
| TDD §5.1 | Branch/table elimination, zeroing | W7 (CT length handling), W9 (zeroing), W12 (audit) |
| TDD §5.2 | RFC 8439 App A vectors; differential fuzzing 0–10⁶ B | W4, W11 |
| Coordinator flag | nasm NOT installed | W1 |
| Coordinator flag | Poly1305 radix ambiguity | G-D1, R3 |
| Coordinator flag | Decrypt API omitted from TDD | D2/G-D2, W10 conditional |
| Coordinator flag | No baseline number exists | W5, G-D5, metrics §5 TBD policy |
| Coordinator flag | rdtsc pitfalls (frequency scaling) | W5 methodology, R4 |
| Coordinator flag | Poly1305 key derivation (RFC 8439 §2.6) omitted from TDD | D7/G-D7, W3, W9 |
| Coordinator flag | Tail-path underspecification | W4 length list, W7, AGENTS §3.5 |

Maintenance rule: when a work item completes, tick it here and in §8; when a gate resolves, fill the corresponding TBD/metrics cell and update `TBD → value` with the evidence link. This file changes only alongside the work it describes.
