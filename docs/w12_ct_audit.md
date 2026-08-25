# W12 · Constant-time audit (AGENTS.md §3.3)

Audit date: 2026-08-25. Ticket: HJ-330.

## Scope

Kernel assembly only — the shipped `chacha20_poly1305_encrypt` entry point and
everything it invokes:

- `src/aead.asm` (W9 composition)
- `src/chacha20_avx2.asm` (4-block core, keystream)
- `src/chacha20_tail.asm` (tail/scalar fallback)
- `src/poly1305_bmi2.asm` (BMI2/ADX engine)

`src/ref/*.c` is the portable correctness oracle, not shipped in the kernel
object, and is therefore excluded from the secrecy audit.

Verdict (summary): **PASS on all five §3.3 items after one code fix.**
One compliance gap was found and fixed (see Item 5). No secret-conditioned
branch, secret-indexed memory, or variable-time operation on secret data was
found. Open/static-unprovable items are listed at the end.

---

## Item 1 — No branch conditioned on secret data

**Verdict: PASS.** Every conditional branch depends only on public message
lengths, block counters, or constant loop iterators — never on key, nonce,
plaintext, ciphertext, intermediate ChaCha/Poly1305 state, or tag bytes.

- `aead.asm`:
  - `:90` `jz .aad_pad_ok` — condition `rbp & 15` where `rbp = aad_len` (public).
  - `:111` `jz .ct_pad_ok` — condition `r15 & 15` where `r15 = plaintext_len` (public).
  - `:67` `jnz .zero_otk` — `ecx = 32/8 = 4` (constant).
  - `:147` `jnz .scrub_loop` — `ecx = 5` (constant).
- `chacha20_avx2.asm`:
  - `:242` `jnz .word` — `r11d = 16` (constant per word loop).
  - `:246` `jb .lane` — `r8d` (block index 0..3) vs constant 4.
  - `:257` `jnz .scrub` — `r8d = 1088/32 = 34` (constant).
  - `:301` `jb .tail` — `ebx` = blocks remaining (public `nblocks`).
  - `:311` `jz .done` — `ebx` (public).
- `chacha20_tail.asm`:
  - `:67` `jb .tail` — `r14` = len (public).
  - `:89` `jz .scrub` — `r14` (public).
  - `:103` `jae .bytes` — `rax` (dword offset) vs `r10 = len>>2` (public).
  - `:117` `jz .scrub`, `:129` `jnz .byteloop` — `rcx = len & 3` (public).
- `poly1305_bmi2.asm`:
  - `:67`/`:211` — `len>>4` block count (public).
  - `:239`,`:243`,`:263`,`:272`,`:289` — leftover / message length (public).

## Item 2 — No memory indexing by secret values

**Verdict: PASS.** All memory addressing derives from public data pointers
(`rdi`/`rsi`/`r12`–`r15`), `rsp`+constant, or public length-derived offsets.
No secret-dependent table lookups, no `gather`/`vpgatherdd`.

- Key/nonce loaded by fixed pointers: `aead/tail/core` read `[rsi]`(key),
  `[rdx]`/`[r8]`(nonce) — the *address* is the caller-provided pointer, not a
  secret-derived value; the secret bytes flow into registers at a fixed
  footprint.
- `chacha20_avx2.asm`: serialize at `[r10 + r8*4]` / `[rdi]` — `r8` = block
  index (constant 0..3), writes advance by 4 (public).
- `chacha20_tail.asm`: `vpmaskmovd [r13 + rax*4]`, `[r12 + rax*4]` — `rax` =
  public dword offset; mask built from public `owed` lane count.
- `poly1305_bmi2.asm`: `[r13]`/`[r13+8]` advance by 16 (public).

## Item 3 — No variable-time operations on secret data

**Verdict: PASS.** No division; every shift/rotate count is an immediate
constant; loop/`rep` counts are public lengths or constants. `mulx`/`mul`/
`adcx`/`adox` are fixed-latency on x86.

- `chacha20_avx2.asm` ROT macros: `ROT16`/`ROT8` via `vpshufb` with a constant
  mask; `ROTL <reg>,12`/`7` and `vpsrld <reg>,<reg>,(32-12/7)` — all constant.
- `chacha20_tail.asm`: `shr r10,2`, `and rcx,3`, `and r10,-4` — immediate
  mask/shift on public `len`.
- `poly1305_bmi2.asm`: `shr`/`shl` by immediate constants (2, 62, 63);
  `mul rdx` with `5` and `mulx` full-width products (fixed-latency).
- `rep stos`/`stosq` counts: public pad/`len` or constants.

## Item 4 — Secret registers and stack slots zeroed before return

**Verdict: PASS (see per-symbol note).**

| Exported symbol | Secret-bearing storage | Scrubbed? |
|---|---|---|
| `chacha20_poly1305_encrypt` (`aead.asm`) | 144 B local frame: ctx `h/r/s`, otk, trailer, saved key/nonce ptrs; `ymm0` | Loop `:140-147` scrubs `rsp+0..143` (and 16 B into the legal 128 B red zone); `ymm0` zeroed via `vpxor`. Non-scratch YMM use happens inside called sub-functions (they scrub their own). |
| `chacha20_blocks4_core` | stack INIT/WORK/OUTSCRATCH + `ymm0-15` | Loop `:250-257` scrubs `rsp+0..1087`; `ymm0-15` zeroed `:258-273`. |
| `chacha20_keystream_avx2` | tail scratch | Scrubbed in `.tail` path `:320-327`; full-group path delegates to `blocks4_core`. |
| `chacha20_xor_tail_avx2` | 256 B keystream scratch | `:132-140`; `ymm0`/`ymm1` zeroed, `eax` zeroed `:142`. |
| `poly1305_init_bmi2` / `_update_` / `_final_` / `_auth_` | ctx `h/r/s/buf`; temp stack slots | `init` zeroes `h`/`leftover`/`buf` + `rax`; `update` scrubs its temp slots + `vzeroupper`; `final` zeroes ctx `h/s/r` and `r8/r9/r10`; `auth` scrubs its 80 B frame. |

**rax–r11 review** (acceptance criterion): no secret *byte value* persists in
`rax`–`r11` at an exported return. These registers carry data pointers
(key/nonce/message — addresses, not secret values), public lengths, or zero
(`aead.asm:158` `xor eax,eax`). Secret byte values are confined to YMM
(scrubbed) and stack (scrubbed). One nuance recorded: in
`poly1305_final_bmi2` the computed 128-bit tag is held in `r8`/`r9` while
stored to `[r13]`; that is the published MAC output, public by design after
finalization.

## Item 5 — `vzeroupper` on every return path

**Verdict: PASS after one fix.**

| Exported symbol | `ret` line | `vzeroupper` |
|---|---|---|
| `chacha20_poly1305_encrypt` | `:159` | `:148` |
| `chacha20_blocks4_core` | `:276` | `:274` |
| `chacha20_blocks4_avx2` | jmp → core | via core |
| `chacha20_keystream_avx2` | `:336` | `:330` |
| `chacha20_xor_tail_avx2` | `:153` | `:144` |
| `poly1305_init_bmi2` | `:45` | `:44` |
| `poly1305_update_bmi2` | `:314` | `:306` |
| `poly1305_final_bmi2` | `:417` | `:409` |
| `poly1305_auth_bmi2` | `:455` | `:447` |
| `poly1305_blocks_internal` | `:224` | `:217` (**added this audit**) |

**Finding fixed:** `poly1305_blocks_internal` returned at `:224` with no
`vzeroupper`. It executes only scalar instructions (no AVX), so no 256-bit
upper half is actually dirtied — the gap was ABI-hygiene only, not a live leak.
Added `vzeroupper` (now `:217`) to satisfy the literal §3.3 checklist and
re-ran `make test`: **19/19 ABI still green** (the preservation probes are
unaffected), all suites pass.

---

## Open items — explicitly escalated (static review cannot fully prove)

These are flagged rather than declared safe, per §3.3 "notes on anything the
checklist cannot cover":

1. **`vpmaskmovd` masked load/store fault behavior.** The address and mask
   depend only on public `len`; AVX2 masked loads do not fault on masked-off
   lanes. The harness `asm_tail_no_write_past_len` + guard band verifies no
   write past `len`. Behavior across all x86-64 CPUs is a hardware property
   static review cannot prove; the guard test is the runtime evidence.
2. **Cache/microarchitectural timing.** Data access pattern depends on public
   message/block length, not secret bytes; secret bytes are read at a fixed
   small footprint (key/nonce). The design is S-box-free and uses no
   secret-indexed table, so it relies on the constant-time assumption that
   fixed-latency arithmetic + public-addressing is side-channel sound. Static
   review cannot prove absence of microarchitectural leakage.
3. **`rep movsb/stosb` timing** is O(public length); no secret dependency.
4. **Red-zone over-scrub** in `aead.asm:141-147` writes 16 bytes at `rsp-16`,
   inside the permitted 128-byte red zone. Legal but worth noting.
5. **D8 API contract** (in-place aliasing, NULL handling, error codes, length
   caps, constant-time tag comparison in a future decrypt path) is a contract
   decision, not a crypto side-channel — **escalate for human sign-off**.
6. **Poly1305 reduction** mixes `mul` (`:166`+ etc.) with `mulx`/`adcx`/`adox`;
   these are fixed-latency on x86 — recorded for completeness, not a found
   leak.

---

## Verdict

The kernel meets AGENTS.md §3.3 for the four reviewed exported ChaCha20/
Poly1305/AEAD paths: **no secret-conditioned branch, no secret-indexed memory,
no variable-time op on secrets, secret YMM + stack state zeroed, `vzeroupper`
on every return path.** One code change was made to close the only literal gap
(`vzeroupper` in `poly1305_blocks_internal`). Open items are the standard
static-analysis limits (CPU fault/cache behavior) plus the D8 contract, which
is escalated to the human.
