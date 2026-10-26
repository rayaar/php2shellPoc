# php2shell — how the real exploits work, and what to borrow

Engineering notes from static analysis of the three verified-real PoCs
(alvarodh5/php2shell, 3em0/php2shell, dinosn/php-cve-2026-10961x-lab-poc).
All three are one lineage (cross-credited @9bie / @dinosn). ikow/php2shell-poc is
**not** in this group — its free code is session-poisoning + a /proc cheat, real
trigger paywalled.

Everything below is from reading the code, not running it. "Works" = the code
genuinely implements the mechanism; none has been executed here yet.

---

## The unified chain (all three agree)

### Stage 0 — arm the OOM, keep the ASLR base

One multipart POST, built the same way in all three:

- **1001 filler fields** (`f0000..f1000`) → exceeds `max_input_vars=1000`. Under
  `display_errors=On` this gets output started (`headers_sent`) which is part of
  what wedges cleanup later.
- **`PHPSESSID=\x00`** (a single NUL) → forces PHP to mint a *new* session id and
  sets `send_cookie=1`, so the id is echoed back in `Set-Cookie` (our read channel).
- **`PHP_SESSION_UPLOAD_PROGRESS=pwn`** + a **file part** → drives the rfc1867
  upload-progress handler, which runs during SAPI startup *before any app code* and
  does the session FILE_START init. This is why `index.php` can be `<?php echo "OK";`
  — the bug is reached pre-application, pre-auth.
- **One huge field, 12–24 MB of "B"** → blows `memory_limit` *mid-insert* inside
  `php_request_startup`. `longjmp`/`zend_bailout` fires with `PS(id)` (and/or a hash
  bucket) left partially initialized and dangling.

Key enabler: **prefork re-forks a fresh worker with the SAME ASLR base** after the
OOM aborts one. So you leak the base once and reuse it for every later stage. This
is the exact capability our `/proc/mem` PoC was faking — it's obtainable purely over
HTTP via worker rotation. (alvarodh5 `rotate()` L194-200; 3em0 stage0 `rotate`
362-383.)

### Stage 1 — leak the Zend MM chunk base (heap ASLR)

Forge an oversized `zend_string` over the dangling `PS(id)`: write len `0x1000` at
`+0x10`, type byte at `+0x18`. Now the session id echoed in `Set-Cookie` dumps ~4 KB
of live heap instead of 32 bytes. URL-decode it.

Derive chunk base = **majority vote** of 2 MB-aligned (`ptr & ~0x1FFFFF`) pointers in
the expected VA range, accept when ≥8 agree. (alvarodh5 L210-219; 3em0 300-312;
dinosn `nb_pure.py` 116-128.)

### Stage 2 — leak the libphp code base (code ASLR)

Groom a 56-byte HashTable so it lands at `PS(id)+0x18`, putting its `pDestructor`
field (a real libphp pointer) into the leaked `Set-Cookie` window. Read bytes[8:16],
**self-validate** with `(p & 0xfff) == (dtor_offset & 0xfff)`, then
`libphp_base = p - dtor_offset`. (alvarodh5 L220-230; 3em0 315-330; dinosn
`nb_pure.py` 105-112, `libphp = pdtor - 0x7B47A0`.)

The chunk↔libphp delta varies per ASLR generation (dinosn README cites
−0x1a00000 / +0x3600000), which is the proof these are real leaks, not hardcoded.

### Stage 3 — plant the destructor, fire on cleanup

Build a **167-byte fake HashTable** inside a live field-value `zend_string`:

```
+0x00  gc = {refcount=1, type_info=IS_ARRAY(7)}
+0x08  flags / nTableMask
+0x10  arData      = htdata + 0x20
+0x18  nNumUsed = nNumOfElements = 1
+0x20  (fake execute_data frame: zif ptr, NUM_ARGS=1, arg1 -> fake string)
+0x30  pDestructor = zif_system           <-- the win
+0x80  fake zend_string holding the command
```

A small bin-sized carrier lands over `PS(http_session_vars)` and rewrites its value
pointer to `htdata`. At request shutdown, `zend_hash_destroy` walks the fake array and
calls `pDestructor(arData)` = `system(cmd)`. (alvarodh5 `_fake_ht` L232-247; 3em0
`_fake_payload` 440-483 + 520; dinosn `build_ht` `nb_send.py` 128-151.)

---

## Two variants (pick the portable one)

| | CVE-2026-109618 "stale bucket" | CVE-2026-109619 "dangling reference" |
|---|---|---|
| Corrupted object | uninitialized HashTable bucket consumed as fake zval | dangling `PS(http_session_vars)` `zend_reference` reclaimed by a live 31-byte string |
| libc leak needed | often yes | **no** — `zif_system` is at `libphp+offset` |
| Zend MM | dinosn's impl needs `USE_ZEND_ALLOC=0` (non-default) | **stock allocator** |
| Debugger at fire | dinosn calibrates addrs with gdb | **none** |
| Verdict | less portable | **this is the one to build on** |

619 reclaim detail: `build_live_ref` sprays a 31-byte string whose data is a fake
`zend_reference` landing exactly on `PS(http_session_vars)` (dinosn `nb_send.py`
154-166; alvarodh5 `nb` variant L264-282).

---

## What to borrow (consensus winners)

1. **Prefork ASLR-base-preserving rotation.** Leak once, reuse. Replaces our
   `/proc/mem`. This is the single most important borrow.
2. **Set-Cookie heap disclosure via a forged oversized `zend_string`.** Both bases
   come out of one cookie. No OOB-read gadget, no memory-read primitive needed.
3. **Self-validating code-base leak** via the low-12-bit match of the echoed
   `pDestructor`. Cheap correctness check, kills false positives.
4. **`zif_system` @ `libphp+offset`** (619 path) → one base, zero libc leak.
5. **`max_input_vars` overflow + NUL-cookie** combo to arm a dangling `PS(id)` that
   is echoed in `Set-Cookie`.
6. **Concurrent read-while-upload** (3em0 241-262) to catch the `Set-Cookie` before
   the worker RSTs.

---

## Shared weaknesses = our opportunity

Every one of the three has the same gaps. Fixing any of these is a genuine,
shareable contribution rather than a re-skin:

1. **Offsets are build-specific and NOT leaked.** Only the *base* is leaked in-band;
   `zif_system` / `pDestructor` offsets are hardcoded per build (profiles cover only
   8.3.35 / 8.4.26 / 8.5.11) or recovered by `docker cp` of the actual binary
   (localhost-only). **This is the real portability wall.**
2. **~14-byte command limit** (`MAX_CMD`). Shared across all three.
3. **Hand-calibrated grooming constants** (field counts like 841 / 406, carrier
   page selection). Brittle; break on a new build.
4. **Noisy + probabilistic.** Dozens of requests, repeated worker crashes, retry
   loops around non-deterministic heap placement.
5. **Config-gated.** Needs `display_errors=On`, single-worker prefork,
   `memory_limit` < OOM field < `post_max_size`, `use_strict_mode=0`,
   `upload_progress=On`. How many of these are actually default vs. lab-only is worth
   measuring honestly.
6. **Post-exploit stability / multi-worker** unproven everywhere.

---

## Plan for our own (the thing we ship)

Goal: an honest, fully-open, well-documented pure-HTTP implementation of the **619**
chain — no `/proc`, no gdb, no paywall — plus **one real improvement** the others
lack. That combination is worth sharing.

Candidate improvements (pick 1 to start, highest value first):

- **A. In-band build fingerprinting → offset resolution.** Leak a handful of known
  libphp pointers, fingerprint the build, resolve `zif_system`/dtor offsets from a
  small open database keyed by fingerprint. Removes the "need the exact binary"
  wall — the biggest practical limitation. Most novel.
- **B. Break the ~14-byte command limit.** Stage the command: first `system()` writes
  a longer payload to a known path, or write the full command string to a controlled
  heap/file location and point arg1 at it. Turns a toy into a usable primitive.
- **C. Reliability pass.** Replace probabilistic placement with a more deterministic
  groom; quantify fire rate honestly.

Build order:
1. Stand up stock `php:8.4.26-apache` lab (pre-patch; fixed in 8.4.27). No LFI, ASLR
   on, the config gates above. Mirror 3em0's compose but ours, documented.
2. Port the 619 chain cleanly from dinosn `nb_pure.py` + alvarodh5 `nb` reclaim,
   rewritten and commented so it's readable, not obfuscated.
3. Confirm it fires end-to-end in the lab (uid=33) with the in-band leak, no `/proc`.
4. Add improvement A or B.
5. Writeup + the honest config-requirement measurement + detection rules (do the
   open version of what ikow gated).

Reference file:line map is in this doc; repos are under `pocs/`.

---

## Update — lab baseline + the neko repo + feasibility of A

### Lab baseline (done)
Our lab (`lab/`, stock `php:8.4.26-apache`, config mirrors 3em0) is genuinely
exploitable. **alvarodh5's chain fires end-to-end on it**, fully in-band:
chunk base 0x75bf0b600000, libphp base 0x75bf0d231000 (matches /proc maps),
`uid=33(www-data)`, no /proc. 3em0's grooming constants MISS on our env (too
tightly tuned); alvarodh5's `9bie` reclaim is more portable. Ground-truth offsets:
`zif_system=0x465370`, `zval_ptr_dtor=0x65eb60`.

### neko (git.kurosek.com/neko/php2shell) — real, and ahead on two axes
Same real 618/619 in-band chain (no /proc/gdb, `index.php`=`echo "OK"`). Adds:
- **Chunked Transfer-Encoding** to beat stock `post_max_size=8M` (rce_exploit.py
  :543-581) — PHP only checks Content-Length, chunked skips it. Removes our
  `post_max_size=64M` lab crutch.
- **`--workers N` spray** (:646-654) to hit default multi-worker Apache
  (MaxRequestWorkers=150), not just single-worker.
- Offset DB keyed by version+distro (:109-138) + pure-Python ELF parse
  (`--auto-pull`) + `calibrate` subcommand.

Still NOT solved by neko (or anyone):
- **Offsets still hardcoded / from the binary.** Only the *base* is leaked; the
  symbol offset always comes from a DB entry or the actual ELF. → **A is novel.**
- **display_errors=On hard wall** (README :215-253): the leak needs the
  max_input_vars warning to emit output and set `SG(headers_sent)=1`. With
  display_errors=Off the cookie succeeds but no bytes leak. They tried precision-OOM
  and it failed. ("Stock" claim is honest only because the official image ships no
  php.ini → compile-default On; `php.ini-production` sets it Off.)
- **14-byte cmd cap** (167-byte carrier).
- Heap grooming still hand-calibrated per profile.

### Flagship A — in-band offset resolution: HONEST feasibility
Confirmed novel. But "resolve offsets purely in-band" is a spectrum, not a single
switch. Do NOT oversell it. Realistic breakdown:

- **Milestone A1 — in-band libphp BASE without an offset DB: likely feasible.**
  The base leak today is *offset-dependent* (base = leaked pDestructor −
  known dtor_offset). If we upgrade the read to a true **arbitrary read** (forge a
  zend_string with a controlled data pointer via the 619 primitive, echoed in
  Set-Cookie), we can take any leaked libphp-range pointer and scan backward page by
  page for the `\x7fELF` magic → that page is the base. No offset needed. This alone
  removes the base-offset dependency.
- **Milestone A2 — in-band zif_system without a DB: uncertain, real research.**
  `zif_system` is a LOCAL symbol, stripped from `.dynsym`; `.symtab` isn't mapped at
  runtime, so you can't read it by symbol. The viable path is runtime resolution via
  the function table: find `executor_globals`/`CG(function_table)`, look up "system",
  read its `handler` = zif_system. The catch: EG/function_table offset is itself
  build-specific (circular) unless we can reach it from the leaked heap chunk by
  pointer-chasing. Whether a clean heap→EG path exists on this build is an open
  question to answer IN THE LAB, not to promise.

So A is a genuine research project: A1 is a solid, shippable improvement; A2 is the
hard part that may or may not fall. Build A1 first against our working lab chain,
probe for an A2 path, and report honestly how far it goes. Fold in neko's chunked-TE
and spray regardless — they're clear wins.

### A2 SPIKE RESULT (confirmed feasible) — spike_a2.pl via /proc oracle
Proven on the live lab process (base 0x73a8879df000):
```
compiler_globals (+0x132db00, dynsym-exported) +0x38 -> function_table HashTable
  (nUsed=1197) -> bucket key "system" -> zend_function -> handler @+0x58 == zif_system
```
The chain reaches zif_system with **no per-build binary offset**. What it relies on:
- `executor_globals`/`compiler_globals` addresses: resolved IN-BAND by parsing the
  mapped `.dynsym` (both are GLOBAL exports; confirmed present). Not hardcoded.
- function_table field within CG: found by a VALIDATING SCAN (HashTable sanity +
  contains "system"), not a hardcoded offset. Offset-free.
- Bucket stride 0x20, key@+0x18, val@+0x00, and `zend_internal_function.handler`@+0x58:
  these are **public, version-stable struct offsets** from php-src headers — the SAME
  for every build of a given PHP version, NOT per-binary. (handler offset can also be
  validated by requiring the pointer to land in libphp's executable range, which we
  have once A1 gives us the base.)

Categorical improvement over status quo: current PoCs need per-BUILD symbol addresses
(`zif_system` differs per compiled binary); ours needs only per-VERSION struct layout
(public/stable). That's the novel, shippable win.

Honest caveats on the spike: (1) it used `/proc/<pid>/mem` as a read oracle — the real
exploit must perform these same reads via the in-band arbitrary read (Set-Cookie leak);
(2) it located the handler field by matching the known zif_system value — the real flow
reads handler at the structural offset (0x58) and validates it points into libphp .text.
Both are straightforward given the working leak, but remain to be built, not assumed.

### Remaining build work for A
1. Upgrade the in-band leak to an arbitrary read (forge zend_string w/ controlled data
   ptr via the 619 primitive; echo via Set-Cookie). This is the real engineering.
2. In-band: leaked libphp ptr -> ELF-magic scan -> base (A1).
3. In-band: parse mapped .dynsym -> executor_globals/compiler_globals.
4. In-band: scan CG for function_table -> walk to "system" -> read handler = zif_system.
5. Plant fake HT w/ pDestructor=zif_system (existing), fire.
6. Fold in neko's chunked-TE (stock post_max_size) + spray (multi-worker).
Result: pure-HTTP RCE with no offset DB and no possession of the target binary.

---

## FLAGSHIP PIVOT — worker-pinning for busy multi-worker servers (BUILT, WORKS)

A (in-band offset resolution) is blocked on an arbitrary-read primitive that does
not exist in this bug class (zend_string stores data inline; the leak is a relative
window dump, not a pointer-following read — see above). Confirmed by reading
alvarodh5's leak code: stage1/stage2 only dump heap at PS(id)+0x18. So A is parked.

Pivoted to the reliability problem (user's idea) and it paid off.

### What we proved empirically (lab: stock php:8.4.26-apache, KeepAlive On, 25 workers)
1. **Keep-alive pins to one worker.** 3 GETs on one socket -> same PID. (test_pin.py)
2. **The 619 OOM is a bailout, not a crash** — the worker AND the keep-alive
   connection survive it. 6 rounds of (OOM + probe) on one socket -> same PID every
   time, Connection stays Keep-Alive. (test_multi.py) The earlier `Connection: close`
   was purely our `KeepAlive Off`, not the OOM.
3. **Prefork workers share ASLR.** libphp base (0x79255b3dd000) AND the Zend MM chunk
   (0x792559800000) are identical across all workers — children inherit the master's
   layout via fork. Verified via /proc across pids 1/27/36/44.

### The technique (ka_exploit.py)
- Run the whole chain over ONE keep-alive connection -> arm + leak hit the SAME
  worker deterministically, no spray, regardless of worker count.
- Because bases are shared across workers, leak ONCE, then fire each stage-3 attempt
  on a FRESH connection (fresh worker, clean heap) reusing the same HT/ZIF addresses.
  This sidesteps the heap-churn that made stage 3 miss on the pinned worker.

### Result — the demonstrable win
- ORIGINAL alvarodh5 (fresh Connection: close per request) on the 25-worker lab:
  **stage 1 heap leak FAILS** — arm and leak land on different workers.
- Our keep-alive ka_exploit.py on the same lab: **full in-band RCE, 3/3 runs, attempt 1,
  uid=33(www-data).**

That's the shippable contribution: the other PoCs assume a single worker (or neko's
spray-and-hope across all 150); keep-alive pinning + shared-ASLR reuse gives
deterministic multi-worker exploitation over a single connection. Honest caveat: a
reverse proxy / LB that pools backend connections can break the 1:1 connection->worker
mapping; there, sticky-session affinity helps reach one backend, and a keep-alive-batched
arm+fire pair is still better than naive spray. Not yet tested through a proxy.

Artifacts: lab/ (compose + conf), ka_exploit.py, test_pin.py, test_multi.py, spike_a2.pl.
