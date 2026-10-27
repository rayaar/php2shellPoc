# 8.3.36 Patch Cross-Check vs. Neko's 5-Layer Fix Map

Verified 2026-10-27 by direct diff of `php-8.3.35` vs. `php-8.3.36` source
trees (official tarballs from www.php.net/distributions). Neko's claim
(`pocs/neko-php2shell/README.md` lines 160-205) is that PHP 8.3.36
adds **five independent defense layers** to kill the CVE-2026-109618/
109619 chain. All five are present in the actual patch and match the
mechanisms described.

## Layer 1 — `php_rinit_session_globals()` at `MULTIPART_EVENT_START`

**Claim**: new call at the very start of multipart parsing, zeroes
`PS(id)`, `PS(session_status)`, and `PS(send_cookie)`.

**Verified**: `ext/session/session.c`
- 8.3.35: single call site at line 2781 (`PHP_RINIT_FUNCTION(session)`).
- 8.3.36: single call at line 2803 (same) + **new** call inside
  `case MULTIPART_EVENT_START:` branch at line 3153.

Any one of layers 1–3 alone kills the chain; this is the simplest.

## Layer 2 — Delayed OOM (`zend_mm_safe_error` → `zend_mm_delayed_verror`)

**Claim**: OOM no longer `longjmp`s; soft limit records the error and
sets `vm_interrupt`, hard limit (default 200 % of `memory_limit`) calls
`_exit(137)`. No `longjmp` means all cleanup runs normally.

**Verified**: `Zend/zend_alloc.c`
- 8.3.35: `zend_mm_safe_error` is `ZEND_COLD ZEND_NORETURN` (line 371),
  calls `zend_bailout()` (line 394). 15 call sites in various emalloc
  paths.
- 8.3.36: `zend_mm_safe_error` **completely removed** (0 refs). Replaced
  by `zend_mm_delayed_verror` (new, line 385) which only records to
  `EG(delayed_oom)` and sets `EG(vm_interrupt)`. Hard-limit path calls
  `_exit(137)` (line 495), skipping C++-style unwinding entirely.

## Layer 3 — `post_max_size` enforcement in `multipart_buffer_fill()`

**Claim**: new check against `SG(read_post_bytes)` regardless of
Transfer-Encoding; blocks the chunked-TE `post_max_size` bypass.

**Verified**: `main/rfc1867.c`
- 8.3.35: `multipart_buffer_fill` has NO per-chunk size enforcement;
  only the Content-Length pre-check at line 684 bounds POST size.
- 8.3.36: **new** check at line 226:
  ```c
  if (SG(post_max_size) > 0 && SG(read_post_bytes) > SG(post_max_size)) {
      // reject
  }
  ```
  Runs inside the chunk-filling loop, so chunked encoding is also
  bounded.

## Layer 4 — `php_basic_early_rinit()`

**Claim**: called from `php_request_startup()` BEFORE `sapi_activate()`;
zeros `BG(serialize_lock)`, `BG(serialize)`, and `BG(unserialize)`,
eliminating the layer-4 stale-serialize window.

**Verified**:
- 8.3.35: no symbol `php_basic_early_rinit` anywhere.
- 8.3.36:
  - `ext/standard/basic_functions.c:482`: `PHPAPI void php_basic_early_rinit(void)` definition.
  - `main/main.c:1829`: `php_basic_early_rinit();` called from
    `php_request_startup()`, **before** `sapi_activate()`.

This is the layer our empirical layer-4 primitive research targets
(see `README.md` → "Layer-4 primitive" section).

## Layer 5 — Session deserialization hardening

**Claim**: three sub-items — (a) RFC1867 session decode in
`incomplete_classes_only` mode, (b) `$_SESSION` deleted at
`MULTIPART_EVENT_END`, (c) `PG(modules_activated)` guard against
`request_parse_body()` corrupting session state.

**Verified**: `ext/session/session.c`
- 8.3.35: 0 refs to `incomplete_classes_only`. $_SESSION not deleted
  at END. No modules_activated guard around request_parse_body.
- 8.3.36:
  - Line 879: `php_var_unserialize_set_incomplete_classes_only(*var_hash, true)`
  - Line 887: `php_var_serialize_set_incomplete_classes_only(*var_hash, true)`
  - Lines 3313-3315 (in `MULTIPART_EVENT_END`):
    `zend_string *session_var_name = ZSTR_INIT_LITERAL("_SESSION", 0);
     zend_delete_global_variable(session_var_name);
     zend_string_release_ex(session_var_name, 0);`
  - Lines 3141-3142: `if (PG(modules_activated)) { /* request_parse_body().
    Do not run here as it corrupts the session. */ ... }` — new guard
    added, documenting the known request_parse_body corruption path.

## Summary

| Layer | Mechanism | 8.3.35 | 8.3.36 | Verdict |
|---|---|---|---|---|
| 1 | `php_rinit_session_globals()` at `MULTIPART_EVENT_START` | ✗ | ✓ (line 3153) | **CONFIRMED** |
| 2 | Delayed OOM (no `longjmp`, `_exit(137)` on hard limit) | `zend_mm_safe_error` × 15 | 0 refs, new `zend_mm_delayed_verror` | **CONFIRMED** |
| 3 | `post_max_size` check in `multipart_buffer_fill` | ✗ | ✓ (line 226) | **CONFIRMED** |
| 4 | `php_basic_early_rinit()` before `sapi_activate` | ✗ | ✓ (basic_functions.c:482 + main.c:1829) | **CONFIRMED** |
| 5 | `incomplete_classes_only` + `$_SESSION` delete + `modules_activated` guard | ✗ | ✓ (3 sub-items present) | **CONFIRMED** |

Neko's reverse-engineering of the 8.3.36 patch is accurate.

## Why it matters

- **Defense-in-depth is real**: layers 1-3 each kill the chain
  independently; layers 4-5 close additional primitive classes
  (layer-4 BG dangling, layer-5 request_parse_body session corruption).
- **The layer-4 bug class is distinct from the main-chain `PS(id)`
  dangling** that layer 1 fixes. Our own research (see
  `php2shell_layer4_primitive.md` memory + README's layer-4 section)
  confirms the primitive is reachable in 8.3.35 and demonstrates the
  parse-time write path.
- **Backporting status**: the official fix bundles all five layers.
  Downstream builds (Debian, RHEL, Alpine, distro-rebuilt packages)
  with cherry-picked subsets could leave specific primitive classes
  reachable. The `--force` flag in our php2shell tool tests this
  empirically; the exploit-is-blocked signal detects whether layers
  1-3 are in place, not individual sub-layers.
