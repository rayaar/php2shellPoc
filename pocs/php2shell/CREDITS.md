# CREDITS

## Chain-E (FPM) — ported from dinosn

The `ExploitFPM` class and all `ce_*` helpers in `php2shell.py` are a surgical
port of the Chain-E implementation from:

  https://github.com/dinosn/php-cve-2026-10961x-lab-poc  (MIT, 2026)
  specifically `tools/e2e/p2s/chaine.py`

What was ported:
- `CE_FAMILIES` offset table for PHP 8.4.26, 8.5.11, 8.5.12
- `/proc/<pid>/maps` parsing (php-fpm image / libc / Zend MM chunk)
- `poison_value()` fake-struct builder (used_slots arithmetic for the write
  primitive via `var_tmp_var`)
- `arm` / `equalise` / `consume` stage logic
- Byte-exact dispatch head/body shape (no User-Agent/Accept, 26-char SID)

What was NOT ported (dinosn's framework has them; we don't need them in a
single-file tool):
- `ce_plan` / routing / verdict machinery
- `calibrate` / `precheck` phase chaining
- WAF / LiteSpeed / CGI / chunked-refusal detection
- Ledger / audit infrastructure
- Signed delta family support

Use `--fpm` + the `--fpm-*` flags to invoke Chain-E. See `php2shell.py --help`.

For the full framework (calibration, routing, patch detection, FPM growth
producer, PHP 7.2 chain, etc.), use dinosn's upstream tool:

  python3 tools/e2e/php2shell_e2e.py --phase all --target ... --authorized

## Nested-array OOM arm — ported from MartinPham

`Exploit._oom_nested()` + the `--arm nested` CLI mode is a port of the
nested-array OOM technique from:

  https://github.com/MartinPham/php2shell-poc  (unlicensed; attribution)
  specifically `poc.py:leak_producer` (producer shape with depth=57 × count=950)

The technique uses deeply-nested multipart field names (`f[i][x][x]...` × 57
levels × 950 iterations) to blow memory_limit via PHP's $_POST nested-array
construction instead of a single large field. ~250 KiB on the wire, ~5 MiB
heap. Useful when `--arm bigfield` is blocked by `post_max_size`-enforcing
proxies or 413 responses.

What was NOT ported: MartinPham's auto-calibration via Docker image analysis
(our dynamic htdata derivation covers the same need against targets you
cannot `docker pull`), his pipelined-consumers race-based worker poisoning
(our fully-sprayed chain handles multi-worker reliably), his specific
targeting of `php -S` CLI dev server (niche target, not a common pentest
surface).

## mod_php chain lineage

The core mod_php chain (stage1 heap leak + stage2 libphp leak + stage3 fake
HashTable with `pDestructor = zif_system`) is attributable to:
- @alvarodh5 (https://github.com/alvarodh5/php2shell) — original research
- @9bie / @dinosn — iterated grooming and reclaim techniques
- @3em0 — supporting lab + exploit chain
- neko (https://git.kurosek.com/neko/php2shell) — authoritative 5-layer fix map

Our contributions over the public chain:
- Multi-worker reliability (keep-alive pinning + fully-sprayed chain, 82/82)
- Adaptive OOM sizing (8MB floor + growth)
- Dynamic htdata derivation from stage1 leak (`derive_htdata`)
- `--probe-only` behavioral vulnerability probe
- `--force` backport-patched detection bypass
- `--stage2` short-domain bootstrap for arbitrary payloads
- Operator diagnostics (classified failure reasons)
- IPv6/SNI/default-port cleanup

## Research framing

- sveoti.net ("millions of attempts, no confirmed break-in", 2026-10-23) —
  external validation of the "memory-corruption-to-shell is genuinely hard"
  thesis our engineering decisions were made against
- Kevin J. @ Baldur Security — public CTF challenge framing the exact
  "exploitable by default against an unknown target?" research question

## License

Our additions: unspecified (operator decides at release).
dinosn's ported code (chaine.py-derived): MIT (preserved).
