"""dog fetchdbg — fetch and apply debug symbols for a glibc from libc6-dbg."""

import os
import shutil
import subprocess
import sys
import tempfile


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "fetchdbg",
        help="Fetch and apply glibc debug symbols from libc6-dbg",
        description=(
            "Reads the glibc version string and build ID from LIBC, downloads "
            "the matching libc6-dbg .deb from Ubuntu/Debian package mirrors "
            "(with main → security → snapshot.debian.org fallback for Debian), "
            "and applies the debug symbols in-place using eu-unstrip.  When "
            "--ld is given, also applies debug symbols to the linker from the "
            "same .deb (single download)."
        ),
    )
    p.add_argument("libc", metavar="LIBC", help="Path to the libc shared library")
    p.add_argument(
        "--ld", metavar="LD",
        help="Path to the ld linker (debug symbols applied from the same deb)",
    )
    p.add_argument(
        "-f", "--force",
        action="store_true",
        help="Apply debug symbols even if the file already has .debug_info",
    )
    p.set_defaults(func=main)


def _has_debug_info(path: str) -> bool:
    try:
        out = subprocess.check_output(
            ["readelf", "-S", path], stderr=subprocess.DEVNULL, text=True,
        )
        return ".debug_info" in out
    except Exception:
        return False


def _read_build_id(path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["readelf", "-n", path], stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            if "Build ID:" in line:
                return line.split("Build ID:")[-1].strip()
    except Exception:
        pass
    return None


def _apply_debug(target_path: str, debug_path: str, label: str) -> bool:
    """Run eu-unstrip to merge debug symbols into *target_path*.

    Returns True on success.
    """
    tmp_out = target_path + ".fetchdbg.tmp"
    try:
        proc = subprocess.run(
            ["eu-unstrip", "-o", tmp_out, target_path, debug_path],
            capture_output=True,
        )
        if proc.returncode == 0 and os.path.exists(tmp_out):
            os.replace(tmp_out, target_path)
            print(
                f"[+] Debug symbols applied to {label} '{target_path}'.",
                file=sys.stderr,
            )
            return True
        else:
            print(
                f"[-] eu-unstrip failed for {label}: "
                f"{proc.stderr.decode(errors='replace')}",
                file=sys.stderr,
            )
            return False
    except FileNotFoundError:
        print(
            "[-] eu-unstrip not found; please install elfutils.",
            file=sys.stderr,
        )
        return False
    finally:
        if os.path.exists(tmp_out):
            os.unlink(tmp_out)


def main(args) -> None:
    from doglib.dumpelf._libc import (
        elf_deb_arch,
        fetch_debug_by_version,
        find_version_string,
    )

    libc_path = os.path.realpath(args.libc)
    if not os.path.isfile(libc_path):
        print(f"[-] File not found: {libc_path}", file=sys.stderr)
        sys.exit(1)

    ld_path = os.path.realpath(args.ld) if args.ld else None
    if ld_path and not os.path.isfile(ld_path):
        print(f"[-] File not found: {ld_path}", file=sys.stderr)
        sys.exit(1)

    libc_needs_dbg = args.force or not _has_debug_info(libc_path)
    ld_needs_dbg = ld_path and (args.force or not _has_debug_info(ld_path))

    if not libc_needs_dbg and not ld_needs_dbg:
        print(
            "[+] All files already have debug symbols. "
            "Skipping. (use --force to override)",
            file=sys.stderr,
        )
        sys.exit(0)

    try:
        data = open(libc_path, "rb").read()
    except OSError as e:
        print(f"[-] Cannot read {libc_path}: {e}", file=sys.stderr)
        sys.exit(1)

    result = find_version_string(data)
    if result is None:
        print(
            f"[-] No Ubuntu/Debian glibc version string found in {libc_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    version, distro = result
    arch = elf_deb_arch(libc_path)

    libc_build_id = _read_build_id(libc_path) if libc_needs_dbg else None
    ld_build_id = _read_build_id(ld_path) if ld_needs_dbg else None

    debug = fetch_debug_by_version(
        version, distro, arch=arch,
        build_id=libc_build_id,
        ld_build_id=ld_build_id,
    )

    ok = True
    try:
        if libc_needs_dbg:
            if debug["libc"]:
                if not _apply_debug(libc_path, debug["libc"], "libc"):
                    ok = False
            else:
                print(
                    f"[-] Could not find libc debug symbols in libc6-dbg deb.",
                    file=sys.stderr,
                )
                ok = False

        if ld_needs_dbg:
            if debug["ld"]:
                if not _apply_debug(ld_path, debug["ld"], "ld"):
                    ok = False
            else:
                print(
                    f"[-] Could not find ld debug symbols in libc6-dbg deb.",
                    file=sys.stderr,
                )
                ok = False
    finally:
        for p in (debug.get("libc"), debug.get("ld")):
            if p and os.path.exists(p):
                tmp_dir = os.path.dirname(p)
                if os.path.commonpath(
                    [tmp_dir, tempfile.gettempdir()]
                ) == tempfile.gettempdir():
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    break

    if not ok:
        sys.exit(1)
