"""PAZ asset repacker for Crimson Desert.

Patches modified files back into PAZ archives. Handles encryption and
compression to produce output the game will accept.

Pipeline: modified file -> LZ4 compress -> ChaCha20 encrypt -> write to PAZ

Constraints:
  - Encrypted blob must be exactly comp_size bytes (original size in PAMT)
  - Decompressed output must be exactly orig_size bytes
  - PAMT files must never be modified (game integrity check)
  - NTFS timestamps on .paz files must be preserved

Usage:
    # Repack using PAMT metadata (recommended)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml"

    # Repack to a standalone file (for testing)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml" --output repacked.bin

Library usage:
    from paz_repack import repack_entry
    from paz_parse import parse_pamt

    entries = parse_pamt("0.pamt", paz_dir="./0003")
    entry = next(e for e in entries if "rendererconfiguration" in e.path)
    repack_entry("modified.xml", entry)
"""

import os
import sys
import struct
import ctypes
import argparse

import lz4.block

from paz_parse import parse_pamt, PazEntry
from paz_crypto import encrypt, lz4_compress


# ── Timestamp preservation (Windows) ────────────────────────────────

def _save_timestamps(path: str):
    """Capture NTFS timestamps. Returns a callable to restore them."""
    if sys.platform != 'win32':
        return lambda: None

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

    OPEN_EXISTING = 3
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_ATTR = 0x80 | 0x02000000  # NORMAL | BACKUP_SEMANTICS

    h = kernel32.CreateFileW(path, GENERIC_READ, 1, None, OPEN_EXISTING, FILE_ATTR, None)
    if h == -1:
        return lambda: None

    ct, at, mt = FILETIME(), FILETIME(), FILETIME()
    kernel32.GetFileTime(h, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
    kernel32.CloseHandle(h)

    def restore():
        h2 = kernel32.CreateFileW(path, GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTR, None)
        if h2 != -1:
            kernel32.SetFileTime(h2, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
            kernel32.CloseHandle(h2)

    return restore


# ── Size matching ────────────────────────────────────────────────────

def _pad_to_orig_size(data: bytes, orig_size: int) -> bytes:
    """Pad data to exactly orig_size bytes with zero bytes."""
    if len(data) >= orig_size:
        return data[:orig_size]
    return data + b'\x00' * (orig_size - len(data))


def _match_compressed_size(plaintext: bytes, target_comp_size: int,
                           target_orig_size: int) -> bytes:
    """Adjust plaintext so it compresses to exactly target_comp_size.

    For XML files, inserts padding elements and tunes compressibility.
    For non-XML, pads with zeros and hopes for the best.

    Returns:
        adjusted plaintext (exactly target_orig_size bytes)

    Raises:
        ValueError if size matching fails
    """
    # Pad to orig_size first
    padded = _pad_to_orig_size(plaintext, target_orig_size)

    comp = lz4.block.compress(padded, store_size=False)
    if len(comp) == target_comp_size:
        return padded

    # If under target, reduce compressibility by replacing trailing zeros
    # with incompressible bytes
    filler = bytes(range(33, 127))  # printable ASCII

    if len(comp) < target_comp_size:
        # Replace trailing bytes with incompressible content
        # Binary search for the right amount
        lo, hi = 0, target_orig_size - len(plaintext)
        best = padded
        for _ in range(64):
            mid = (lo + hi) // 2
            if mid <= 0:
                break
            fill = (filler * (mid // len(filler) + 1))[:mid]
            trial = plaintext + fill
            trial = _pad_to_orig_size(trial, target_orig_size)
            c = lz4.block.compress(trial, store_size=False)
            if len(c) == target_comp_size:
                return trial
            elif len(c) < target_comp_size:
                lo = mid + 1
                best = trial
            else:
                hi = mid - 1

        # Linear scan near the boundary
        for n in range(max(0, lo - 5), min(hi + 5, target_orig_size - len(plaintext))):
            fill = (filler * (n // len(filler) + 1))[:n] if n > 0 else b''
            trial = plaintext + fill
            trial = _pad_to_orig_size(trial, target_orig_size)
            c = lz4.block.compress(trial, store_size=False)
            if len(c) == target_comp_size:
                return trial

    if len(comp) > target_comp_size:
        raise ValueError(
            f"Compressed size {len(comp)} exceeds target {target_comp_size}. "
            f"Reduce file content.")

    raise ValueError(
        f"Cannot match target comp_size {target_comp_size} "
        f"(best: {len(lz4.block.compress(padded, store_size=False))})")


# ── Core repack ──────────────────────────────────────────────────────

def repack_entry(modified_path: str, entry: PazEntry,
                 output_path: str = None, dry_run: bool = False) -> dict:
    """Repack a modified file and patch it into the PAZ archive.

    Args:
        modified_path: path to the modified plaintext file
        entry: PAMT entry for the file being replaced
        output_path: if set, write to this file instead of patching the PAZ
        dry_run: if True, compute sizes but don't write anything

    Returns:
        dict with repack stats
    """
    with open(modified_path, 'rb') as f:
        plaintext = f.read()

    basename = os.path.basename(entry.path)
    is_compressed = entry.compressed and entry.compression_type == 2

    if is_compressed:
        # Need to match both orig_size and comp_size exactly
        adjusted = _match_compressed_size(plaintext, entry.comp_size, entry.orig_size)
        compressed = lz4.block.compress(adjusted, store_size=False)
        assert len(compressed) == entry.comp_size, \
            f"Size mismatch: {len(compressed)} != {entry.comp_size}"
        payload = compressed
    else:
        # Uncompressed: pad/truncate to comp_size, zero-pad remainder
        if len(plaintext) > entry.comp_size:
            raise ValueError(
                f"Modified file ({len(plaintext)} bytes) exceeds budget "
                f"({entry.comp_size} bytes). Reduce content.")
        payload = plaintext + b'\x00' * (entry.comp_size - len(plaintext))

    # Encrypt if it's an XML file
    if entry.encrypted:
        payload = encrypt(payload, basename)

    result = {
        "entry_path": entry.path,
        "modified_size": len(plaintext),
        "comp_size": entry.comp_size,
        "orig_size": entry.orig_size,
        "compressed": is_compressed,
        "encrypted": entry.encrypted,
    }

    if dry_run:
        result["action"] = "dry_run"
        return result

    if output_path:
        # Write to standalone file
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(payload)
        result["action"] = "written"
        result["output"] = output_path
    else:
        # Patch directly into PAZ archive
        restore_ts = _save_timestamps(entry.paz_file)

        with open(entry.paz_file, 'r+b') as f:
            f.seek(entry.offset)
            f.write(payload)

        restore_ts()
        result["action"] = "patched"
        result["paz_file"] = entry.paz_file
        result["offset"] = f"0x{entry.offset:08X}"

    return result


# ── CLI ──────────────────────────────────────────────────────────────

def find_entry(entries: list[PazEntry], entry_path: str) -> PazEntry:
    """Find a PAMT entry by path (case-insensitive, partial match)."""
    entry_path = entry_path.lower().replace('\\', '/')

    # Exact match first
    for e in entries:
        if e.path.lower().replace('\\', '/') == entry_path:
            return e

    # Partial match (basename or suffix)
    matches = [e for e in entries if entry_path in e.path.lower().replace('\\', '/')]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"Ambiguous entry path '{entry_path}', matches:", file=sys.stderr)
        for m in matches[:10]:
            print(f"  {m.path}", file=sys.stderr)
        if len(matches) > 10:
            print(f"  ... ({len(matches) - 10} more)", file=sys.stderr)
        sys.exit(1)

    print(f"Entry not found: '{entry_path}'", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Repack a modified file into a PAZ archive",
        epilog="Example: python paz_repack.py modified.xml --pamt 0.pamt "
               "--paz-dir ./0003 --entry technique/rendererconfiguration.xml")
    parser.add_argument("modified", help="Path to modified file")
    parser.add_argument("--pamt", required=True, help="Path to .pamt index file")
    parser.add_argument("--paz-dir", help="Directory containing .paz files")
    parser.add_argument("--entry", required=True,
                        help="Entry path within the archive (or partial match)")
    parser.add_argument("--output", help="Write to file instead of patching PAZ")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without writing")
    args = parser.parse_args()

    entries = parse_pamt(args.pamt, paz_dir=args.paz_dir)
    entry = find_entry(entries, args.entry)

    print(f"Entry:      {entry.path}")
    print(f"PAZ:        {entry.paz_file} @ 0x{entry.offset:08X}")
    print(f"comp_size:  {entry.comp_size:,}")
    print(f"orig_size:  {entry.orig_size:,}")
    print(f"Compressed: {'LZ4' if entry.compressed else 'no'}")
    print(f"Encrypted:  {'yes' if entry.encrypted else 'no'}")
    print()

    try:
        result = repack_entry(args.modified, entry,
                              output_path=args.output,
                              dry_run=args.dry_run)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if result["action"] == "dry_run":
        print("Dry run — no changes made.")
    elif result["action"] == "written":
        print(f"Written to {result['output']}")
    elif result["action"] == "patched":
        print(f"Patched {result['paz_file']} at {result['offset']}")

    print(f"Modified file: {result['modified_size']:,} bytes")


if __name__ == "__main__":
    main()
