#!/usr/bin/env python3
"""Add or overwrite the Execution Info (title ID) header in an Xbox 360 XEX2 file.

Usage: python3 xex_set_titleid.py <in.xex> <out.xex> <TITLEID hex> [MEDIAID hex]
"""
import hashlib
import struct
import sys

EXEC_INFO = 0x00040006


def fix_header_hash(d):
    """Recompute the XEX2 header digest stored in the security info.

    digest = SHA1(xex[secinfo+0x17C : pe_offset] + xex[0 : secinfo+8])
    """
    pe_off, sec_off = struct.unpack('>I4xI', d[8:20])
    digest = hashlib.sha1(bytes(d[sec_off + 0x17C:pe_off]) + bytes(d[:sec_off + 8])).digest()
    d[sec_off + 0x164:sec_off + 0x178] = digest


def header_size(key, d, val):
    lo = key & 0xFF
    if lo in (0x00, 0x01):
        return 0  # value is inline in the directory
    if lo == 0xFF:
        return struct.unpack('>I', d[val:val + 4])[0]
    return lo * 4


def main():
    src, dst, tid = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    media = int(sys.argv[4], 16) if len(sys.argv) > 4 else tid ^ 0x5A5A5A5A
    d = bytearray(open(src, 'rb').read())
    if d[:4] != b'XEX2':
        sys.exit("not an XEX2 file")
    pe_off, sec_off, count = struct.unpack('>I4xII', d[8:24])
    sec_size = struct.unpack('>I', d[sec_off:sec_off + 4])[0]
    entries = [struct.unpack('>II', d[24 + i * 8:32 + i * 8]) for i in range(count)]

    for k, v in entries:
        if k == EXEC_INFO:  # already has one: just overwrite the title ID
            struct.pack_into('>I', d, v + 12, tid)
            fix_header_hash(d)
            open(dst, 'wb').write(d)
            print(f"overwrote title ID -> {tid:08X}")
            return

    # find 24 free (zero, unused) bytes for the new header data
    used = [(sec_off, sec_off + sec_size)]
    for k, v in entries:
        n = header_size(k, d, v)
        if n:
            used.append((v, v + n))
    start = (sec_off + sec_size + 3) & ~3
    blob = None
    for off in range(start, pe_off - 24, 4):
        if all(not (a < off + 24 and off < b) for a, b in used) and not any(d[off:off + 24]):
            blob = off
            break
    if blob is None:
        sys.exit("no free header space")

    # directory must fit before the security info block
    if 24 + (count + 1) * 8 > sec_off or any(d[24 + count * 8:32 + count * 8]):
        sys.exit("no room in optional header directory")

    exec_info = struct.pack('>IIII4BI', media, 0, 0, tid, 0, 0, 1, 1, 0)
    d[blob:blob + 24] = exec_info
    entries.append((EXEC_INFO, blob))
    entries.sort()
    for i, (k, v) in enumerate(entries):
        struct.pack_into('>II', d, 24 + i * 8, k, v)
    struct.pack_into('>I', d, 20, count + 1)
    fix_header_hash(d)
    open(dst, 'wb').write(d)
    print(f"added Execution Info at 0x{blob:X}: TitleID {tid:08X}, MediaID {media:08X}")


if __name__ == '__main__':
    main()
