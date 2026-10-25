#!/usr/bin/env python3
"""Extractor for Lexmark-extended CramFS (GM2 firmware family).

Lexmark ships a CramFS variant with **16-byte inodes** instead of vanilla
cramfs's 12-byte ones, so that file size and data offset become full 32-bit
fields. They need this because a GM2 rootfs (~77 MB) is far larger than the
16 MB that vanilla cramfs allows (its size field is only 24 bits).

The superblock keeps the standard magic (0x28CD3D45) and "Compressed ROMFS"
signature, but the fsid block/file counters are zeroed -- which is why `file`,
7-Zip and util-linux `cramfsck` all report "0 files" and refuse to walk it.
This extractor ignores those counters and walks the inode tree from the root.

Extended inode layout (little-endian, 16 bytes), name[namelen*4] follows:

    w0: mode:16 | uid:16
    w1: (low 16 unused/gid) | namelen:16      # namelen in 4-byte units
    w2: size   (uint32)
    w3: offset (uint32)                        # offset*4 = byte position

File data uses the standard cramfs block scheme: ceil(size / BLOCK) uint32
block-end pointers at `offset`, followed by back-to-back zlib streams, each
decompressing to at most BLOCK bytes.

Usage:
    unpack_cramfs.py <image.cramfs> <output_dir>
"""

import os
import stat
import struct
import sys
import zlib

CRAMFS_MAGIC = 0x28CD3D45
BLOCK = 4096
ROOT_INODE_OFFSET = 0x40


def is_cramfs(data):
    return len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == CRAMFS_MAGIC


def _parse_inode(data, pos):
    w0, w1, w2, w3 = struct.unpack_from("<IIII", data, pos)
    mode = w0 & 0xFFFF
    uid = w0 >> 16
    namelen = (w1 >> 16) * 4
    size = w2
    offset = w3 * 4
    name = data[pos + 16 : pos + 16 + namelen].rstrip(b"\x00")
    return mode, uid, size, offset, name, 16 + namelen


def _read_file(data, offset, size):
    if size == 0:
        return b""
    nblocks = (size + BLOCK - 1) // BLOCK
    ptrs = struct.unpack_from("<%dI" % nblocks, data, offset)
    out = bytearray()
    prev = offset + nblocks * 4
    for end in ptrs:
        comp = data[prev:end]
        out += zlib.decompress(comp) if comp else b""
        prev = end
    return bytes(out[:size])


def _walk(data, child_off, dir_size, outdir, stats):
    pos, end = child_off, child_off + dir_size
    while pos < end:
        mode, _uid, size, offset, name, hlen = _parse_inode(data, pos)
        pos += hlen
        if not name or name in (b".", b".."):
            continue
        target = os.path.join(outdir, name.decode("utf8", "replace"))
        if stat.S_ISDIR(mode):
            os.makedirs(target, exist_ok=True)
            stats["dirs"] += 1
            if size:
                _walk(data, offset, size, target, stats)
        elif stat.S_ISLNK(mode):
            link = _read_file(data, offset, size).decode("utf8", "replace")
            try:
                if os.path.lexists(target):
                    os.unlink(target)
                os.symlink(link, target)
                stats["symlinks"] += 1
            except OSError:
                pass
        elif stat.S_ISREG(mode):
            if os.path.lexists(target):
                try:
                    os.chmod(target, 0o644)
                    os.unlink(target)
                except OSError:
                    pass
            with open(target, "wb") as f:
                f.write(_read_file(data, offset, size))
            stats["files"] += 1
        # device/fifo/socket nodes are intentionally skipped


def extract(image, outdir):
    """Extract a Lexmark-extended CramFS image into outdir.

    `image` may be a path or the raw bytes. Returns a stats dict.
    """
    data = image if isinstance(image, (bytes, bytearray)) else open(image, "rb").read()
    if not is_cramfs(data):
        raise ValueError("not a CramFS image (bad magic)")
    os.makedirs(outdir, exist_ok=True)
    _mode, _uid, size, offset, _name, _hlen = _parse_inode(data, ROOT_INODE_OFFSET)
    stats = {"files": 0, "dirs": 0, "symlinks": 0}
    _walk(data, offset, size, outdir, stats)
    return stats


def main(argv):
    if len(argv) != 3:
        print("usage: %s <image.cramfs> <output_dir>" % argv[0])
        return 1
    stats = extract(argv[1], argv[2])
    print(
        "> extracted %d files, %d dirs, %d symlinks into '%s'"
        % (stats["files"], stats["dirs"], stats["symlinks"], argv[2])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
