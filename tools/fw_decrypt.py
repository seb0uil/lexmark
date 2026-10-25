#!/usr/bin/env python3

import sys
import os
import struct
import binascii
from Crypto.Cipher import AES

DEFAULT_KEY_INDEX = 2
RSA_BLOCKSIZE = 256
AES_BLOCKSIZE = 0x10
AES_CHUNKSIZE = 0x800000
MAIN_MAGIC = 0x7C42494E
TAG_DATA = 0xFFAA00C7
CRAMFS_MAGIC = 0x28CD3D45

from keys import KEYS

try:
    import unpack_cramfs
except ImportError:
    unpack_cramfs = None

# Legacy (pre-GM2) content index -> name map, used by the flat-TLV code path.
CONTENT_ID_MAP = {
    1: "uboot",
    2: "initramfs",
    3: "rootfs",
    4: "license",
    15: "scannerfs",
}

# GM2 firmwares reuse the indices differently. Only names verified by
# inspecting the extracted contents of LW80.GM2.P266 are listed here; any
# other index falls back to a bare number in the output filename.
GM2_CONTENT_ID_MAP = {
    0: "eula",      # plain-text license agreement
    2: "boot",      # kernel uImage + uInitramfs + sub-MCU programs
    3: "rootfs",    # main Linux root filesystem
    4: "rootfs2",   # secondary rootfs (own bin/lib/etc/sbin/web)
}


class LexmarkFirmwareUnpacker:
    def __init__(self, filename):
        if not os.path.exists(filename):
            self.err("could not open file '%s'" % filename)
        self.filename = filename
        self.fh = open(self.filename, "rb")
        self.parse_pjl_header()

        self.sections = [
            {
                "name": "flasher",
                "size": self.pjl_properties["KERNELCOUNT"],
                "pos": 0,
            },
            {
                "name": "main",
                "size": self.pjl_properties["TYPECOUNT"],
                "pos": 0,
            },
            {
                "name": "fksign",
                "size": self.pjl_properties["FKSIGNSZ"],
                "pos": 0,
            },
        ]

        pos = self.fh.tell()
        for i in range(len(self.sections)):
            self.sections[i]["pos"] = pos
            pos += self.sections[i]["size"]

    def err(self, s):
        print("ERROR: %s" % s)
        exit(0)

    def info(self, s):
        print("INFO: %s" % s)

    def section(self, name):
        for i in range(len(self.sections)):
            if self.sections[i]["name"] == name:
                return self.sections[i]
        return None

    def unpad(self, blob):
        if blob[0] != 0x01:
            self.err("invalid PKCS start byte (0x%02x)" % blob[0])
        pos = 1
        while blob[pos] == 0xFF:
            pos = pos + 1
        if blob[pos] != 0x00:
            self.err("invalid PKCS end byte (0x%02x)" % blob[pos])
        return blob[pos + 1 :]

    def rsa(self, ctext, key_idx) -> bytes:
        # pow(block1, rsa_exp, rsa_mod)
        if len(ctext) != RSA_BLOCKSIZE:
            self.err("rsa block is wrong size (%d)" % len(ctext))
        ctext_int = 0
        for i in range(RSA_BLOCKSIZE):
            ctext_int <<= 8
            ctext_int |= ctext[i]

        dtext_int = pow(ctext_int, KEYS[key_idx]["exp"], KEYS[key_idx]["mod"])
        o = b""

        for i in range(RSA_BLOCKSIZE - 1):
            v = (dtext_int >> ((RSA_BLOCKSIZE - 2 - i) * 8)) & 0xFF
            o += bytes([v])
        return o

    def parse_pjl_header(self):
        a = self.fh.readline()
        if a != b"\x1b%-12345X@PJL \n":
            self.err("invalid header line")

        # Les firmwares récents intercalent un gros bloc de licence en
        # "@PJL COMMENT" avant le LPROGRAMRIP. On saute ces lignes jusqu'à
        # tomber sur la vraie instruction. readline() laisse le file handle
        # pile au début du binaire, donc les offsets de section restent bons.
        while True:
            line = self.fh.readline()
            if not line.startswith(b"@PJL"):
                self.err("unexpected line in PJL header: %r" % line[:40])
            tokens = line.split()
            instr = tokens[1].decode("utf8") if len(tokens) > 1 else ""
            if instr == "COMMENT":
                continue
            if instr != "LPROGRAMRIP":
                self.err("unexpected pjl instruction '%s'" % instr)
            pjl_line_b = line.decode("utf8")
            break

        parts = pjl_line_b.split(" ")
        self.pjl_properties = {}
        for i in range(2, len(parts)):
            name, value = parts[i].split("=", 1)
            if value.startswith('"'):
                self.pjl_properties[name] = value[1 : len(value) - 1]
            else:
                # Certaines proprietes sont des chaines non quotees (ex. TYPE=MAIN).
                # On tente l'entier, sinon on garde la chaine telle quelle.
                try:
                    self.pjl_properties[name] = int(value, 0)
                except ValueError:
                    self.pjl_properties[name] = value

    def dword_at(self, blob, pos):
        return struct.unpack("<L", blob[pos : pos + 4])[0]

    def build_iv(self, v):
        o = [v[i] for i in range(16)]
        o[0] ^= 0x49
        for i in range(1, 16):
            o[i] ^= o[i - 1]
        return bytes(o)

    def decrypt_section(self, section_name, output_filename):
        self.fh.seek(self.section(section_name)["pos"])

        section_hdr = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        section_hdr += self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))

        if len(section_hdr) != 296:
            self.err(
                "decrypted section header size mismatch! (%d vs %d)"
                % (len(section_hdr), 296)
            )

        self.sig_size = self.dword_at(section_hdr, 0xC)
        self.aes_key_size = self.dword_at(section_hdr, 0x118)
        self.aes_key_byte_size = self.dword_at(section_hdr, 0x11C)
        self.aes_mode = self.dword_at(section_hdr, 0x120)
        self.data_size = self.dword_at(section_hdr, 0x124)

        print("> section header:")
        print("  - decrypted signature size : 0x%08x" % self.sig_size)
        print("  - decrypted aes key size   : 0x%08x" % self.aes_key_size)
        print("  - aes key byte size        : 0x%08x" % self.aes_key_byte_size)
        print("  - aes mode                 : 0x%08x" % self.aes_mode)
        print("  - decrypted data size      : 0x%08x" % self.data_size)
        print("")

        signature = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(signature) != self.sig_size:
            self.err("signature has invalid length!")

        print("> signature : %s" % binascii.hexlify(signature).decode("utf8"))

        aes_key = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(aes_key) != self.aes_key_byte_size:
            self.err("aes key has invalid length!")

        print("> AES key   : %s" % binascii.hexlify(aes_key).decode("utf8"))

        iv = self.build_iv(aes_key)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        fo = open(output_filename, "wb")

        left = self.data_size
        sys.stdout.write("> unpacking section '%s': " % section_name)
        sys.stdout.flush()
        while left > 0:
            sys.stdout.write(".")
            sys.stdout.flush()
            chunk_size = AES_CHUNKSIZE
            if chunk_size > left:
                chunk_size = left
            pt = cipher.decrypt(self.fh.read(chunk_size))
            fo.write(pt)
            left -= chunk_size

        fo.close()
        print(" done!\n")

    @staticmethod
    def _content_type(blob):
        # Best-effort type tag used only for self-documenting filenames.
        if len(blob) >= 4:
            if struct.unpack("<L", blob[:4])[0] == CRAMFS_MAGIC:
                return "cramfs"
            if blob[:4] == b"\xab\xcd\xef\xab":
                return "zlib"
            if blob[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
                return "zlib"
        try:
            blob[:512].decode("ascii")
            return "text"
        except UnicodeDecodeError:
            return "bin"

    def unpack_main(self, inputfile, outputdir):
        d = open(inputfile, "rb").read()

        magic, file_size = struct.unpack(">LL", d[0:8])
        assert magic == MAIN_MAGIC
        assert file_size <= len(d)

        # Two container layouts exist. GM2-era firmwares (e.g. LW80.GM2.P266)
        # prefix the content directory with FFAA00xx opcodes and store each
        # entry as `FFAA00C7 <index:u32be> <size:u32be> <data[size]>`. Older
        # firmwares use the flat tag/size stream handled by the legacy path.
        if d[8:11] == b"\xff\xaa\x00":
            return self._unpack_main_gm2(d, file_size, outputdir)
        return self._unpack_main_legacy(d, file_size, outputdir)

    def _unpack_main_gm2(self, d, file_size, outputdir):
        marker = struct.pack(">L", TAG_DATA)  # FFAA00C7
        pos = d.find(marker, 0, file_size)
        if pos < 0:
            self.err("no content entries (FFAA00C7) found in 'main' section")

        while pos + 12 <= file_size and d[pos : pos + 4] == marker:
            index, size = struct.unpack(">LL", d[pos + 4 : pos + 12])
            start = pos + 12
            data = d[start : start + size]
            ctype = self._content_type(data)
            name = GM2_CONTENT_ID_MAP.get(index)
            label = "%02d_%s" % (index, name) if name else "%02d" % index
            ofn = os.path.join(outputdir, "content_%s_%s.bin" % (label, ctype))
            with open(ofn, "wb") as f:
                f.write(data)
            print(
                "> content idx %2d  size 0x%08x  type %-6s -> %s"
                % (index, size, ctype, os.path.basename(ofn))
            )
            pos = start + size

    def _unpack_main_legacy(self, d, file_size, outputdir):
        pos = 8
        n = 0
        while pos < file_size:
            tag, size = struct.unpack(">LL", d[pos : pos + 8])
            if tag == 0:
                break

            pos += 8

            data = d[pos : pos + size]

            if size > 0 and tag != TAG_DATA:
                with open(
                    os.path.join(outputdir, "%02d_%08X.bin" % (n, tag)), "wb"
                ) as f:
                    f.write(data)
            elif tag == TAG_DATA:
                content_index, content_size = struct.unpack(">LL", data[0:8])

                assert content_index in CONTENT_ID_MAP
                assert content_size == size - 8
                content_name = CONTENT_ID_MAP[content_index]
                ofn = os.path.join(outputdir, "content_%s.bin" % content_name)
                with open(ofn, "wb") as f:
                    f.write(data[8:])
                print("> saved content '%s' to '%s'" % (content_name, ofn))

            n += 1
            pos += size


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: %s <firmware.fls> <output_dir>" % sys.argv[0])
        exit(0)

    firmware_file, output_dir = sys.argv[1:]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    lfd = LexmarkFirmwareUnpacker(firmware_file)
    # unpack all raw sections
    for section in lfd.sections:
        if section["name"] in ["flasher", "main"]:
            lfd.decrypt_section(
                section["name"],
                os.path.join(output_dir, "section_" + section["name"] + ".bin"),
            )

    if not os.path.exists(os.path.join(output_dir, "main")):
        os.makedirs(os.path.join(output_dir, "main"))

    main_dir = os.path.join(output_dir, "main")
    lfd.unpack_main(os.path.join(output_dir, "section_main.bin"), main_dir)

    # Auto-extract any CramFS content blobs into main/fs_<idx>/.
    if unpack_cramfs is not None:
        for fn in sorted(os.listdir(main_dir)):
            if not (fn.startswith("content_") and fn.endswith("_cramfs.bin")):
                continue
            idx = fn.split("_", 2)[1]
            dest = os.path.join(main_dir, "fs_" + idx)
            try:
                stats = unpack_cramfs.extract(os.path.join(main_dir, fn), dest)
                print(
                    "> extracted %s: %d files, %d dirs, %d symlinks -> %s"
                    % (fn, stats["files"], stats["dirs"], stats["symlinks"], dest)
                )
            except Exception as e:  # noqa: BLE001 - keep going on a bad blob
                print("> WARNING: could not extract %s: %s" % (fn, e))
    else:
        print(
            "> note: unpack_cramfs.py not importable; skipping CramFS auto-extraction"
        )
