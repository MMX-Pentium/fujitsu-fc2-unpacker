#!/usr/bin/env python3
"""
Fujitsu DataCloningWizard (.fc2 / .002 / .003) Recovery Image Inspector & Unpacker.

Supports Fujitsu DPIMGFHD2 (32-bit sector) multi-volume recovery images stored either:
  - Directly inside UDF 1.02 / 1.50 recovery DVD ISO images (no pre-extraction needed), or
  - As standalone extracted .fc2 / .002 / .003 files.

Subcommands:
  info        Display DPIMGFHD2/DPIMGFTL2 headers, partitions, ExRecords, PBKLABEL, and .inf/.fj info.
  unpack-img  Reconstruct a sparse raw NTFS partition image (or full MBR disk image with --full-disk).
  extract     Extract files directly from the NTFS logical backup stream into a directory tree.
  verify      Verify stream integrity across all volumes and optionally check all files against .crc.
"""

import argparse
import datetime
import fnmatch
import io
import os
import shutil
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SECTOR_SIZE = 512
DPIMGFHD2_SIZE = 0x3400  # 13,312 bytes
MBR_SIZE = 0x200         # 512 bytes


# =============================================================================
# Minimal Pure-Python UDF 1.02 / 1.50 Reader (for reading .iso files directly)
# =============================================================================

class UdfFileEntry:
    def __init__(self, iso_path: str, name: str, size: int,
                 extents: Optional[List[Tuple[int, int]]], inline: Optional[bytes]):
        self.iso_path = iso_path
        self.name = name
        self.size = size
        self.extents = extents  # list of (byte_offset_in_iso, byte_length)
        self.inline = inline

    def read_all(self) -> bytes:
        if self.inline is not None:
            return self.inline[:self.size]
        out = bytearray()
        rem = self.size
        with open(self.iso_path, "rb") as f:
            for off, ln in self.extents:
                take = min(rem, ln)
                f.seek(off)
                out.extend(f.read(take))
                rem -= take
                if rem == 0:
                    break
        return bytes(out)

    def read_range(self, offset: int, length: int) -> bytes:
        if self.inline is not None:
            return self.inline[offset:offset + length]
        out = bytearray()
        cur = 0
        rem = min(length, max(0, self.size - offset))
        with open(self.iso_path, "rb") as f:
            for ext_off, ext_len in self.extents:
                if rem <= 0:
                    break
                if cur + ext_len <= offset:
                    cur += ext_len
                    continue
                skip = max(0, offset - cur)
                take = min(rem, ext_len - skip)
                f.seek(ext_off + skip)
                out.extend(f.read(take))
                rem -= take
                cur += ext_len
        return bytes(out)

    def to_segments(self, skip_head: int = 0, trim_tail: int = 0) -> List[Tuple[str, int, int]]:
        """Return [(file_path, byte_offset, byte_len)] for [skip_head : size - trim_tail]."""
        target_start = skip_head
        target_end = self.size - trim_tail
        if target_end <= target_start:
            return []
        if self.inline is not None:
            raise ValueError("Inline UDF file cannot be represented as disk segments")
        segs: List[Tuple[str, int, int]] = []
        cur = 0
        for ext_off, ext_len in self.extents:
            seg_s = max(cur, target_start)
            seg_e = min(cur + ext_len, target_end)
            if seg_e > seg_s:
                segs.append((self.iso_path, ext_off + (seg_s - cur), seg_e - seg_s))
            cur += ext_len
        return segs


def parse_udf_root(iso_path: str) -> Dict[str, UdfFileEntry]:
    """Parse root directory files from a UDF 1.02/1.50 ISO image."""
    ISO_SECTOR = 2048
    with open(iso_path, "rb") as f:
        f.seek(256 * ISO_SECTOR)
        avdp = f.read(ISO_SECTOR)
        if len(avdp) < ISO_SECTOR or struct.unpack_from("<H", avdp, 0)[0] != 2:
            raise ValueError(f"{iso_path}: Not a valid UDF image (AVDP tag != 2 at sector 256)")
        mvds_len, mvds_loc = struct.unpack_from("<II", avdp, 16)

        part_start = None
        fsd_lbn = None
        for s in range(mvds_len // ISO_SECTOR):
            f.seek((mvds_loc + s) * ISO_SECTOR)
            desc = f.read(ISO_SECTOR)
            tag = struct.unpack_from("<H", desc, 0)[0]
            if tag == 5:    # Partition Descriptor
                part_start = struct.unpack_from("<I", desc, 188)[0]
            elif tag == 6:  # Logical Volume Descriptor
                fsd_lbn = struct.unpack_from("<I", desc, 248 + 4)[0]
            elif tag == 8:  # Terminating Descriptor
                break
        if part_start is None or fsd_lbn is None:
            raise ValueError(f"{iso_path}: Missing UDF Partition or Logical Volume Descriptor")

        f.seek((part_start + fsd_lbn) * ISO_SECTOR)
        fsd = f.read(ISO_SECTOR)
        if struct.unpack_from("<H", fsd, 0)[0] != 256:
            raise ValueError(f"{iso_path}: Missing UDF File Set Descriptor")
        root_lbn = struct.unpack_from("<I", fsd, 400 + 4)[0]

        def read_fe(lbn: int) -> Tuple[int, Optional[List[Tuple[int, int]]], Optional[bytes]]:
            f.seek((part_start + lbn) * ISO_SECTOR)
            fe = f.read(ISO_SECTOR)
            tag = struct.unpack_from("<H", fe, 0)[0]
            if tag not in (261, 266):
                raise ValueError(f"{iso_path}: Unexpected UDF File Entry tag {tag} at LBN {lbn}")
            icb_flags = struct.unpack_from("<H", fe, 16 + 18)[0]
            ad_type = icb_flags & 7
            info_len = struct.unpack_from("<Q", fe, 56)[0]
            if tag == 261:
                ea_len, ad_len = struct.unpack_from("<II", fe, 168)
                ad_off = 176 + ea_len
            else:
                ea_len, ad_len = struct.unpack_from("<II", fe, 208)
                ad_off = 216 + ea_len
            if ad_type == 3:
                return info_len, None, fe[ad_off:ad_off + ad_len]
            extents: List[Tuple[int, int]] = []
            if ad_type == 0:
                for p in range(0, ad_len, 8):
                    elen, epos = struct.unpack_from("<II", fe, ad_off + p)
                    elen &= 0x3FFFFFFF
                    if elen > 0:
                        extents.append(((part_start + epos) * ISO_SECTOR, elen))
            elif ad_type == 1:
                for p in range(0, ad_len, 16):
                    elen, epos = struct.unpack_from("<II", fe, ad_off + p)
                    elen &= 0x3FFFFFFF
                    if elen > 0:
                        extents.append(((part_start + epos) * ISO_SECTOR, elen))
            else:
                raise ValueError(f"{iso_path}: Unsupported UDF allocation descriptor type {ad_type}")
            return info_len, extents, None

        root_len, root_ext, root_inline = read_fe(root_lbn)
        if root_inline is not None:
            dir_data = root_inline[:root_len]
        else:
            buf = bytearray()
            for off, ln in root_ext:
                f.seek(off)
                buf.extend(f.read(ln))
            dir_data = bytes(buf[:root_len])

        entries: Dict[str, UdfFileEntry] = {}
        pos = 0
        while pos + 38 <= len(dir_data):
            if struct.unpack_from("<H", dir_data, pos)[0] != 257:
                break
            fchar = dir_data[pos + 18]
            l_fi = dir_data[pos + 19]
            icb_lbn = struct.unpack_from("<I", dir_data, pos + 20 + 4)[0]
            l_iu = struct.unpack_from("<H", dir_data, pos + 36)[0]
            fi_raw = dir_data[pos + 38 + l_iu:pos + 38 + l_iu + l_fi]
            pos += ((38 + l_iu + l_fi + 3) // 4) * 4
            if (fchar & 0x0C) or not fi_raw:
                continue
            comp_id = fi_raw[0]
            if comp_id == 8:
                name = fi_raw[1:].decode("latin1")
            elif comp_id == 16:
                name = fi_raw[1:].decode("utf-16be")
            else:
                name = fi_raw[1:].decode("latin1", errors="replace")
            if not (fchar & 0x02):  # regular file
                flen, fext, finline = read_fe(icb_lbn)
                entries[name] = UdfFileEntry(iso_path, name, flen, fext, finline)
        return entries


# =============================================================================
# Volume Abstraction & DPIMGFHD2 Header / Trailer Structures
# =============================================================================

class VolumeSource:
    """Represents a single .fc2 / .002 / .003 volume (either standalone file or inside an ISO)."""
    def __init__(self, name: str, size: int, path: Optional[str] = None,
                 udf_entry: Optional[UdfFileEntry] = None):
        self.name = name
        self.size = size
        self.path = path
        self.udf_entry = udf_entry
        self.header = self.parse_header(self.read_range(0, DPIMGFHD2_SIZE))

    def read_range(self, offset: int, length: int) -> bytes:
        if self.udf_entry is not None:
            return self.udf_entry.read_range(offset, length)
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(length)

    def to_segments(self, skip_head: int = 0, trim_tail: int = 0) -> List[Tuple[str, int, int]]:
        if self.udf_entry is not None:
            return self.udf_entry.to_segments(skip_head, trim_tail)
        ln = self.size - skip_head - trim_tail
        return [(self.path, skip_head, ln)] if ln > 0 else []

    @staticmethod
    def parse_header(raw: bytes) -> dict:
        if len(raw) < DPIMGFHD2_SIZE:
            raise ValueError(f"Header too short ({len(raw)} bytes)")
        sig_head = struct.unpack_from("<I", raw, 0x00)[0]
        magic = raw[0x04:0x0c]
        sig_tail = struct.unpack_from("<I", raw, 0x33fc)[0]
        if magic not in (b"IMGFHD2\x00", b"IMGFTL2\x00"):
            raise ValueError(f"Unsupported magic {magic!r} (expected IMGFHD2/IMGFTL2)")
        if sig_head != sig_tail:
            raise ValueError(f"Header/tail signature mismatch: 0x{sig_head:08x} != 0x{sig_tail:08x}")

        data_vl = struct.unpack_from("<HH", raw, 0x0c)
        tool_vl = struct.unpack_from("<HH", raw, 0x10)
        backup_ts = struct.unpack_from("<I", raw, 0x14)[0]
        compress_type = raw[0x18]
        image_type = raw[0x1a]
        sector_size = struct.unpack_from("<H", raw, 0x3c)[0]
        num_records = struct.unpack_from("<H", raw, 0x3e)[0]
        disk_number = struct.unpack_from("<H", raw, 0x40)[0]
        num_files = struct.unpack_from("<H", raw, 0x42)[0]
        file_index = struct.unpack_from("<H", raw, 0x44)[0]
        stream_start = struct.unpack_from("<I", raw, 0x48)[0]
        file_size = struct.unpack_from("<I", raw, 0x4c)[0]
        num_ex_records = struct.unpack_from("<H", raw, 0x50)[0]
        image_type2 = raw[0x52]
        image_type3 = raw[0x53]

        partitions = []
        for i in range(num_records):
            p_off = 0x60 + i * 0x64
            p = raw[p_off:p_off + 0x64]
            partitions.append({
                "index": i,
                "backup_object": p[0],
                "system_id": p[1],
                "boot_indicator": p[2],
                "fs_type": p[3],
                "start_sector": struct.unpack_from("<I", p, 0x04)[0],
                "all_sectors": struct.unpack_from("<I", p, 0x08)[0],
                "used_sectors": struct.unpack_from("<I", p, 0x0c)[0],
                "start_file": struct.unpack_from("<H", p, 0x10)[0],
                "end_file": struct.unpack_from("<H", p, 0x12)[0],
                "compressed_bytes": struct.unpack_from("<Q", p, 0x5c)[0],
            })

        ex_records = []
        ex_base = 0x60 + num_records * 0x64
        for i in range(num_ex_records):
            e_off = ex_base + i * 0x80
            e = raw[e_off:e_off + 0x80]
            ex_records.append({
                "index": i,
                "type": struct.unpack_from("<I", e, 0x00)[0],
                "start_sector": struct.unpack_from("<I", e, 0x04)[0],
                "all_sectors": struct.unpack_from("<I", e, 0x08)[0],
                "used_sectors": struct.unpack_from("<I", e, 0x0c)[0],
                "start_file": struct.unpack_from("<H", e, 0x10)[0],
                "end_file": struct.unpack_from("<H", e, 0x12)[0],
                "compressed_bytes": struct.unpack_from("<Q", e, 0x5c)[0],
            })

        return {
            "signature": sig_head,
            "magic": magic.rstrip(b"\x00").decode("ascii"),
            "data_vl": data_vl,
            "tool_vl": tool_vl,
            "backup_timestamp": backup_ts,
            "compress_type": compress_type,
            "image_type": image_type,
            "sector_size": sector_size,
            "num_records": num_records,
            "disk_number": disk_number,
            "num_files": num_files,
            "file_index": file_index,
            "stream_start": stream_start,
            "file_size": file_size,
            "num_ex_records": num_ex_records,
            "image_type2": image_type2,
            "image_type3": image_type3,
            "partitions": partitions,
            "ex_records": ex_records,
        }


class MultiSegmentStream:
    """Sequential byte reader across multiple file/ISO extents."""
    def __init__(self, segments: List[Tuple[str, int, int]]):
        self.segments = segments
        self.seg_idx = 0
        self.seg_rem = segments[0][2] if segments else 0
        self.f = open(segments[0][0], "rb") if segments else None
        if self.f:
            self.f.seek(segments[0][1])
        self.total_read = 0

    def read(self, n: int) -> bytes:
        out = bytearray()
        while n > 0 and self.f is not None:
            if self.seg_rem == 0:
                self.f.close()
                self.seg_idx += 1
                if self.seg_idx >= len(self.segments):
                    self.f = None
                    break
                p, off, ln = self.segments[self.seg_idx]
                self.f = open(p, "rb")
                self.f.seek(off)
                self.seg_rem = ln
            take = min(n, self.seg_rem)
            data = self.f.read(take)
            if not data:
                break
            out.extend(data)
            self.seg_rem -= len(data)
            self.total_read += len(data)
            n -= len(data)
        return bytes(out)

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = None


class Fc2ChunkReader:
    """Decompresses DPIMGFHD2 chunks (8-byte header + zlib/raw/RLE payload) into sector records."""
    def __init__(self, stream: MultiSegmentStream, compress_type: int = 3):
        self.stream = stream
        self.compress_type = compress_type
        self.cur_data = b""
        self.cur_off = 0
        self.cur_id = 0
        self.chunks_read = 0

    @staticmethod
    def _decompress_rle16(cdata: bytes, usize: int) -> bytes:
        """Compression type 1: 16-bit RLE with 0xFEAA escape marker."""
        out = bytearray()
        pos = 0
        n = len(cdata)
        while pos + 2 <= n and len(out) < usize:
            word = struct.unpack_from("<H", cdata, pos)[0]
            pos += 2
            if word == 0xFEAA:
                count, val = struct.unpack_from("<HH", cdata, pos)
                pos += 4
                out.extend(struct.pack("<H", val) * count)
            else:
                out.extend(struct.pack("<H", word))
        return bytes(out[:usize])

    def next_chunk(self) -> Tuple[int, int]:
        hdr = self.stream.read(8)
        if len(hdr) < 8:
            raise EOFError(f"Unexpected EOF reading chunk header (chunks_read={self.chunks_read})")
        csize, usize = struct.unpack("<II", hdr)
        if csize > 0:
            cdata = self.stream.read(csize)
            if len(cdata) != csize:
                raise EOFError(f"Truncated compressed chunk ({len(cdata)} != {csize})")
            if self.compress_type == 1:
                udata = self._decompress_rle16(cdata, usize)
            else:
                udata = zlib.decompress(cdata)
        else:
            udata = self.stream.read(usize)
        if len(udata) != usize:
            raise ValueError(f"Decompressed chunk size mismatch: {len(udata)} != {usize}")
        scount, cid = struct.unpack_from("<II", udata, 0)
        if usize != 8 + scount * SECTOR_SIZE:
            raise ValueError(f"Invalid sector chunk size: usize={usize}, scount={scount}")
        self.cur_id = cid
        self.cur_data = udata[8:]
        self.cur_off = 0
        self.chunks_read += 1
        return scount, cid

    def read_sectors(self, count: int) -> bytes:
        out = bytearray()
        rem = count * SECTOR_SIZE
        while rem > 0:
            avail = len(self.cur_data) - self.cur_off
            if avail == 0:
                _, cid = self.next_chunk()
                if cid != 0xFFFFFFFE:
                    raise ValueError(
                        f"Expected continuation chunk (0xFFFFFFFE), got 0x{cid:08x} "
                        f"at chunk #{self.chunks_read}"
                    )
                avail = len(self.cur_data)
            take = min(rem, avail)
            out.extend(self.cur_data[self.cur_off:self.cur_off + take])
            self.cur_off += take
            rem -= take
        return bytes(out)

    def ensure_consumed(self):
        if self.cur_off != len(self.cur_data):
            raise ValueError(
                f"Unconsumed {len(self.cur_data) - self.cur_off} bytes left in chunk #{self.chunks_read}"
            )


class Fc2ImageSet:
    """Loads and orders all volumes (.fc2, .002, .003, ...) and optional metadata (.inf, .fj, .crc)."""
    def __init__(self, inputs: List[str]):
        self.volumes: List[VolumeSource] = []
        self.inf_data: Optional[bytes] = None
        self.fj_data: Optional[bytes] = None
        self.crc_entry: Optional[Tuple[str, Optional[UdfFileEntry]]] = None
        self._load_inputs(inputs)

    def _load_inputs(self, inputs: List[str]):
        seen_files = set()
        for inp in inputs:
            p = Path(inp)
            if not p.exists():
                raise FileNotFoundError(f"Input not found: {inp}")
            if p.suffix.lower() == ".iso":
                udf_files = parse_udf_root(str(p))
                for fname, entry in udf_files.items():
                    low = fname.lower()
                    if low.endswith(".inf") and self.inf_data is None:
                        self.inf_data = entry.read_all()
                    elif low.endswith(".fj") and self.fj_data is None:
                        self.fj_data = entry.read_all()
                    elif low.endswith(".crc") and self.crc_entry is None:
                        self.crc_entry = (fname, entry)
                    elif entry.size >= DPIMGFHD2_SIZE:
                        head = entry.read_range(0, 12)
                        if head[4:12] == b"IMGFHD2\x00":
                            self.volumes.append(VolumeSource(fname, entry.size, udf_entry=entry))
            else:
                # Standalone .fc2 / .002 / .003 file; if only .fc2 given, auto-discover siblings
                rp = str(p.resolve())
                if rp not in seen_files:
                    seen_files.add(rp)
                    self.volumes.append(VolumeSource(p.name, p.stat().st_size, path=str(p)))
                if len(inputs) == 1 and p.suffix.lower() == ".fc2":
                    stem = p.stem
                    parent = p.parent
                    for idx in range(2, 1000):
                        sib = parent / f"{stem}.{idx:03d}"
                        if sib.exists():
                            srp = str(sib.resolve())
                            if srp not in seen_files:
                                seen_files.add(srp)
                                self.volumes.append(VolumeSource(sib.name, sib.stat().st_size, path=str(sib)))
                        else:
                            break
                    for ext in (".inf", ".INF"):
                        cand = parent / f"{stem}{ext}"
                        if cand.exists() and self.inf_data is None:
                            self.inf_data = cand.read_bytes()
                    for ext in (".fj", ".FJ"):
                        cand = parent / f"{stem}{ext}"
                        if cand.exists() and self.fj_data is None:
                            self.fj_data = cand.read_bytes()
                    for ext in (".crc", ".CRC"):
                        cand = parent / f"{stem}{ext}"
                        if cand.exists() and self.crc_entry is None:
                            self.crc_entry = (str(cand), None)

        if not self.volumes:
            raise ValueError("No valid DPIMGFHD2 (.fc2/.002/...) volumes found in inputs")

        # Sort by file_index (0 = .fc2, 1 = .002, 2 = .003, ...)
        self.volumes.sort(key=lambda v: v.header["file_index"])
        expected_count = self.volumes[0].header["num_files"]
        indices = [v.header["file_index"] for v in self.volumes]
        if indices != list(range(expected_count)):
            raise ValueError(
                f"Incomplete or mismatched volume set: found indices {indices}, "
                f"expected 0..{expected_count - 1}"
            )
        sigs = {v.header["signature"] for v in self.volumes}
        if len(sigs) != 1:
            raise ValueError(f"Volume signature mismatch across inputs: {sigs}")

        self.header = self.volumes[0].header
        self.mbr = self.volumes[0].read_range(DPIMGFHD2_SIZE, MBR_SIZE)
        last_vol = self.volumes[-1]
        self.trailer = VolumeSource.parse_header(
            last_vol.read_range(last_vol.size - DPIMGFHD2_SIZE, DPIMGFHD2_SIZE)
        )

    def open_stream(self) -> Tuple[MultiSegmentStream, Fc2ChunkReader]:
        segs: List[Tuple[str, int, int]] = []
        last_idx = len(self.volumes) - 1
        for i, vol in enumerate(self.volumes):
            skip_head = DPIMGFHD2_SIZE + (MBR_SIZE if i == 0 else 0)
            trim_tail = DPIMGFHD2_SIZE if i == last_idx else 0
            segs.extend(vol.to_segments(skip_head=skip_head, trim_tail=trim_tail))
        ms = MultiSegmentStream(segs)
        return ms, Fc2ChunkReader(ms, compress_type=self.header["compress_type"])

    def read_crc_manifest(self, override_path: Optional[str] = None) -> Optional[bytes]:
        if override_path:
            return Path(override_path).read_bytes()
        if self.crc_entry is None:
            return None
        path_or_name, udf_entry = self.crc_entry
        if udf_entry is not None:
            return udf_entry.read_all()
        return Path(path_or_name).read_bytes()


# =============================================================================
# NTFS Helpers (USA Fixup, PBKLABEL, Data Runs, Attribute Lists, Filenames)
# =============================================================================

def parse_pbklabel_ntfs(pbk: bytes) -> dict:
    if pbk[:20] not in (b"FJIMGBR_PBKLABEL_HDR", b"FJIMGBR_PBKLABEL_EOF"):
        raise ValueError(f"Invalid PBKLABEL signature: {pbk[:20]!r}")
    bps = struct.unpack_from("<H", pbk, 0x24)[0]
    spc = pbk[0x26]
    mft_rec_size = struct.unpack_from("<I", pbk, 0x30)[0]
    mft_clusters = struct.unpack_from("<I", pbk, 0x58)[0]
    cluster_size = bps * spc
    total_mft_records = mft_clusters * (cluster_size // mft_rec_size)
    return {
        "tag": pbk[:20].decode("ascii"),
        "version": struct.unpack_from("<HH", pbk, 0x14),
        "timestamp": struct.unpack_from("<I", pbk, 0x18)[0],
        "backup_object": pbk[0x1c],
        "system_id": pbk[0x1d],
        "boot_indicator": pbk[0x1e],
        "fs_type": pbk[0x1f],
        "total_sectors": struct.unpack_from("<I", pbk, 0x20)[0],
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "cluster_size": cluster_size,
        "used_clusters": struct.unpack_from("<I", pbk, 0x28)[0],
        "mft_record_size": mft_rec_size,
        "index_block_clusters": struct.unpack_from("<I", pbk, 0x34)[0],
        "bitmap_clusters": struct.unpack_from("<I", pbk, 0x44)[0],
        "last_used_cluster": struct.unpack_from("<I", pbk, 0x4c)[0],
        "flags": struct.unpack_from("<I", pbk, 0x54)[0],
        "mft_clusters": mft_clusters,
        "mftmirr_clusters": struct.unpack_from("<I", pbk, 0x5c)[0],
        "total_mft_records": total_mft_records,
    }


def apply_usa_fixup(rec: bytes, bps: int = 512) -> bytes:
    buf = bytearray(rec)
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt < 1 or usa_off + usa_cnt * 2 > len(buf):
        return rec
    for i in range(1, usa_cnt):
        sec_end = i * bps - 2
        if sec_end + 2 <= len(buf):
            buf[sec_end:sec_end + 2] = buf[usa_off + i * 2:usa_off + (i + 1) * 2]
    return bytes(buf)


def parse_data_runs(buf: bytes, off: int) -> List[Tuple[int, Optional[int]]]:
    """Parse NTFS data runs -> list of (cluster_count, absolute_lcn_or_None_if_sparse)."""
    runs: List[Tuple[int, Optional[int]]] = []
    pos = off
    cur_lcn = 0
    while pos < len(buf):
        hdr = buf[pos]
        if hdr == 0:
            break
        len_sz = hdr & 0x0F
        off_sz = hdr >> 4
        pos += 1
        clen = int.from_bytes(buf[pos:pos + len_sz], "little", signed=False)
        pos += len_sz
        if off_sz == 0:
            runs.append((clen, None))
        else:
            delta = int.from_bytes(buf[pos:pos + off_sz], "little", signed=True)
            pos += off_sz
            cur_lcn += delta
            runs.append((clen, cur_lcn))
    return runs


def iter_mft_attributes(rec: bytes):
    """Yield (attr_type, non_resident, name, flags, attr_offset, attr_len) for an MFT record."""
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off + 8 <= len(rec):
        atype = struct.unpack_from("<I", rec, off)[0]
        if atype == 0xFFFFFFFF:
            break
        alen = struct.unpack_from("<I", rec, off + 4)[0]
        if alen == 0 or off + alen > len(rec):
            break
        non_res = rec[off + 8]
        nlen = rec[off + 9]
        noff = struct.unpack_from("<H", rec, off + 10)[0]
        aflags = struct.unpack_from("<H", rec, off + 12)[0]
        aname = rec[off + noff:off + noff + nlen * 2].decode("utf-16le", errors="ignore") if nlen else ""
        yield atype, non_res, aname, aflags, off, alen
        off += alen


def parse_attr_list_refs(buf: bytes, target_set: set, only_bad: bool = False):
    pos = 0
    while pos + 26 <= len(buf):
        atype, rlen, nlen, noff = struct.unpack_from("<IHBB", buf, pos)
        if rlen == 0 or pos + rlen > len(buf):
            break
        mft_ref = struct.unpack_from("<Q", buf, pos + 16)[0] & 0x0000FFFFFFFFFFFF
        if only_bad:
            if atype == 0x80 and nlen == 4 and buf[pos + noff:pos + noff + 8] == "$Bad".encode("utf-16le"):
                target_set.add(mft_ref)
        else:
            target_set.add(mft_ref)
        pos += rlen


def classify_frs(mft_idx: int, rec: bytes, ext_mft: set, ext_bad: set, ext_pagefile: set) -> int:
    if mft_idx in (0, 1, 3, 5, 6, 7, 8):
        return mft_idx
    if mft_idx in ext_mft:
        return 0
    if mft_idx in ext_bad:
        return 8
    if mft_idx in ext_pagefile:
        return 0x100
    for atype, non_res, _, _, off, _ in iter_mft_attributes(rec):
        if atype == 0x30 and non_res == 0:
            voff = struct.unpack_from("<H", rec, off + 20)[0]
            parent_ref = struct.unpack_from("<Q", rec, off + voff)[0] & 0x0000FFFFFFFFFFFF
            if parent_ref == 5:
                fn_len = rec[off + voff + 64]
                fn = rec[off + voff + 66:off + voff + 66 + fn_len * 2].decode("utf-16le", errors="ignore")
                if fn.lower() == "pagefile.sys":
                    return 0x100
    return -1


def ntfs_filetime_to_unix(ft: int) -> Optional[float]:
    if ft <= 116444736000000000:
        return None
    return (ft - 116444736000000000) / 10_000_000.0


def should_skip_stream_data(frs_type: int, atype: int, aname: str) -> bool:
    if frs_type in (0, 1, 6, 0x100) and atype == 0x80:
        return True
    if frs_type == 8 and atype == 0x80 and aname == "$Bad":
        return True
    return False


# =============================================================================
# Subcommand: info
# =============================================================================

def cmd_info(args):
    img = Fc2ImageSet(args.inputs)
    h = img.header
    ts = datetime.datetime.fromtimestamp(h["backup_timestamp"], tz=datetime.timezone.utc)
    comp_map = {0: "None", 1: "RLE16", 2: "zlib (fast)", 3: "zlib"}
    imgtype_map = {0: "Disk", 1: "Partition"}

    print("=== Fujitsu DataCloningWizard Image Info ===")
    print(f"Magic:          {h['magic']} (Trailer: {img.trailer['magic']})")
    print(f"Signature/ID:   0x{h['signature']:08x}")
    print(f"Backup Date:    {ts.strftime('%Y-%m-%d %H:%M:%S UTC')} (raw=0x{h['backup_timestamp']:08x})")
    print(f"DataVL/ToolVL:  {h['data_vl'][0]}.{h['data_vl'][1]} / {h['tool_vl'][0]}.{h['tool_vl'][1]}")
    print(f"ImageType:      {imgtype_map.get(h['image_type'], h['image_type'])} "
          f"(ImageType2={h['image_type2']}, ImageType3={h['image_type3']})")
    print(f"Compression:    {comp_map.get(h['compress_type'], h['compress_type'])} (code={h['compress_type']})")
    print(f"Sector Size:    {h['sector_size']} bytes")
    print(f"Volumes:        {h['num_files']}")
    for v in img.volumes:
        vh = v.header
        print(f"  [{vh['file_index']}] {v.name:28s} size={v.size:13,d} B  stream_start=0x{vh['stream_start']:08x}")

    print("\n--- Partitions ---")
    for p in h["partitions"]:
        size_gb = p["all_sectors"] * h["sector_size"] / (1024 ** 3)
        used_gb = p["used_sectors"] * h["sector_size"] / (1024 ** 3)
        print(f"  Part #{p['index']}: BackupObject={p['backup_object']} SysID=0x{p['system_id']:02x} "
              f"FSType=0x{p['fs_type']:02x} Boot=0x{p['boot_indicator']:02x}")
        print(f"    StartSector={p['start_sector']:,}  AllSectors={p['all_sectors']:,} ({size_gb:.2f} GiB)  "
              f"UsedSectors={p['used_sectors']:,} ({used_gb:.2f} GiB)")
        print(f"    Files={p['start_file']}..{p['end_file']}  CompressedBytes={p['compressed_bytes']:,} "
              f"(0x{p['compressed_bytes']:x})")

    print("\n--- ExRecords ---")
    for e in h["ex_records"]:
        print(f"  ExRec #{e['index']}: Type=0x{e['type']:x} StartSector={e['start_sector']} "
              f"Sectors={e['all_sectors']} Files={e['start_file']}..{e['end_file']} "
              f"CompressedBytes={e['compressed_bytes']} (0x{e['compressed_bytes']:x})")

    # Read first PBKLABEL_HDR
    ms, cs = img.open_stream()
    try:
        cs.next_chunk()
        pbk = parse_pbklabel_ntfs(cs.read_sectors(1))
        print("\n--- Partition 0 PBKLABEL_HDR ---")
        print(f"  BytesPerSector={pbk['bytes_per_sector']}  SectorsPerCluster={pbk['sectors_per_cluster']} "
              f"(ClusterSize={pbk['cluster_size']})")
        print(f"  TotalSectors={pbk['total_sectors']:,}  UsedClusters={pbk['used_clusters']:,}")
        print(f"  MftRecordSize={pbk['mft_record_size']}  MftClusters={pbk['mft_clusters']:,} "
              f"-> TotalMftRecords={pbk['total_mft_records']:,}")
        print(f"  BitmapClusters={pbk['bitmap_clusters']}  MftMirrClusters={pbk['mftmirr_clusters']}  "
              f"Flags=0x{pbk['flags']:08x}")
    finally:
        ms.close()

    if img.inf_data:
        print("\n--- .inf Metadata ---")
        print(img.inf_data.decode("cp932", errors="replace").strip())
    if img.fj_data:
        print("\n--- .fj File List ---")
        print(img.fj_data.decode("cp932", errors="replace").strip())
    if img.crc_entry:
        crc_raw = img.read_crc_manifest()
        lines = crc_raw.count(b"\n")
        print(f"\n--- .crc Manifest ---")
        print(f"  Source: {img.crc_entry[0]}  Entries: {lines:,} lines ({len(crc_raw):,} bytes)")


# =============================================================================
# Subcommand: unpack-img (Reconstruct sparse raw NTFS partition or full disk)
# =============================================================================

def cmd_unpack_img(args):
    t0 = time.time()
    img = Fc2ImageSet(args.inputs)
    part = img.header["partitions"][0]
    if part["fs_type"] != 0x07:
        raise ValueError(f"Only NTFS (fs_type=0x07) is currently supported, got 0x{part['fs_type']:02x}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    ms, cs = img.open_stream()
    try:
        sc, cid = cs.next_chunk()
        if cid != 0xFFFFFFFF or sc != 1:
            raise ValueError(f"Expected PBKLABEL_HDR chunk, got sc={sc} cid=0x{cid:08x}")
        pbk_raw = cs.read_sectors(1)
        pbk = parse_pbklabel_ntfs(pbk_raw)

        bps = pbk["bytes_per_sector"]
        spc = pbk["sectors_per_cluster"]
        cluster_size = pbk["cluster_size"]
        mft_rec_sz = pbk["mft_record_size"]
        total_sectors = pbk["total_sectors"]
        total_mft = pbk["total_mft_records"]
        total_clusters = (total_sectors - 1) // spc

        part_byte_offset = (part["start_sector"] * bps) if args.full_disk else 0
        out_total_bytes = part_byte_offset + total_sectors * bps

        print(f"Reconstructing {'full MBR disk' if args.full_disk else 'NTFS partition'} image -> {out_path}")
        print(f"  Logical size: {out_total_bytes:,} bytes ({out_total_bytes / (1024**3):.2f} GiB, sparse)")
        print(f"  MFT records:  {total_mft:,}  Cluster size: {cluster_size} bytes")

        # Track cluster allocations for reconstructing $Bitmap
        bitmap_bytes = bytearray((total_clusters + 7) // 8)
        def mark_clusters(start_lcn: int, length: int):
            end_lcn = min(start_lcn + length, total_clusters)
            lcn = start_lcn
            # Align to byte boundary
            while lcn < end_lcn and (lcn & 7):
                bitmap_bytes[lcn >> 3] |= (1 << (lcn & 7))
                lcn += 1
            # Fill full bytes
            full_end = end_lcn & ~7
            if lcn < full_end:
                b_start = lcn >> 3
                b_end = full_end >> 3
                bitmap_bytes[b_start:b_end] = b"\xff" * (b_end - b_start)
                lcn = full_end
            # Remainder bits
            while lcn < end_lcn:
                bitmap_bytes[lcn >> 3] |= (1 << (lcn & 7))
                lcn += 1

        mft_runs: List[Tuple[int, Optional[int]]] = []
        mftmirr_runs: List[Tuple[int, Optional[int]]] = []
        bitmap_runs: List[Tuple[int, Optional[int]]] = []
        mft_first4: List[bytes] = []
        boot_sector: Optional[bytes] = None
        ext_mft: set = set()
        ext_bad: set = set()
        ext_pagefile: set = set()

        def lcn_for_mft_index(idx: int) -> int:
            byte_off = idx * mft_rec_sz
            vcn = byte_off // cluster_size
            in_cluster_off = byte_off % cluster_size
            cur_vcn = 0
            for clen, lcn in mft_runs:
                if vcn < cur_vcn + clen:
                    if lcn is None:
                        raise ValueError(f"$MFT VCN {vcn} is sparse!")
                    return part_byte_offset + (lcn + (vcn - cur_vcn)) * cluster_size + in_cluster_off
                cur_vcn += clen
            raise ValueError(f"MFT index {idx} (VCN {vcn}) out of $MFT runs")

        with open(out_path, "wb") as out_f:
            out_f.truncate(out_total_bytes)
            if args.full_disk:
                out_f.seek(0)
                out_f.write(img.mbr)

            mft_written_clusters = 0
            for mft_idx in range(total_mft):
                cs.ensure_consumed()
                sc, cid = cs.next_chunk()
                if cid != mft_idx:
                    raise ValueError(f"MFT sync error at {mft_idx}: got cid=0x{cid:08x}")
                raw_rec = cs.read_sectors(mft_rec_sz // SECTOR_SIZE)

                if mft_idx < 4:
                    mft_first4.append(raw_rec)

                # Parse in-use FILE record
                if raw_rec[:4] == b"FILE" and (struct.unpack_from("<H", raw_rec, 0x16)[0] & 1):
                    rec = apply_usa_fixup(raw_rec, bps)
                    frs_type = classify_frs(mft_idx, rec, ext_mft, ext_bad, ext_pagefile)

                    for atype, non_res, aname, aflags, off, alen in iter_mft_attributes(rec):
                        if non_res == 0:
                            if atype == 0x20:
                                vlen = struct.unpack_from("<I", rec, off + 16)[0]
                                voff = struct.unpack_from("<H", rec, off + 20)[0]
                                al_data = rec[off + voff:off + voff + vlen]
                                if frs_type == 0:
                                    parse_attr_list_refs(al_data, ext_mft)
                                elif frs_type == 0x100:
                                    parse_attr_list_refs(al_data, ext_pagefile)
                                elif frs_type == 8:
                                    parse_attr_list_refs(al_data, ext_bad, only_bad=True)
                        else:
                            run_off = struct.unpack_from("<H", rec, off + 32)[0]
                            runs = parse_data_runs(rec, off + run_off)

                            # Record metadata runs for special files & mark their clusters used
                            if frs_type == 0 and atype == 0x80:
                                mft_runs.extend(runs)
                                for clen, lcn in runs:
                                    if lcn is not None:
                                        mark_clusters(lcn, clen)
                                continue
                            if frs_type == 1 and atype == 0x80:
                                mftmirr_runs.extend(runs)
                                for clen, lcn in runs:
                                    if lcn is not None:
                                        mark_clusters(lcn, clen)
                                continue
                            if frs_type == 6 and atype == 0x80:
                                bitmap_runs.extend(runs)
                                for clen, lcn in runs:
                                    if lcn is not None:
                                        mark_clusters(lcn, clen)
                                continue
                            if frs_type == 0x100 and atype == 0x80:
                                # pagefile.sys: clusters remain allocated (zero-filled sparse)
                                for clen, lcn in runs:
                                    if lcn is not None:
                                        mark_clusters(lcn, clen)
                                continue
                            if frs_type == 8 and atype == 0x80 and aname == "$Bad":
                                continue

                            # All other non-resident attributes: read from stream and write at original LCNs
                            attr_buf = bytearray() if (atype == 0x20 and frs_type in (0, 8, 0x100)) else None
                            for clen, lcn in runs:
                                if lcn is None:
                                    continue  # sparse run -> already zero in sparse file
                                mark_clusters(lcn, clen)
                                # Stream in manageable blocks (up to 256 clusters = 1 MiB)
                                rem_c = clen
                                cur_c = lcn
                                while rem_c > 0:
                                    batch = min(rem_c, 256)
                                    chunk_bytes = cs.read_sectors(batch * spc)
                                    if mft_idx == 7 and atype == 0x80 and cur_c == 0 and boot_sector is None:
                                        boot_sector = chunk_bytes[:bps]
                                    if attr_buf is not None:
                                        attr_buf.extend(chunk_bytes)
                                    out_f.seek(part_byte_offset + cur_c * cluster_size)
                                    out_f.write(chunk_bytes)
                                    cur_c += batch
                                    rem_c -= batch
                                    mft_written_clusters += batch

                            if attr_buf is not None:
                                real_sz = struct.unpack_from("<Q", rec, off + 48)[0]
                                if frs_type == 0:
                                    parse_attr_list_refs(bytes(attr_buf[:real_sz]), ext_mft)
                                elif frs_type == 0x100:
                                    parse_attr_list_refs(bytes(attr_buf[:real_sz]), ext_pagefile)
                                elif frs_type == 8:
                                    parse_attr_list_refs(bytes(attr_buf[:real_sz]), ext_bad, only_bad=True)

                # Write raw MFT record (with original USA fixups intact!) into $MFT
                if mft_runs:
                    out_f.seek(lcn_for_mft_index(mft_idx))
                    out_f.write(raw_rec)

                if mft_idx > 0 and mft_idx % 25000 == 0:
                    print(f"  Progress: MFT {mft_idx:,}/{total_mft:,} ({mft_idx * 100 / total_mft:.1f}%) "
                          f"elapsed={time.time() - t0:.1f}s")

            # Verify Partition 0 PBKLABEL_EOF
            cs.ensure_consumed()
            sc, cid = cs.next_chunk()
            eof_pbk = cs.read_sectors(1)
            if cid != 0xFFFFFFFF or eof_pbk[:20] != b"FJIMGBR_PBKLABEL_EOF":
                raise ValueError(f"Expected PBKLABEL_EOF, got cid=0x{cid:08x} {eof_pbk[:20]!r}")

            # Write $MFTMirr (MFT records 0..3)
            mftmirr_blob = b"".join(mft_first4)
            pos = 0
            for clen, lcn in mftmirr_runs:
                if lcn is not None and pos < len(mftmirr_blob):
                    nbytes = min(clen * cluster_size, len(mftmirr_blob) - pos)
                    out_f.seek(part_byte_offset + lcn * cluster_size)
                    out_f.write(mftmirr_blob[pos:pos + nbytes])
                    pos += nbytes

            # Write reconstructed $Bitmap
            pos = 0
            for clen, lcn in bitmap_runs:
                if lcn is not None and pos < len(bitmap_bytes):
                    nbytes = clen * cluster_size
                    chunk = bitmap_bytes[pos:pos + nbytes]
                    if len(chunk) < nbytes:
                        chunk = chunk + b"\x00" * (nbytes - len(chunk))
                    out_f.seek(part_byte_offset + lcn * cluster_size)
                    out_f.write(chunk)
                    pos += nbytes

            # Write backup NTFS boot sector at the very last sector of the partition
            if boot_sector is not None:
                out_f.seek(part_byte_offset + (total_sectors - 1) * bps)
                out_f.write(boot_sector)

            # Read ExRecord 0 (Track 0 hidden sectors 1..62)
            track0_data = b""
            if img.header["num_ex_records"] > 0:
                cs.ensure_consumed()
                sc, cid = cs.next_chunk()
                ex_hdr = cs.read_sectors(1)
                if cid == 0xFFFFFFFF and ex_hdr[:20] == b"FJIMGBR_PBKLABEL_HDR":
                    ex_sectors = struct.unpack_from("<I", ex_hdr, 0x20)[0]
                    sc, cid = cs.next_chunk()
                    track0_data = cs.read_sectors(ex_sectors)
                    cs.ensure_consumed()
                    cs.next_chunk()
                    cs.read_sectors(1)  # PBKLABEL_EOF
                    if args.full_disk:
                        out_f.seek(cid * bps)
                        out_f.write(track0_data)

        if args.save_meta:
            meta_dir = Path(args.save_meta)
            meta_dir.mkdir(parents=True, exist_ok=True)
            (meta_dir / "mbr.bin").write_bytes(img.mbr)
            (meta_dir / "pbklabel_hdr.bin").write_bytes(pbk_raw)
            if track0_data:
                (meta_dir / "track0_exrec.bin").write_bytes(track0_data)
            print(f"  Saved metadata binaries to {meta_dir}")

        print(f"Done in {time.time() - t0:.1f}s! Written {mft_written_clusters:,} data clusters "
              f"({mft_written_clusters * cluster_size:,} bytes) + $MFT/$MFTMirr/$Bitmap.")
    finally:
        ms.close()


# =============================================================================
# Subcommands: verify & extract (Direct Logical NTFS Stream Reader)
# =============================================================================

def parse_crc_manifest(raw: bytes) -> Dict[str, Tuple[Optional[int], int]]:
    """Parse D551F--A400G05-1.crc -> {lowercase_path: (size_or_None_for_dir, crc32)}."""
    entries: Dict[str, Tuple[Optional[int], int]] = {}
    text = raw.decode("cp932", errors="replace")
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        path, sz_str, crc_str = parts[0], parts[1], parts[2]
        key = path.lower()
        if sz_str == "-DIR-":
            entries[key] = (None, 0)
        else:
            entries[key] = (int(sz_str), int(crc_str, 16))
    return entries


def _run_logical_pass(img: Fc2ImageSet, mode: str, out_dir: Optional[Path] = None,
                      glob_filter: Optional[str] = None, crc_raw: Optional[bytes] = None):
    """
    Single-pass logical NTFS parser for both 'verify' and 'extract'.
    Handles resident/non-resident $DATA, sparse runs, $ATTRIBUTE_LIST multi-record files,
    hardlinks, out-of-order parent directories, and timestamps.
    """
    t0 = time.time()
    ms, cs = img.open_stream()
    staging_dir: Optional[Path] = None
    if mode == "extract":
        assert out_dir is not None
        out_dir.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(prefix=".fc2_staging_", dir=str(out_dir)))

    try:
        sc, cid = cs.next_chunk()
        pbk = parse_pbklabel_ntfs(cs.read_sectors(1))
        bps = pbk["bytes_per_sector"]
        spc = pbk["sectors_per_cluster"]
        cluster_size = pbk["cluster_size"]
        mft_rec_sz = pbk["mft_record_size"]
        total_mft = pbk["total_mft_records"]

        print(f"Streaming {total_mft:,} MFT records ({mode})...")

        ext_mft: set = set()
        ext_bad: set = set()
        ext_pagefile: set = set()

        # Per base MFT record metadata:
        # names[base_ref] = list of (parent_ref, name, namespace)
        names: Dict[int, List[Tuple[int, str, int]]] = {}
        is_dir_map: Dict[int, bool] = {}
        mtime_map: Dict[int, float] = {}
        # For verify mode:
        # single-extent files get fast streaming CRC32; multi-extent ($ATTRIBUTE_LIST) files store segments in tmp
        file_real_size: Dict[int, int] = {}
        file_init_size: Dict[int, int] = {}
        file_crc: Dict[int, int] = {}
        # For files whose default unnamed $DATA comes in multiple $DATA attributes (via $ATTRIBUTE_LIST)
        # or out-of-order VCNs: spool into a temp dir in verify mode too (only ~95 files max!).
        multi_tmp_dir: Optional[Path] = None
        multi_files: Dict[int, Path] = {}
        staged_files: Dict[int, Path] = {}
        has_attr_list_set: set = set()

        def ensure_multi_file(base_ref: int) -> Path:
            nonlocal multi_tmp_dir
            if base_ref not in multi_files:
                if multi_tmp_dir is None:
                    multi_tmp_dir = Path(tempfile.mkdtemp(prefix="fc2_verify_"))
                p = multi_tmp_dir / f"{base_ref}.bin"
                p.touch()
                multi_files[base_ref] = p
            return multi_files[base_ref]

        def ensure_staged_file(base_ref: int) -> Path:
            if base_ref not in staged_files:
                p = staging_dir / f"{base_ref}.bin"
                p.touch()
                staged_files[base_ref] = p
            return staged_files[base_ref]

        in_use_count = 0
        for mft_idx in range(total_mft):
            cs.ensure_consumed()
            sc, cid = cs.next_chunk()
            if cid != mft_idx:
                raise ValueError(f"MFT sync error at {mft_idx}: got cid=0x{cid:08x}")
            raw_rec = cs.read_sectors(mft_rec_sz // SECTOR_SIZE)

            if raw_rec[:4] != b"FILE":
                continue
            rec_flags = struct.unpack_from("<H", raw_rec, 0x16)[0]
            if not (rec_flags & 1):
                continue

            in_use_count += 1
            rec = apply_usa_fixup(raw_rec, bps)
            frs_type = classify_frs(mft_idx, rec, ext_mft, ext_bad, ext_pagefile)
            base_ref = struct.unpack_from("<Q", rec, 0x20)[0] & 0x0000FFFFFFFFFFFF
            owner = base_ref if base_ref != 0 else mft_idx
            if base_ref == 0:
                is_dir_map[mft_idx] = bool(rec_flags & 2)

            # First scan attributes to see if this record has $ATTRIBUTE_LIST
            attrs = list(iter_mft_attributes(rec))
            if any(a[0] == 0x20 for a in attrs):
                has_attr_list_set.add(owner)

            for atype, non_res, aname, aflags, off, alen in attrs:
                if non_res == 0:
                    vlen = struct.unpack_from("<I", rec, off + 16)[0]
                    voff = struct.unpack_from("<H", rec, off + 20)[0]
                    val = rec[off + voff:off + voff + vlen]
                    if atype == 0x10 and len(val) >= 16:
                        mt = ntfs_filetime_to_unix(struct.unpack_from("<Q", val, 8)[0])
                        if mt is not None:
                            mtime_map[owner] = mt
                    elif atype == 0x30 and len(val) >= 66:
                        parent_ref = struct.unpack_from("<Q", val, 0)[0] & 0x0000FFFFFFFFFFFF
                        fn_len = val[64]
                        ns = val[65]
                        fn = val[66:66 + fn_len * 2].decode("utf-16le", errors="replace")
                        names.setdefault(owner, []).append((parent_ref, fn, ns))
                    elif atype == 0x20:
                        if frs_type == 0:
                            parse_attr_list_refs(val, ext_mft)
                        elif frs_type == 0x100:
                            parse_attr_list_refs(val, ext_pagefile)
                        elif frs_type == 8:
                            parse_attr_list_refs(val, ext_bad, only_bad=True)
                    elif atype == 0x80 and aname == "" and owner >= 16:
                        file_real_size[owner] = len(val)
                        file_init_size[owner] = len(val)
                        if mode == "verify":
                            file_crc[owner] = zlib.crc32(val) & 0xFFFFFFFF
                        elif mode == "extract":
                            ensure_staged_file(owner).write_bytes(val)
                else:
                    if should_skip_stream_data(frs_type, atype, aname):
                        continue
                    run_off = struct.unpack_from("<H", rec, off + 32)[0]
                    runs = parse_data_runs(rec, off + run_off)
                    start_vcn = struct.unpack_from("<Q", rec, off + 16)[0]
                    real_sz = struct.unpack_from("<Q", rec, off + 48)[0] if start_vcn == 0 else None
                    init_sz = struct.unpack_from("<Q", rec, off + 56)[0] if start_vcn == 0 else None

                    is_default_data = (atype == 0x80 and aname == "" and owner >= 16)
                    if is_default_data and start_vcn == 0:
                        file_real_size[owner] = real_sz
                        file_init_size[owner] = min(init_sz, real_sz)

                    need_al_buf = (atype == 0x20 and frs_type in (0, 8, 0x100))
                    al_buf = bytearray() if need_al_buf else None

                    # Decide whether to stream CRC32 directly or write to staging/multi file
                    use_streaming_crc = (
                        mode == "verify"
                        and is_default_data
                        and owner not in has_attr_list_set
                        and base_ref == 0
                        and start_vcn == 0
                    )
                    write_target_fh = None
                    if is_default_data:
                        if mode == "extract":
                            write_target_fh = open(ensure_staged_file(owner), "r+b")
                        elif mode == "verify" and not use_streaming_crc:
                            write_target_fh = open(ensure_multi_file(owner), "r+b")

                    crc_acc = 0
                    bytes_hashed = 0
                    valid_limit = min(init_sz, real_sz) if (real_sz is not None and init_sz is not None) else 0
                    cur_vcn = start_vcn
                    try:
                        for clen, lcn in runs:
                            if lcn is None:
                                # Sparse run -> zeros
                                zero_bytes = clen * cluster_size
                                if use_streaming_crc and real_sz is not None:
                                    rem_to_hash = max(0, valid_limit - bytes_hashed)
                                    take = min(zero_bytes, rem_to_hash)
                                    zblock = b"\x00" * 65536
                                    while take > 0:
                                        step = min(take, 65536)
                                        crc_acc = zlib.crc32(zblock[:step], crc_acc)
                                        bytes_hashed += step
                                        take -= step
                                cur_vcn += clen
                                continue

                            rem_c = clen
                            while rem_c > 0:
                                batch = min(rem_c, 256)
                                chunk = cs.read_sectors(batch * spc)
                                if al_buf is not None:
                                    al_buf.extend(chunk)
                                if use_streaming_crc and real_sz is not None:
                                    rem_to_hash = max(0, valid_limit - bytes_hashed)
                                    if rem_to_hash > 0:
                                        part_chunk = chunk[:rem_to_hash]
                                        crc_acc = zlib.crc32(part_chunk, crc_acc)
                                        bytes_hashed += len(part_chunk)
                                elif write_target_fh is not None:
                                    write_target_fh.seek(cur_vcn * cluster_size)
                                    write_target_fh.write(chunk)
                                cur_vcn += batch
                                rem_c -= batch
                    finally:
                        if write_target_fh is not None:
                            write_target_fh.close()

                    if use_streaming_crc and real_sz is not None:
                        # Bytes in [valid_limit, real_sz) are uninitialized (NTFS reads them as zeros)
                        rem_zeros = max(0, real_sz - bytes_hashed)
                        if rem_zeros > 0:
                            zblock = b"\x00" * 65536
                            while rem_zeros > 0:
                                step = min(rem_zeros, 65536)
                                crc_acc = zlib.crc32(zblock[:step], crc_acc)
                                rem_zeros -= step
                        file_crc[owner] = crc_acc & 0xFFFFFFFF

                    if al_buf is not None and real_sz is not None:
                        if frs_type == 0:
                            parse_attr_list_refs(bytes(al_buf[:real_sz]), ext_mft)
                        elif frs_type == 0x100:
                            parse_attr_list_refs(bytes(al_buf[:real_sz]), ext_pagefile)
                        elif frs_type == 8:
                            parse_attr_list_refs(bytes(al_buf[:real_sz]), ext_bad, only_bad=True)

            if mft_idx > 0 and mft_idx % 25000 == 0:
                print(f"  Progress: MFT {mft_idx:,}/{total_mft:,} ({mft_idx * 100 / total_mft:.1f}%) "
                      f"elapsed={time.time() - t0:.1f}s")

        # Verify Partition 0 PBKLABEL_EOF
        cs.ensure_consumed()
        sc, cid = cs.next_chunk()
        eof_pbk = cs.read_sectors(1)
        if cid != 0xFFFFFFFF or eof_pbk[:20] != b"FJIMGBR_PBKLABEL_EOF":
            raise ValueError(f"Expected PBKLABEL_EOF, got cid=0x{cid:08x} {eof_pbk[:20]!r}")

        expected_part_bytes = img.header["partitions"][0]["compressed_bytes"]
        if ms.total_read != expected_part_bytes:
            raise ValueError(
                f"Partition stream length mismatch: read 0x{ms.total_read:x}, "
                f"header expected 0x{expected_part_bytes:x}"
            )

        # Verify ExRecord 0
        if img.header["num_ex_records"] > 0:
            cs.ensure_consumed()
            sc, cid = cs.next_chunk()
            ex_hdr = cs.read_sectors(1)
            assert cid == 0xFFFFFFFF and ex_hdr[:20] == b"FJIMGBR_PBKLABEL_HDR"
            ex_sectors = struct.unpack_from("<I", ex_hdr, 0x20)[0]
            cs.next_chunk()
            cs.read_sectors(ex_sectors)
            cs.ensure_consumed()
            sc, cid = cs.next_chunk()
            ex_eof = cs.read_sectors(1)
            assert cid == 0xFFFFFFFF and ex_eof[:20] == b"FJIMGBR_PBKLABEL_EOF"

        print(f"Stream integrity OK! {cs.chunks_read:,} chunks, {in_use_count:,} in-use MFT records, "
              f"{ms.total_read:,} compressed bytes ({time.time() - t0:.1f}s).")

        # Finalize multi-extent ($ATTRIBUTE_LIST) files in verify mode
        if mode == "verify" and multi_files:
            for owner, fpath in multi_files.items():
                rsz = file_real_size.get(owner, 0)
                isz = file_init_size.get(owner, rsz)
                with open(fpath, "r+b") as fh:
                    fh.truncate(min(isz, rsz))
                    fh.truncate(rsz)
                crc_acc = 0
                rem = rsz
                with open(fpath, "rb") as fh:
                    while rem > 0:
                        blk = fh.read(min(rem, 1024 * 1024))
                        if not blk:
                            blk = b"\x00" * min(rem, 1024 * 1024)
                        crc_acc = zlib.crc32(blk, crc_acc)
                        rem -= len(blk)
                file_crc[owner] = crc_acc & 0xFFFFFFFF

        # Build all resolved Windows paths (supporting hardlinks; excluding pure DOS 8.3 aliases when Win32 exists)
        # For each MFT entry, group (parent_ref, name, ns) by parent_ref and prefer ns in (0, 1, 3) over ns==2 (DOS)
        dir_primary_name: Dict[int, Tuple[int, str]] = {}
        file_links: Dict[int, List[Tuple[int, str]]] = {}

        for mft_ref, nlist in names.items():
            if mft_ref < 16:
                continue
            by_parent: Dict[int, List[Tuple[str, int]]] = {}
            for pref, fname, ns in nlist:
                by_parent.setdefault(pref, []).append((fname, ns))
            resolved_links: List[Tuple[int, str]] = []
            for pref, cand in by_parent.items():
                non_dos = [fn for fn, ns in cand if ns != 2]
                if non_dos:
                    for fn in non_dos:
                        resolved_links.append((pref, fn))
                else:
                    resolved_links.append((pref, cand[0][0]))
            file_links[mft_ref] = resolved_links
            if is_dir_map.get(mft_ref, False) and resolved_links:
                dir_primary_name[mft_ref] = resolved_links[0]

        dir_path_cache: Dict[int, Optional[str]] = {5: ""}

        def get_dir_path(dref: int, depth: int = 0) -> Optional[str]:
            if dref in dir_path_cache:
                return dir_path_cache[dref]
            if depth > 128 or dref not in dir_primary_name:
                dir_path_cache[dref] = None
                return None
            pref, dname = dir_primary_name[dref]
            pp = get_dir_path(pref, depth + 1)
            if pp is None:
                dir_path_cache[dref] = None
                return None
            res = f"{pp}\\{dname}"
            dir_path_cache[dref] = res
            return res

        # Map lowercase Windows path -> (mft_ref, exact_win_path, is_dir)
        all_paths: List[Tuple[int, str, bool]] = []
        path_lookup: Dict[str, Tuple[int, str, bool]] = {}
        for mft_ref, links in file_links.items():
            is_d = is_dir_map.get(mft_ref, False)
            for pref, fname in links:
                pp = get_dir_path(pref)
                if pp is None:
                    continue
                wpath = f"{pp}\\{fname}"
                all_paths.append((mft_ref, wpath, is_d))
                path_lookup[wpath.lower()] = (mft_ref, wpath, is_d)

        # In extract mode, finalize staged files (truncate to valid init_sz then extend to real_sz)
        # BEFORE optional CRC verification so --verify-crc sees exact NTFS-valid bytes.
        if mode == "extract":
            for mft_ref, sp in staged_files.items():
                rsz = file_real_size.get(mft_ref, 0)
                isz = file_init_size.get(mft_ref, rsz)
                with open(sp, "r+b") as fh:
                    fh.truncate(min(isz, rsz))
                    fh.truncate(rsz)
                mt = mtime_map.get(mft_ref)
                if mt is not None:
                    try:
                        os.utime(sp, (mt, mt))
                    except OSError:
                        pass

        # Verify against .crc manifest if requested/available
        if crc_raw is not None:
            manifest = parse_crc_manifest(crc_raw)
            print(f"Verifying {len(manifest):,} entries against .crc manifest...")
            ok_files = 0
            ok_dirs = 0
            missing = []
            size_mismatch = []
            crc_mismatch = []

            for mpath_low, (exp_sz, exp_crc) in manifest.items():
                found = path_lookup.get(mpath_low)
                if found is None:
                    missing.append(mpath_low)
                    continue
                mft_ref, _, is_d = found
                if exp_sz is None:
                    ok_dirs += 1
                else:
                    actual_sz = file_real_size.get(mft_ref, 0)
                    if actual_sz != exp_sz:
                        size_mismatch.append((mpath_low, exp_sz, actual_sz))
                        continue
                    if mode == "verify":
                        actual_crc = file_crc.get(mft_ref, 0)
                    else:
                        # Compute CRC32 from staged file if present
                        sp = staged_files.get(mft_ref)
                        if sp is not None and sp.exists():
                            crc_acc = 0
                            rem = actual_sz
                            with open(sp, "rb") as fh:
                                while rem > 0:
                                    b = fh.read(min(rem, 1024 * 1024))
                                    if not b:
                                        b = b"\x00" * min(rem, 1024 * 1024)
                                    crc_acc = zlib.crc32(b, crc_acc)
                                    rem -= len(b)
                            actual_crc = crc_acc & 0xFFFFFFFF
                        else:
                            actual_crc = 0
                    if actual_crc != exp_crc:
                        crc_mismatch.append((mpath_low, exp_crc, actual_crc))
                    else:
                        ok_files += 1

            print(f"  Verified files: {ok_files:,} OK")
            print(f"  Verified dirs:  {ok_dirs:,} OK")
            print(f"  Missing:        {len(missing)}")
            print(f"  Size mismatch:  {len(size_mismatch)}")
            print(f"  CRC mismatch:   {len(crc_mismatch)}")
            for item in missing[:10]:
                print(f"    [MISSING] {item}")
            for p_l, es, asz in size_mismatch[:10]:
                print(f"    [SIZE] {p_l}: expected={es} actual={asz}")
            for p_l, ec, ac in crc_mismatch[:10]:
                print(f"    [CRC]  {p_l}: expected=0x{ec:08x} actual=0x{ac:08x}")
            if missing or size_mismatch or crc_mismatch:
                sys.exit(1)

        if mode == "extract":
            assert out_dir is not None
            filt = glob_filter.lower() if glob_filter else None
            extracted_files = 0
            extracted_dirs = 0

            # Place files/dirs into output tree (using hardlinks for NTFS hardlinked files!)
            placed_primary: Dict[int, Path] = {}
            for mft_ref, wpath, is_d in sorted(all_paths, key=lambda x: x[1]):
                if filt and not fnmatch.fnmatch(wpath.lower(), filt):
                    continue
                rel = wpath.lstrip("\\").replace("\\", "/")
                # Safety check against path traversal
                dest = (out_dir / rel).resolve()
                if not str(dest).startswith(str(out_dir.resolve())):
                    continue
                if is_d:
                    dest.mkdir(parents=True, exist_ok=True)
                    extracted_dirs += 1
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if dest.exists():
                        dest.unlink()
                    if mft_ref in placed_primary:
                        try:
                            os.link(placed_primary[mft_ref], dest)
                        except OSError:
                            shutil.copy2(placed_primary[mft_ref], dest)
                    elif mft_ref in staged_files:
                        shutil.move(str(staged_files[mft_ref]), str(dest))
                        placed_primary[mft_ref] = dest
                    else:
                        # 0-byte file with no $DATA attribute
                        dest.touch()
                        placed_primary[mft_ref] = dest
                    extracted_files += 1

            print(f"Extracted {extracted_files:,} files and {extracted_dirs:,} directories -> {out_dir} "
                  f"({time.time() - t0:.1f}s)")
    finally:
        ms.close()
        if multi_tmp_dir is not None and multi_tmp_dir.exists():
            shutil.rmtree(multi_tmp_dir, ignore_errors=True)
        if staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def cmd_verify(args):
    img = Fc2ImageSet(args.inputs)
    crc_raw = None if args.no_crc else img.read_crc_manifest(args.crc)
    _run_logical_pass(img, mode="verify", crc_raw=crc_raw)


def cmd_extract(args):
    img = Fc2ImageSet(args.inputs)
    crc_raw = img.read_crc_manifest(args.crc) if args.verify_crc else None
    _run_logical_pass(
        img,
        mode="extract",
        out_dir=Path(args.output),
        glob_filter=args.filter,
        crc_raw=crc_raw,
    )


# =============================================================================
# CLI Entrypoint
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Fujitsu DataCloningWizard (.fc2 / DPIMGFHD2) Recovery Image Unpacker"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="Display image headers, partition info, and metadata")
    p_info.add_argument("inputs", nargs="+", help="Recovery .iso files or .fc2/.002/.003 files")
    p_info.set_defaults(func=cmd_info)

    p_img = sub.add_parser("unpack-img", help="Reconstruct sparse raw NTFS partition (or full disk) image")
    p_img.add_argument("inputs", nargs="+", help="Recovery .iso files or .fc2/.002/.003 files")
    p_img.add_argument("-o", "--output", required=True, help="Output raw image path (e.g. partition.img)")
    p_img.add_argument("--full-disk", action="store_true",
                       help="Emit full MBR disk image (MBR + Track 0 + Partition 1 at StartSector)")
    p_img.add_argument("--save-meta", help="Optional directory to dump mbr.bin, track0_exrec.bin, pbklabel_hdr.bin")
    p_img.set_defaults(func=cmd_unpack_img)

    p_ext = sub.add_parser("extract", help="Extract files directly to a directory tree")
    p_ext.add_argument("inputs", nargs="+", help="Recovery .iso files or .fc2/.002/.003 files")
    p_ext.add_argument("-o", "--output", required=True, help="Output directory")
    p_ext.add_argument("--filter", help="Optional case-insensitive Windows path glob (e.g. '\\Fujitsu\\*')")
    p_ext.add_argument("--verify-crc", action="store_true", help="Verify against .crc manifest before placing files")
    p_ext.add_argument("--crc", help="Optional explicit path to .crc manifest file")
    p_ext.set_defaults(func=cmd_extract)

    p_ver = sub.add_parser("verify", help="Verify entire stream integrity and check all files against .crc")
    p_ver.add_argument("inputs", nargs="+", help="Recovery .iso files or .fc2/.002/.003 files")
    p_ver.add_argument("--crc", help="Optional explicit path to .crc manifest file")
    p_ver.add_argument("--no-crc", action="store_true", help="Skip .crc file check (verify stream only)")
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
