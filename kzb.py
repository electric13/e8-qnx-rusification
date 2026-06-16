#!/usr/bin/env python3
"""
KZB Tools GUI - Engineering Interface
Thread-safe UI with progress monitoring
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import struct
from pathlib import Path
from typing import List, Callable
import queue
import hashlib

FZBF_SIGN = b'KZBF'
HEADER_SIZE = 0x4C

def file_to_bytes(p: Path) -> bytearray:
    with open(p, 'rb') as f:
        return bytearray(f.read())

def buffer_to_file(out_path: Path, buf: bytes):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(buf)

_WIN_RESERVED = {
    "CON","PRN","AUX","NUL",
    *(f"COM{i}" for i in range(1,10)),
    *(f"LPT{i}" for i in range(1,10)),
}

def _strip_controls(s: str) -> str:
    return ''.join(ch for ch in s if ch != '\x00' and ord(ch) >= 32)

def _fix_reserved(seg: str) -> str:
    seg = seg.rstrip(" .")
    if not seg or seg.upper() in _WIN_RESERVED:
        return f"_{seg or 'unnamed'}_"
    return seg

def sanitize_name(raw: str, fallback: str) -> str:
    s = _strip_controls(raw)
    s = (s.replace('\\', '/')
           .replace('/', '_')
           .replace(':', '_')
           .replace('*', '_')
           .replace('?', '_')
           .replace('"', "'")
           .replace('<', '(')
           .replace('>', ')')
           .replace('|', '_'))
    s = _fix_reserved(s.strip())
    return s if s else fallback

def sanitize_path(p: str) -> Path:
    p = p.replace('\\', '/')
    parts = []
    for seg in p.split('/'):
        if seg in ('', '.', '..'):
            continue
        parts.append(shorten_segment(sanitize_name(seg, "unnamed"), 80))
    return Path(*parts)

def shorten_segment(seg: str, limit: int = 80) -> str:
    if len(seg) <= limit:
        return seg
    h = hashlib.md5(seg.encode('utf-8', 'ignore')).hexdigest()[:8]
    base, dot, ext = seg.rpartition('.')
    if dot and base:
        keep = max(1, limit - len(h) - 1 - len(ext) - 1)
        return f"{base[:keep]}_{h}.{ext}"
    keep = max(1, limit - 1 - len(h))
    return f"{seg[:keep]}_{h}"

def fit_path_under(base_dir: Path, rel_path: Path, max_total: int = 240) -> Path:
    parts = [shorten_segment(p, 80) for p in rel_path.parts]
    rel2 = Path(*parts)
    full = base_dir / rel2
    if len(str(full)) <= max_total:
        return rel2

    original_last = parts[-1]
    for limit in (80, 64, 48, 32, 24):
        parts[-1] = shorten_segment(original_last, limit)
        rel2 = Path(*parts)
        if len(str(base_dir / rel2)) <= max_total:
            return rel2

    h = hashlib.md5(original_last.encode('utf-8', 'ignore')).hexdigest()[:16]
    parts[-1] = h
    return Path(*parts)

def escape_path(p: str) -> Path:
    return sanitize_path(p)

def read_be_string(buf: bytearray, idx: int, max_len: int = 0x400):
    if idx + 2 > len(buf):
        raise RuntimeError("EOF while reading string length")
    slen = be16(buf[idx:idx+2]); idx += 2
    slen_cap = min(slen, max_len)
    if idx + slen_cap > len(buf):
        slen_cap = max(0, len(buf) - idx)
    raw = bytes(buf[idx:idx+slen_cap]); idx += slen_cap
    nul = raw.find(b'\x00')
    if nul >= 0:
        raw = raw[:nul]
    try:
        txt = raw.decode('utf-8', errors='ignore')
    except Exception:
        txt = ''
    aligned_idx = align4_idx(idx)
    return txt, aligned_idx, slen

def align4_idx(idx: int) -> int:
    return (idx + 3) & ~3

def be16(b: bytes) -> int:
    return struct.unpack('>H', b)[0]

def be32(b: bytes) -> int:
    return struct.unpack('>I', b)[0]

def put_be16(v: int) -> bytes:
    return struct.pack('>H', v & 0xFFFF)

def put_be32(v: int) -> bytes:
    return struct.pack('>I', v & 0xFFFFFFFF)

class KZBProcessor:
    def __init__(self, log_callback, progress_callback=None):
        self.log = log_callback
        self.progress_callback = progress_callback
        self.G_extract = True
        self.G_extract_path = Path()
        self.G_idx = 0
        self.G_bin = bytearray()
        self.total_files = 0
        self.processed_files = 0

    def update_progress(self, current: int, total: int, message: str = ""):
        if self.progress_callback:
            self.progress_callback(current, total, message)

    def count_files_in_folder(self, prefix: Path, count: int, depth: int) -> int:
        file_count = 0
        saved_idx = self.G_idx
        
        for i in range(count):
            if self.G_idx + 16 > len(self.G_bin):
                break
            addr = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            size = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            self.G_idx += 8
            raw_name, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
            file_count += 1
        
        self.G_idx = saved_idx
        return file_count

    def count_total_files(self) -> int:
        saved_idx = self.G_idx
        saved_extract = self.G_extract
        self.G_extract = False
        
        try:
            str_sz = be16(self.G_bin[self.G_idx:self.G_idx+2]); self.G_idx += 2
            self.G_idx += str_sz
            self.G_idx = align4_idx(self.G_idx)
            
            self.G_idx += 4 * 4
            count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            
            total = 0
            for _ in range(count):
                total += self.count_folder_files(Path(), 1)
                
        except Exception as e:
            self.log(f"[WARNING] Could not count files: {e}")
            total = 100
        finally:
            self.G_idx = saved_idx
            self.G_extract = saved_extract
            
        return total

    def count_folder_files(self, prefix: Path, depth: int) -> int:
        file_count = 0
        
        if self.G_idx + 4 > len(self.G_bin):
            return 0
            
        size = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
        raw_name, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
        
        if self.G_idx + 4 > len(self.G_bin):
            return 0
            
        count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
        last_folder = (count == 0)
        
        if last_folder:
            if self.G_idx + 4 > len(self.G_bin):
                return 0
            elem_count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            file_count += elem_count
            for _ in range(elem_count):
                if self.G_idx + 16 > len(self.G_bin):
                    break
                self.G_idx += 16
                _, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
        else:
            for _ in range(count):
                child_files = self.count_folder_files(prefix, depth+1)
                file_count += child_files
            
            if self.G_idx + 4 <= len(self.G_bin):
                next_val = be32(self.G_bin[self.G_idx:self.G_idx+4])
                if next_val < 1000:
                    elem_count2 = next_val; self.G_idx += 4
                    file_count += elem_count2
                    for _ in range(elem_count2):
                        if self.G_idx + 16 > len(self.G_bin):
                            break
                        self.G_idx += 16
                        _, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
                        
        return file_count

    def extract_resource(self, resource_path: Path, address: int, size: int):
        start = address + 4
        end = start + size
        
        if end > len(self.G_bin):
            raise RuntimeError(f"Resource bounds exceed file size: {end} > {len(self.G_bin)}")
            
        safe_rel = fit_path_under(self.G_extract_path, resource_path, 240)
        buffer_to_file(self.G_extract_path / safe_rel, self.G_bin[start:end])
        
        self.processed_files += 1
        if self.total_files > 0:
            self.update_progress(self.processed_files, self.total_files, 
                               f"Extracting: {resource_path.name}")

    def parse_elements(self, prefix: Path, count: int, depth: int) -> int:
        for i in range(count):
            if self.G_idx + 16 > len(self.G_bin):
                raise RuntimeError("Unexpected EOF reading element")
                
            addr = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            size = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            unk1 = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
            unk2 = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4

            raw_name, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
            safe_name = sanitize_name(raw_name, f"elem_{addr:08x}")

            file_path = prefix / escape_path(safe_name)
            self.log("  "*depth + f"[FILE] {safe_name} | addr=0x{addr:08x} size={size}")

            if self.G_extract:
                self.extract_resource(file_path, addr, size)
        return 0

    def parse_folder(self, prefix: Path, depth: int) -> int:
        if self.G_idx + 4 > len(self.G_bin):
            raise RuntimeError("Unexpected EOF reading folder size")
            
        size = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
        raw_name, self.G_idx, _ = read_be_string(self.G_bin, self.G_idx)
        safe_name = sanitize_name(raw_name, f"folder_{self.G_idx:08x}")

        if self.G_idx + 4 > len(self.G_bin):
            raise RuntimeError("Unexpected EOF reading folder count")
            
        count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
        last_folder = (count == 0)
        
        if last_folder:
            if self.G_idx + 4 > len(self.G_bin):
                raise RuntimeError("Unexpected EOF reading element count")
            elem_count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
        else:
            elem_count = None

        folder_path = prefix / f"Folder_{safe_name}"
        self.log("  "*depth + f"[DIR ] {safe_name} | children={count}")

        if self.G_extract:
            (self.G_extract_path / escape_path(str(folder_path))).mkdir(parents=True, exist_ok=True)

        if last_folder:
            self.parse_elements(folder_path, elem_count, depth+1)
        else:
            processed_size = 0
            for _ in range(count):
                processed_size += self.parse_folder(folder_path, depth+1)
            if processed_size != size:
                if self.G_idx + 4 > len(self.G_bin):
                    self.log("  "*depth + "[WARN] EOF before mixed folder elements")
                    return size
                elem_count2 = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4
                self.log("  "*depth + f"[MIX ] {elem_count2} additional files")
                self.parse_elements(folder_path, elem_count2, depth+1)

        return size

    def parse_kzb(self, in_file: Path):
        self.G_idx = HEADER_SIZE

        self.total_files = self.count_total_files()
        self.processed_files = 0
        self.log(f"[INFO] Estimated files: {self.total_files}")
        
        self.G_idx = HEADER_SIZE

        str_sz = be16(self.G_bin[self.G_idx:self.G_idx+2]); self.G_idx += 2
        root_name = self.G_bin[self.G_idx:self.G_idx+str_sz].decode('utf-8', errors='ignore')
        self.G_idx += str_sz
        self.G_idx = align4_idx(self.G_idx)

        self.G_idx += 4 * 4
        count = be32(self.G_bin[self.G_idx:self.G_idx+4]); self.G_idx += 4

        self.log(f"[ROOT] {root_name} | top_folders={count}")
        for _ in range(count):
            self.parse_folder(Path(), 1)

        self.log(f"[DONE] Extraction completed at offset 0x{self.G_idx:x}")

    def extract_resource_kzbf(self, resource_path: Path, address: int, size: int):
        if address + size > len(self.G_bin):
            raise RuntimeError(f"KZBF resource bounds exceed file size")
            
        safe_rel = fit_path_under(self.G_extract_path, resource_path, 240)
        path = (self.G_extract_path / safe_rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path = path.with_name('r_' + path.name)
        buffer_to_file(path, self.G_bin[address:address+size])
        
        self.processed_files += 1
        if self.total_files > 0:
            self.update_progress(self.processed_files, self.total_files,
                               f"Extracting: {resource_path.name}")

    def parse_kzbf(self, in_file: Path):
        import json
        def need(n: int):
            if self.G_idx + n > len(self.G_bin):
                raise RuntimeError("KZBF: unexpected EOF while parsing")

        need(4)
        _unk = int.from_bytes(self.G_bin[self.G_idx:self.G_idx+4], 'little'); self.G_idx += 4
        need(4)
        str_sz = int.from_bytes(self.G_bin[self.G_idx:self.G_idx+4], 'little'); self.G_idx += 4
        need(str_sz)
        root_name = self.G_bin[self.G_idx:self.G_idx+str_sz].decode('utf-8', errors='ignore')
        self.G_idx += str_sz
        self.G_idx = align4_idx(self.G_idx)
        need(4)
        count = int.from_bytes(self.G_bin[self.G_idx:self.G_idx+4], 'little'); self.G_idx += 4
        if count == 0 and self.G_idx + 4 <= len(self.G_bin):
            next_val = int.from_bytes(self.G_bin[self.G_idx:self.G_idx+4], 'little')
            if next_val > 0:
                count = next_val
                self.G_idx += 4

        nodes = []
        raw_nodes = []
        for _ in range(count):
            sbytes = []
            while self.G_idx < len(self.G_bin) and self.G_bin[self.G_idx] != 0:
                sbytes.append(self.G_bin[self.G_idx])
                self.G_idx += 1
            if self.G_idx >= len(self.G_bin):
                raise RuntimeError("KZBF: unterminated node string")
            self.G_idx += 1
            node_raw = bytes(sbytes).decode('utf-8', errors='ignore')
            node = sanitize_name(node_raw, f"node_{len(nodes):04d}")
            nodes.append(node)
            raw_nodes.append(node_raw)

        self.log(f"[KZBF] Node count: {len(nodes)}")
        self.total_files = len(nodes)
        self.processed_files = 0

        need(4)
        elem_count = int.from_bytes(self.G_bin[self.G_idx:self.G_idx+4], 'little'); self.G_idx += 4
        elems = []
        for _ in range(elem_count):
            need(24)
            idx, unk1, addr, size, unk4, unk5 = struct.unpack('<6I', self.G_bin[self.G_idx:self.G_idx+24])
            self.G_idx += 24
            elems.append((idx, unk1, addr, size, unk4, unk5))

        for i, node in enumerate(nodes):
            idx, _unk1, addr, size, unk4, unk5 = elems[i]
            self.log(f"[{idx:04d}] 0x{addr:08x} | {size:8d} bytes | {node}")

        meta_nodes = []
        for i, node in enumerate(nodes):
            idx, unk1, addr, size, unk4, unk5 = elems[i]
            local = addr
            target = escape_path(node)
            is_png = '.png' in node.lower()
            is_font = '.ttf' in node.lower() or '.otf' in node.lower()
            is_loc = False
            
            data_to_extract = b''
            
            if is_png:
                header = self.G_bin[local:local+24]
                if len(header) >= 24 and header[0:16] == b'\x00' * 16:
                    local += 24
                    data_to_extract = self.G_bin[local:local+size-24]
                else:
                    is_png = False
                    data_to_extract = self.G_bin[local:local+size]
            elif is_font:
                header = self.G_bin[local:local+8]
                if len(header) >= 8 and header[0:4] == b'\x00' * 4:
                    local += 8
                    data_to_extract = self.G_bin[local:local+size-8]
                else:
                    is_font = False
                    data_to_extract = self.G_bin[local:local+size]
            else:
                data_to_extract = self.G_bin[local:local+size]
            
            target_name = 'r_' + target.name
            
            if not is_png and not is_font:
                d = data_to_extract
                parsed_loc = None
                parsed_meta = []
                if len(d) >= 16 and d[:12] == b'\x00'*12:
                    meta_n = int.from_bytes(d[12:16], 'little')
                    header_size = 16 + meta_n * 4
                    if len(d) >= header_size + 4:
                        for j in range(meta_n):
                            parsed_meta.append(int.from_bytes(d[16 + j*4 : 20 + j*4], 'little'))
                        count = int.from_bytes(d[header_size:header_size+4], 'little')
                        s_idx = header_size + 4
                        strings = []
                        valid = True
                        while s_idx < len(d):
                            end = d.find(b'\x00', s_idx)
                            if end == -1:
                                valid = False; break
                            try:
                                s = d[s_idx:end].decode('utf-8')
                            except UnicodeDecodeError:
                                valid = False; break
                            strings.append(s)
                            s_idx = end + 1
                        
                        if valid and ((count > 0 and len(strings) == count * 2) or (count == 0 and len(strings) == 0)):
                            res = {"__meta__": parsed_meta, "strings": {}}
                            for j in range(count):
                                res["strings"][strings[j*2]] = strings[j*2+1]
                            parsed_loc = res
                
                if parsed_loc is not None:
                    is_loc = True
                    target_name += '.json'
                    data_to_extract = json.dumps(parsed_loc, indent=4, ensure_ascii=False).encode('utf-8')

            meta_nodes.append({
                "orig": raw_nodes[i],
                "target": target_name,
                "idx": idx,
                "unk1": unk1,
                "unk4": unk4,
                "is_png": is_png,
                "is_font": is_font,
                "is_loc": is_loc
            })
            
            if self.G_extract:
                safe_rel = fit_path_under(self.G_extract_path, target, 240)
                out_path = (self.G_extract_path / safe_rel)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path = out_path.with_name(target_name)
                buffer_to_file(out_path, data_to_extract)
                self.processed_files += 1
                if self.total_files > 0:
                    self.update_progress(self.processed_files, self.total_files, f"Extracting: {target.name}")

        if self.G_extract:
            meta = {
                "format": "KZBF",
                "unk": _unk,
                "root_name": root_name,
                "nodes": meta_nodes
            }
            with open(self.G_extract_path / "_kzbf_meta.json", "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

    def unpack(self, in_file: Path) -> Path:
        self.G_extract = True
        self.G_extract_path = in_file.parent / f"{in_file.name}_unpacked"
        self.G_extract_path.mkdir(exist_ok=True)

        self.G_idx = 0
        self.G_bin = file_to_bytes(in_file)

        sign = bytes(self.G_bin[0:4])
        self.G_idx += 4
        if sign != FZBF_SIGN:
            self.parse_kzb(in_file)
        else:
            self.parse_kzbf(in_file)

        return self.G_extract_path


class ElementInfo:
    def __init__(self, name: str, disk_path: Path, size: int):
        self.name = name
        self.disk_path = disk_path
        self.size = size

class FolderNode:
    def __init__(self, name: str):
        self.name = name
        self.children = []
        self.elements = []

class MetaFolderPH:
    def __init__(self, size_pos: int):
        self.size_pos = size_pos

class MetaElemPH:
    def __init__(self, addr_pos: int, element: ElementInfo):
        self.addr_pos = addr_pos
        self.element = element

def build_node_from_fs(p: Path) -> FolderNode:
    name = p.name
    if name.startswith('Folder_'):
        name = name[len('Folder_'):]
    node = FolderNode(name)
    entries = sorted(list(p.iterdir()), key=lambda x: x.name)
    for e in entries:
        if e.is_dir():
            node.children.append(build_node_from_fs(e))
        elif e.is_file():
            node.elements.append(ElementInfo(e.name, e, e.stat().st_size))
    return node

def compute_total_data_size(node: FolderNode) -> int:
    total = sum(4 + el.size for el in node.elements)
    for c in node.children:
        total += compute_total_data_size(c)
    return total

def write_root_header(root_name: str, top_count: int, meta: bytearray):
    meta += put_be16(len(root_name))
    meta += root_name.encode('utf-8', errors='ignore')
    while len(meta) % 4 != 0:
        meta += b'\x00'
    meta += put_be32(0)
    meta += put_be32(0)
    meta += put_be32(0)
    meta += put_be32(0)
    meta += put_be32(top_count)

def write_folder_metadata(node: FolderNode, meta: bytearray,
                          folderPH: List[MetaFolderPH],
                          elemPH: List[MetaElemPH]):
    folderPH.append(MetaFolderPH(len(meta)))
    meta += put_be32(0)

    meta += put_be16(len(node.name))
    meta += node.name.encode('utf-8', errors='ignore')
    while len(meta) % 4 != 0:
        meta += b'\x00'

    if not node.children:
        meta += put_be32(0)
        meta += put_be32(len(node.elements))
        for el in node.elements:
            elemPH.append(MetaElemPH(len(meta), el))
            meta += put_be32(0)
            meta += put_be32(el.size)
            meta += put_be32(0)
            meta += put_be32(0)
            meta += put_be16(len(el.name))
            meta += el.name.encode('utf-8', errors='ignore')
            while len(meta) % 4 != 0:
                meta += b'\x00'
    else:
        meta += put_be32(len(node.children))
        for c in node.children:
            write_folder_metadata(c, meta, folderPH, elemPH)
        if node.elements:
            meta += put_be32(len(node.elements))
            for el in node.elements:
                elemPH.append(MetaElemPH(len(meta), el))
                meta += put_be32(0)
                meta += put_be32(el.size)
                meta += put_be32(0)
                meta += put_be32(0)
                meta += put_be16(len(el.name))
                meta += el.name.encode('utf-8', errors='ignore')
                while len(meta) % 4 != 0:
                    meta += b'\x00'

def pack_kzbf(extracted_dir: Path, output_file: Path, log_callback, progress_callback=None) -> int:
    import json
    meta_path = extracted_dir / "_kzbf_meta.json"
    if not meta_path.exists():
        log_callback(f"[ERROR] KZBF metadata not found: {meta_path}")
        return 2

    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)

    out = bytearray(b'KZBF')
    out.extend(struct.pack('<I', meta['unk']))
    
    root_name = meta['root_name'].encode('utf-8')
    out.extend(struct.pack('<I', len(root_name)))
    out.extend(root_name)
    
    while len(out) % 4 != 0:
        out.append(0)
        
    out.extend(struct.pack('<I', 0))
    out.extend(struct.pack('<I', len(meta['nodes'])))
    
    for node in meta['nodes']:
        out.extend(node['orig'].encode('utf-8'))
        out.append(0)
        
    while len(out) % 4 != 0:
        out.append(0)
        
    out.extend(struct.pack('<I', len(meta['nodes'])))
    
    elem_ph_pos = len(out)
    out.extend(b'\x00' * (24 * len(meta['nodes'])))
    
    while len(out) % 4 != 0:
        out.append(0)
        
    elems_data = []
    total_files = len(meta['nodes'])
    
    for i, node in enumerate(meta['nodes']):
        if progress_callback:
            progress_callback(i + 1, total_files, f"Packing: {node['target']}")
        if i % 100 == 0:
            log_callback(f"[PROG] {i}/{total_files}")
            
        disk_path = extracted_dir / node['target']
        if not disk_path.exists():
            log_callback(f"[WARNING] File not found, packing empty: {disk_path}")
            data = b''
        else:
            if node.get('is_loc'):
                try:
                    with open(disk_path, 'r', encoding='utf-8') as f:
                        loc_dict = json.load(f)
                    out_loc = bytearray(b'\x00' * 12)
                    
                    if '__meta__' in loc_dict and 'strings' in loc_dict:
                        meta_ints = loc_dict['__meta__']
                        strings_dict = loc_dict['strings']
                    else:
                        meta_ints = [0]
                        strings_dict = loc_dict
                        
                    out_loc.extend(struct.pack('<I', len(meta_ints)))
                    for m_val in meta_ints:
                        out_loc.extend(struct.pack('<I', m_val))
                        
                    out_loc.extend(struct.pack('<I', len(strings_dict)))
                    for k, v in strings_dict.items():
                        out_loc.extend(k.encode('utf-8'))
                        out_loc.append(0)
                        out_loc.extend(v.encode('utf-8'))
                        out_loc.append(0)
                    data = bytes(out_loc)
                except Exception as e:
                    log_callback(f"[ERROR] Failed to compile localization JSON {disk_path}: {e}")
                    if output_file.exists():
                        output_file.unlink()
                    raise RuntimeError(f"Failed to process localization file {disk_path.name}: {e}")
            else:
                with open(disk_path, 'rb') as f:
                    data = f.read()
                
        if node['is_png']:
            png_header = struct.pack('<6I', 0, 0, 0, 0, 1, len(data))
            data = png_header + data
        elif node.get('is_font'):
            font_header = struct.pack('<II', 0, len(data))
            data = font_header + data
            
        while len(out) % 4 != 0:
            out.append(0)
            
        addr = len(out)
        size = len(data)
        out.extend(data)
        elems_data.append((node['idx'], node['unk1'], addr, size, node['unk4'], size))
        
    for i, el in enumerate(elems_data):
        pos = elem_ph_pos + (i * 24)
        out[pos:pos+24] = struct.pack('<6I', *el)
        
    while len(out) % 4096 != 0:
        out.append(0)
        
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'wb') as f:
        f.write(out)
        
    log_callback(f"[DONE] KZBF written: {output_file} ({len(out)} bytes)")
    return 0

def pack_kzb(extracted_dir: Path, output_file: Path, log_callback, progress_callback=None) -> int:
    if not extracted_dir.exists() or not extracted_dir.is_dir():
        log_callback(f"[ERROR] Input directory not found: {extracted_dir}")
        return 2
        
    if (extracted_dir / "_kzbf_meta.json").exists():
        return pack_kzbf(extracted_dir, output_file, log_callback, progress_callback)

    root = FolderNode(extracted_dir.name)
    tops = sorted(list(extracted_dir.iterdir()), key=lambda x: x.name)
    for de in tops:
        if de.is_dir():
            root.children.append(build_node_from_fs(de))
        elif de.is_file():
            root.elements.append(ElementInfo(de.name, de, de.stat().st_size))

    meta = bytearray()
    top_count = len(root.children) + (0 if not root.elements else 1)
    write_root_header(root.name, top_count, meta)

    folderPH: List[MetaFolderPH] = []
    elemPH: List[MetaElemPH] = []

    for child in root.children:
        write_folder_metadata(child, meta, folderPH, elemPH)

    if root.elements:
        synth = FolderNode(root.name + "_rootfiles")
        synth.elements = list(root.elements)
        write_folder_metadata(synth, meta, folderPH, elemPH)

    folder_sizes = []
    for child in root.children:
        folder_sizes.append(compute_total_data_size(child))
    if root.elements:
        folder_sizes.append(compute_total_data_size(synth))

    for ph, sz in zip(folderPH, folder_sizes):
        meta[ph.size_pos:ph.size_pos+4] = put_be32(sz)

    out = bytearray(b'\x00' * HEADER_SIZE)
    out[0:4] = b'kzbf'

    out.extend(meta)
    while len(out) % 4 != 0:
        out.append(0)

    log_callback(f"[INFO] Writing {len(elemPH)} resources...")
    total_files = len(elemPH)
    
    for i, ph in enumerate(elemPH):
        if progress_callback:
            progress_callback(i + 1, total_files, f"Packing: {ph.element.name}")
        if i % 100 == 0:
            log_callback(f"[PROG] {i}/{total_files}")
        addr_abs = len(out)
        out[HEADER_SIZE + ph.addr_pos : HEADER_SIZE + ph.addr_pos + 4] = put_be32(addr_abs)
        out.extend(b'\x00\x00\x00\x00')
        with open(ph.element.disk_path, 'rb') as f:
            data = f.read()
        out.extend(data)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'wb') as f:
        f.write(out)
    log_callback(f"[DONE] KZB written: {output_file} ({len(out)} bytes)")
    return 0


class KZBToolsGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("KZB Tools v2.0")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)

        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.check_queues()

        self.create_widgets()

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=(tk.W, tk.E))
        
        ttk.Label(title_frame, text="KZB Archive Tools", 
                 font=('TkDefaultFont', 14, 'bold')).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(title_frame, text="Version 2.0", 
                 font=('TkDefaultFont', 8)).grid(row=0, column=1, padx=(10, 0), sticky=tk.W)
        
        ttk.Separator(main_frame, orient='horizontal').grid(row=1, column=0, columnspan=3, 
                                                            sticky=(tk.W, tk.E), pady=(0, 10))

        # Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        unpack_frame = ttk.Frame(notebook, padding="10")
        notebook.add(unpack_frame, text="Unpack")
        self.create_unpack_tab(unpack_frame)

        pack_frame = ttk.Frame(notebook, padding="10")
        notebook.add(pack_frame, text="Pack")
        self.create_pack_tab(pack_frame)

        # Status bar
        status_frame = ttk.Frame(main_frame, relief=tk.SUNKEN, borderwidth=1)
        status_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        self.status_label = ttk.Label(status_frame, text="Status: Ready", anchor=tk.W)
        self.status_label.pack(fill=tk.X, padx=5, pady=2)

    def create_unpack_tab(self, parent):
        # Input file section
        input_group = ttk.LabelFrame(parent, text="Input Configuration", padding="10")
        input_group.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        parent.columnconfigure(1, weight=1)

        ttk.Label(input_group, text="Archive File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.unpack_input = tk.StringVar()
        ttk.Entry(input_group, textvariable=self.unpack_input, width=70).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(input_group, text="Browse...", 
                  command=self.browse_unpack_input).grid(row=0, column=2)
        
        input_group.columnconfigure(1, weight=1)

        # Control section
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=1, column=0, columnspan=3, pady=(0, 10))
        
        ttk.Button(control_frame, text="Extract Archive", 
                  command=self.unpack_file, width=20).pack()

        # Progress section
        progress_group = ttk.LabelFrame(parent, text="Extraction Progress", padding="10")
        progress_group.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.unpack_status_label = ttk.Label(progress_group, text="Idle")
        self.unpack_status_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.unpack_progress = ttk.Progressbar(progress_group, mode='determinate', length=400)
        self.unpack_progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        progress_info_frame = ttk.Frame(progress_group)
        progress_info_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(progress_info_frame, text="Progress:").pack(side=tk.LEFT)
        self.unpack_progress_label = ttk.Label(progress_info_frame, text="0%")
        self.unpack_progress_label.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(progress_info_frame, text="Files:").pack(side=tk.LEFT)
        self.unpack_files_label = ttk.Label(progress_info_frame, text="0/0")
        self.unpack_files_label.pack(side=tk.LEFT, padx=5)
        
        progress_group.columnconfigure(0, weight=1)

        # Log section
        log_group = ttk.LabelFrame(parent, text="Operation Log", padding="10")
        log_group.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 0))
        parent.rowconfigure(3, weight=1)
        
        log_scroll_frame = ttk.Frame(log_group)
        log_scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        self.unpack_log = scrolledtext.ScrolledText(log_scroll_frame, height=20, width=90, 
                                                    font=('Courier', 9), state='disabled')
        self.unpack_log.pack(fill=tk.BOTH, expand=True)

    def create_pack_tab(self, parent):
        # Input section
        input_group = ttk.LabelFrame(parent, text="Input Configuration", padding="10")
        input_group.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        parent.columnconfigure(1, weight=1)

        ttk.Label(input_group, text="Directory:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.pack_input = tk.StringVar()
        ttk.Entry(input_group, textvariable=self.pack_input, width=70).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(input_group, text="Browse...", 
                  command=self.browse_pack_input).grid(row=0, column=2)
        
        input_group.columnconfigure(1, weight=1)

        # Output section
        output_group = ttk.LabelFrame(parent, text="Output Configuration", padding="10")
        output_group.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(output_group, text="Output File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.pack_output = tk.StringVar()
        ttk.Entry(output_group, textvariable=self.pack_output, width=70).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(output_group, text="Browse...", 
                  command=self.browse_pack_output).grid(row=0, column=2)
        
        output_group.columnconfigure(1, weight=1)

        # Control section
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))
        
        ttk.Button(control_frame, text="Create Archive", 
                  command=self.pack_file, width=20).pack()

        # Progress section
        progress_group = ttk.LabelFrame(parent, text="Packing Progress", padding="10")
        progress_group.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.pack_status_label = ttk.Label(progress_group, text="Idle")
        self.pack_status_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.pack_progress = ttk.Progressbar(progress_group, mode='determinate', length=400)
        self.pack_progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        progress_info_frame = ttk.Frame(progress_group)
        progress_info_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(progress_info_frame, text="Progress:").pack(side=tk.LEFT)
        self.pack_progress_label = ttk.Label(progress_info_frame, text="0%")
        self.pack_progress_label.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(progress_info_frame, text="Files:").pack(side=tk.LEFT)
        self.pack_files_label = ttk.Label(progress_info_frame, text="0/0")
        self.pack_files_label.pack(side=tk.LEFT, padx=5)
        
        progress_group.columnconfigure(0, weight=1)

        # Log section
        log_group = ttk.LabelFrame(parent, text="Operation Log", padding="10")
        log_group.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 0))
        parent.rowconfigure(4, weight=1)
        
        log_scroll_frame = ttk.Frame(log_group)
        log_scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        self.pack_log = scrolledtext.ScrolledText(log_scroll_frame, height=20, width=90,
                                                  font=('Courier', 9), state='disabled')
        self.pack_log.pack(fill=tk.BOTH, expand=True)

    def browse_unpack_input(self):
        filename = filedialog.askopenfilename(
            title="Select KZB/KZBF Archive",
            filetypes=[("KZB files", "*.kzb"), ("KZBF files", "*.kzbf"), ("All files", "*.*")]
        )
        if filename:
            self.unpack_input.set(filename)

    def browse_pack_input(self):
        dirname = filedialog.askdirectory(title="Select Directory to Pack")
        if dirname:
            self.pack_input.set(dirname)

    def browse_pack_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Archive As",
            defaultextension=".kzb",
            filetypes=[("KZB files", "*.kzb"), ("All files", "*.*")]
        )
        if filename:
            self.pack_output.set(filename)

    def log_to_widget(self, widget, message):
        self.log_queue.put((widget, message))

    def update_progress_ui(self, progressbar, status_label, progress_label, files_label, 
                          current, total, message):
        self.progress_queue.put((progressbar, status_label, progress_label, files_label, 
                                current, total, message))

    def check_queues(self):
        # Process log queue
        try:
            while True:
                widget, message = self.log_queue.get_nowait()
                widget.configure(state='normal')
                widget.insert(tk.END, message + '\n')
                widget.see(tk.END)
                widget.configure(state='disabled')
        except queue.Empty:
            pass

        # Process progress queue
        try:
            while True:
                progressbar, status_label, progress_label, files_label, current, total, message = self.progress_queue.get_nowait()
                if total > 0:
                    percent = (current / total) * 100
                    progressbar['value'] = percent
                    progress_label.configure(text=f"{percent:.1f}%")
                    files_label.configure(text=f"{current}/{total}")
                    status_label.configure(text=message)
                    self.status_label.configure(text=f"Status: {message}")
        except queue.Empty:
            pass

        self.root.after(100, self.check_queues)

    def unpack_file(self):
        input_file = self.unpack_input.get()
        if not input_file:
            messagebox.showerror("Error", "Please select an input file")
            return
        if not Path(input_file).exists():
            messagebox.showerror("Error", "Input file does not exist")
            return

        self.unpack_log.configure(state='normal')
        self.unpack_log.delete(1.0, tk.END)
        self.unpack_log.configure(state='disabled')
        self.unpack_progress['value'] = 0
        self.unpack_progress_label.configure(text="0%")
        self.unpack_files_label.configure(text="0/0")
        self.unpack_status_label.configure(text="Initializing extraction...")

        def run_unpack():
            try:
                def progress_callback(current, total, message):
                    self.update_progress_ui(
                        self.unpack_progress,
                        self.unpack_status_label,
                        self.unpack_progress_label,
                        self.unpack_files_label,
                        current, total, message
                    )

                processor = KZBProcessor(
                    lambda msg: self.log_to_widget(self.unpack_log, msg),
                    progress_callback
                )
                output_dir = processor.unpack(Path(input_file))
                
                self.log_to_widget(self.unpack_log, "=" * 70)
                self.log_to_widget(self.unpack_log, "[SUCCESS] Extraction completed")
                self.log_to_widget(self.unpack_log, f"[OUTPUT] {output_dir}")
                self.log_to_widget(self.unpack_log, f"[STATS ] {processor.processed_files} files extracted")
                self.log_to_widget(self.unpack_log, "=" * 70)
                
                self.update_progress_ui(
                    self.unpack_progress,
                    self.unpack_status_label,
                    self.unpack_progress_label,
                    self.unpack_files_label,
                    100, 100, "Extraction complete"
                )
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "Extraction Complete", 
                    f"Archive unpacked successfully\n\nOutput: {output_dir}\nFiles: {processor.processed_files}"
                ))
            except Exception as e:
                self.log_to_widget(self.unpack_log, "=" * 70)
                self.log_to_widget(self.unpack_log, f"[ERROR] {str(e)}")
                self.log_to_widget(self.unpack_log, "=" * 70)
                self.update_progress_ui(
                    self.unpack_progress,
                    self.unpack_status_label,
                    self.unpack_progress_label,
                    self.unpack_files_label,
                    0, 100, "Error occurred"
                )
                self.root.after(0, lambda: messagebox.showerror(
                    "Extraction Failed", 
                    f"Error during unpacking:\n\n{str(e)}"
                ))

        threading.Thread(target=run_unpack, daemon=True).start()

    def pack_file(self):
        input_dir = self.pack_input.get()
        output_file = self.pack_output.get()

        if not input_dir:
            messagebox.showerror("Error", "Please select an input directory")
            return
        if not output_file:
            messagebox.showerror("Error", "Please select an output file")
            return
        if not Path(input_dir).exists():
            messagebox.showerror("Error", "Input directory does not exist")
            return

        self.pack_log.configure(state='normal')
        self.pack_log.delete(1.0, tk.END)
        self.pack_log.configure(state='disabled')
        self.pack_progress['value'] = 0
        self.pack_progress_label.configure(text="0%")
        self.pack_files_label.configure(text="0/0")
        self.pack_status_label.configure(text="Initializing packing...")

        def run_pack():
            try:
                def progress_callback(current, total, message):
                    self.update_progress_ui(
                        self.pack_progress,
                        self.pack_status_label,
                        self.pack_progress_label,
                        self.pack_files_label,
                        current, total, message
                    )

                result = pack_kzb(
                    Path(input_dir),
                    Path(output_file),
                    lambda msg: self.log_to_widget(self.pack_log, msg),
                    progress_callback
                )
                
                if result == 0:
                    self.log_to_widget(self.pack_log, "=" * 70)
                    self.log_to_widget(self.pack_log, "[SUCCESS] Packing completed")
                    self.log_to_widget(self.pack_log, f"[OUTPUT] {output_file}")
                    self.log_to_widget(self.pack_log, "=" * 70)
                    
                    self.update_progress_ui(
                        self.pack_progress,
                        self.pack_status_label,
                        self.pack_progress_label,
                        self.pack_files_label,
                        100, 100, "Packing complete"
                    )
                    
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Packing Complete", 
                        f"Archive created successfully\n\nOutput: {output_file}"
                    ))
                else:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Packing Failed", 
                        "Error during packing. Check log for details."
                    ))
            except Exception as e:
                self.log_to_widget(self.pack_log, "=" * 70)
                self.log_to_widget(self.pack_log, f"[ERROR] {str(e)}")
                self.log_to_widget(self.pack_log, "=" * 70)
                self.update_progress_ui(
                    self.pack_progress,
                    self.pack_status_label,
                    self.pack_progress_label,
                    self.pack_files_label,
                    0, 100, "Error occurred"
                )
                self.root.after(0, lambda: messagebox.showerror(
                    "Packing Failed", 
                    f"Error during packing:\n\n{str(e)}"
                ))

        threading.Thread(target=run_pack, daemon=True).start()

def main():
    root = tk.Tk()
    app = KZBToolsGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
