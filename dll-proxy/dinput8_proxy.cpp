/**
 * dinput8.dll Proxy - v21
 * 
 * v20 found 0 instances of "winter15.gosredirector.ea.com" in writable memory.
 * The struct might be in execute+read memory or the string might be shorter.
 * 
 * v21: Search ALL readable memory for "winter15.gosredirector.ea.com",
 * dump the struct context, and try to set bAllowAnyCert.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct IUnknown;
typedef IUnknown* LPUNKNOWN;

typedef HRESULT(WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
static HMODULE g_realDinput8 = NULL;
static DirectInput8Create_t g_realDirectInput8Create = NULL;

static void LoadRealDinput8() {
    if (g_realDinput8) return;
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    strcat_s(systemDir, "\\dinput8.dll");
    g_realDinput8 = LoadLibraryA(systemDir);
    if (g_realDinput8)
        g_realDirectInput8Create = (DirectInput8Create_t)GetProcAddress(g_realDinput8, "DirectInput8Create");
}

extern "C" {
    __declspec(dllexport) HRESULT WINAPI DirectInput8Create(HINSTANCE h, DWORD v, REFIID r, LPVOID* p, LPUNKNOWN u) {
        LoadRealDinput8();
        return g_realDirectInput8Create ? g_realDirectInput8Create(h, v, r, p, u) : E_FAIL;
    }
    __declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) { return S_FALSE; }
    __declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID a, REFIID b, LPVOID* c) { return E_FAIL; }
    __declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) { return E_FAIL; }
    __declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) { return E_FAIL; }
}

static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logCS;

static void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_logCS);
    if (!g_logFile) g_logFile = fopen("fifa17_ssl_bypass.log", "a");
    if (g_logFile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_logFile, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args; va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logCS);
}

static int g_patched = 0;

// Search ALL memory for "winter15.gosredirector.ea.com"
// Log every occurrence with its protection flags and surrounding bytes
static int FindHostStrings() {
    static const char host[] = "winter15.gosredirector.ea.com";
    static const SIZE_T hostLen = 29;
    int found = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 256 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) { // any readable
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + hostLen < size; j++) {
                    if (base[j] != 'w' || memcmp(base + j, host, hostLen) != 0) continue;
                    
                    found++;
                    Log("HOST STRING #%d at %p protect=0x%lx region=%p+%llu",
                        found, base + j, mbi.Protect, base, (unsigned long long)size);
                    
                    // Dump 64 bytes before
                    if (j >= 64) {
                        char hex[256]; int hlen = 0;
                        for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", base[j-64+h]);
                        Log("  -0x40: %s", hex);
                        hlen = 0;
                        for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", base[j-32+h]);
                        Log("  -0x20: %s", hex);
                    }
                    
                    // Dump 256 bytes after the string
                    for (int off = 0; off < 0x180; off += 32) {
                        if (j + hostLen + off + 32 >= size) break;
                        char hex[128]; int hlen = 0;
                        for (int h = 0; h < 32; h++)
                            hlen += sprintf(hex+hlen, "%02X ", base[j + off + h]);
                        Log("  +0x%03X: %s", off, hex);
                    }
                    
                    // Try to set bAllowAnyCert at various offsets
                    // In the struct, strHost is at +0x20, bAllowAnyCert at +0x140
                    // So from strHost, bAllowAnyCert is at +0x120
                    // But struct may be different, so try a range
                    bool didPatch = false;
                    for (int off = 0x100; off <= 0x160; off += 8) {
                        if (j + off >= size) break;
                        DWORD op;
                        if (VirtualProtect(base + j + off, 1, PAGE_READWRITE, &op)) {
                            BYTE oldVal = base[j + off];
                            base[j + off] = 0x01;
                            VirtualProtect(base + j + off, 1, op, &op);
                            Log("  SET byte at +0x%X from 0x%02X to 0x01", off, oldVal);
                            didPatch = true;
                        }
                    }
                    if (didPatch) g_patched++;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return found;
}

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v21 (search ALL memory for host string) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Scan every 500ms for 3 minutes
        DWORD startTick = GetTickCount();
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindHostStrings();
                if (r > 0) Log("Scan %d (%lus): found %d host strings, patched=%d", i, elapsed/1000, r, g_patched);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            
            if (i % 60 == 0 && i > 0) {
                Log("Heartbeat: scan=%d, %lus, patched=%d", i, elapsed/1000, g_patched);
            }
        }
        
        Log("=== Done. patched=%d ===", g_patched);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("FATAL exception");
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_logCS);
        LoadRealDinput8();
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_realDinput8) FreeLibrary(g_realDinput8);
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCS);
    }
    return TRUE;
}
