/**
 * dinput8.dll Proxy - v18
 * 
 * v17: Only found server cert keys. CA cert struct doesn't have 0x0C prefix.
 * 
 * New: Search near the KNOWN CA cert parsed fields (the padded "US",
 * "California", "Redwood City" etc. that DON'T have "winter15" nearby).
 * Dump a large region (4KB) after those fields to find the RSA key
 * in whatever format it's stored.
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

static const BYTE g_otgPadded[] = "Online Technology Group";
static const SIZE_T g_otgLen = 23;

// Find "Online Technology Group" in padded format (null after),
// WITHOUT "winter15" nearby (= CA cert, not server cert).
// Then dump 4KB after it to find the RSA key.
static void DumpCACertRegion() {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int found = 0;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + g_otgLen + 1 < size; j++) {
                    if (base[j] != 'O' || memcmp(base + j, g_otgPadded, g_otgLen) != 0) continue;
                    if (base[j + g_otgLen] != 0x00) continue; // padded format
                    if (j + g_otgLen + 1 < size && base[j + g_otgLen + 1] != 0x00) continue;
                    
                    // Check NO "winter15" within 2KB
                    bool hasWinter = false;
                    for (SIZE_T scan = (j > 0x800 ? j - 0x800 : 0); scan < j + 0x800 && scan + 8 < size; scan++) {
                        if (memcmp(base + scan, "winter15", 8) == 0) { hasWinter = true; break; }
                    }
                    if (hasWinter) continue; // skip server cert structs
                    
                    found++;
                    Log("=== CA CERT STRUCT #%d: OTG at %p ===", found, base + j);
                    
                    // Dump 2KB after OTG to find the key
                    SIZE_T dumpLen = (j + 2048 <= size) ? 2048 : (size - j);
                    for (SIZE_T i = 0; i < dumpLen; i += 32) {
                        char hex[128] = {0};
                        char ascii[40] = {0};
                        int hlen = 0;
                        SIZE_T lineLen = (i + 32 <= dumpLen) ? 32 : (dumpLen - i);
                        for (SIZE_T k = 0; k < lineLen; k++) {
                            hlen += sprintf(hex + hlen, "%02X ", base[j + i + k]);
                            ascii[k] = (base[j+i+k] >= 32 && base[j+i+k] < 127) ? (char)base[j+i+k] : '.';
                        }
                        Log("  %04llX: %-96s %s", (unsigned long long)i, hex, ascii);
                    }
                    
                    if (found >= 2) break; // only dump first 2
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (found >= 2) break;
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    Log("Found %d CA-only cert structs (no winter15 nearby)", found);
}

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 v18 (dump CA cert struct region to find RSA key) ===");
        Log("PID: %lu", GetCurrentProcessId());
        Sleep(25000);
        Log("Searching...");
        DumpCACertRegion();
        Log("=== Done ===");
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
