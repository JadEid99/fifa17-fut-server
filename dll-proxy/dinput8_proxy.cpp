/**
 * dinput8.dll Proxy - v22
 * 
 * New approach: Instead of finding bAllowAnyCert in the struct,
 * patch the code that CHECKS bAllowAnyCert.
 * 
 * From the DirtySDK source, _ProtoSSLUpdateRecvServerCert does:
 *   if (!pState->bAllowAnyCert) {
 *       // hostname check + cert verify
 *   }
 * 
 * In x64 assembly, this is something like:
 *   cmp byte ptr [rcx+0x140], 0   ; or similar offset
 *   jne skip_verification
 *   ... verification code ...
 *   skip_verification:
 * 
 * We can find this by searching for the error string references.
 * The function prints "x509 cert untrusted" on failure.
 * We search for that string, find the code that references it,
 * and patch the conditional jump before it.
 * 
 * But simpler: search for "x509 cert" or "cert untrusted" strings
 * in memory, then look at the code nearby.
 * 
 * ACTUALLY SIMPLEST: The function returns ST_FAIL_CERT on failure.
 * We can search for the pattern where it loads bAllowAnyCert and
 * tests it. In x64, testing a byte in a struct looks like:
 *   test byte ptr [reg+offset], 0xFF  or  cmp byte ptr [reg+offset], 0
 * followed by a conditional jump.
 * 
 * Let's just find ALL "cert" related strings and dump nearby code.
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

// From v21 results, HOST STRING #5 at 0x27E51C0C looks like the ProtoSSLRefT struct.
// It has zeros before it (struct fields) and structured data after.
// The -0x20 offset shows all zeros, suggesting strHost starts at the beginning
// of a large zero-initialized region.
//
// But we don't know the exact offset of bAllowAnyCert.
// 
// NEW STRATEGY: Find the ProtoSSLRefT struct by looking for the strHost field
// that has a POINTER before it (pSock, pHost, etc.) and set bAllowAnyCert
// by scanning for the byte pattern.
//
// Actually, the SIMPLEST approach that should work:
// Find "winter15.gosredirector.ea.com" in heap memory (protect=0x4 = PAGE_READWRITE)
// where the -0x20 area is mostly zeros (indicating start of struct).
// Then set EVERY byte from +0x100 to +0x200 that is currently 0x00 to 0x01.
// One of them will be bAllowAnyCert. The others are padding/unused fields
// that won't matter.

static int g_patched = 0;

static int FindAndPatchStruct() {
    static const char host[] = "winter15.gosredirector.ea.com";
    static const SIZE_T hostLen = 29;
    int patched = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x300 &&
            mbi.Protect == PAGE_READWRITE) { // heap memory only
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0x40; j + hostLen + 0x200 < size; j++) {
                    if (base[j] != 'w' || memcmp(base + j, host, hostLen) != 0) continue;
                    if (base[j + hostLen] != 0x00) continue;
                    
                    // Check if -0x20 area is mostly zeros (struct beginning)
                    int zeroCount = 0;
                    for (int k = 0; k < 32; k++) {
                        if (base[j - 0x20 + k] == 0x00) zeroCount++;
                    }
                    if (zeroCount < 20) continue; // not a struct, skip
                    
                    // Also check: should NOT have "POST " or "HTTP" nearby
                    // (those are HTTP request buffers, not the struct)
                    bool isHTTP = false;
                    for (int scan = -0x60; scan < 0; scan++) {
                        if (j + scan >= 4 && memcmp(base + j + scan, "POST", 4) == 0) isHTTP = true;
                        if (j + scan >= 4 && memcmp(base + j + scan, "HTTP", 4) == 0) isHTTP = true;
                    }
                    if (isHTTP) continue;
                    
                    // Also skip if "findCACertificates" is nearby (URL buffer)
                    bool isURL = false;
                    for (int scan = -0x60; scan < 0; scan++) {
                        if (j + scan >= 8 && memcmp(base + j + scan, "findCACe", 8) == 0) isURL = true;
                    }
                    if (isURL) continue;
                    
                    Log("CANDIDATE ProtoSSLRefT at %p (strHost at %p)", base + j - 0x20, base + j);
                    
                    // Dump context
                    char hex[256]; int hlen;
                    hlen = 0;
                    for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", base[j-0x20+h]);
                    Log("  -0x20: %s", hex);
                    hlen = 0;
                    for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", base[j+h]);
                    Log("  +0x00: %s", hex);
                    
                    // Set bytes at offsets 0x100-0x1A0 from strHost to 0x01
                    // where they are currently 0x00
                    int setBits = 0;
                    for (int off = 0x100; off < 0x1A0; off++) {
                        if (j + off >= size) break;
                        if (base[j + off] == 0x00) {
                            base[j + off] = 0x01;
                            setBits++;
                        }
                    }
                    Log("  Set %d zero-bytes to 0x01 in range +0x100 to +0x19F", setBits);
                    patched++;
                    g_patched++;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return patched;
}

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v22 (targeted struct patch) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        DWORD startTick = GetTickCount();
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindAndPatchStruct();
                if (r > 0) Log("Scan %d (%lus): patched %d", i, elapsed/1000, r);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            
            if (i % 60 == 0 && i > 0) {
                Log("Heartbeat: %d, %lus, patched=%d", i, elapsed/1000, g_patched);
            }
        }
        Log("=== Done. patched=%d ===", g_patched);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("FATAL");
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
