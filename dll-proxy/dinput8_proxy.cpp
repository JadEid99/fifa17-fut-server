/**
 * dinput8.dll Proxy - v23
 * 
 * v22 found 11 candidates and crashed by setting too many bytes.
 * The real ProtoSSLRefT struct is at 0x2A7CE278 — it has pointer-like
 * values at -0x10 and -0x08 (pSock and pHost).
 * 
 * v23: Only patch structs that have pointer-like values before strHost.
 * Only set ONE byte at strHost + 0x120 (bAllowAnyCert offset from source).
 * If that doesn't work, try +0x118, +0x128, +0x130 one at a time.
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

static int FindAndPatchStruct() {
    static const char host[] = "winter15.gosredirector.ea.com";
    static const SIZE_T hostLen = 29;
    int patched = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x300 &&
            mbi.Protect == PAGE_READWRITE) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0x20; j + hostLen + 0x200 < size; j++) {
                    if (base[j] != 'w' || memcmp(base + j, host, hostLen) != 0) continue;
                    if (base[j + hostLen] != 0x00) continue;
                    
                    BYTE* strHost = base + j;
                    
                    // The REAL ProtoSSLRefT struct has pointers before strHost.
                    // strHost is at +0x20 in the struct, so:
                    //   struct_base + 0x00 = pSock (8 bytes, non-zero pointer)
                    //   struct_base + 0x08 = pHost (8 bytes, pointer or null)
                    //   struct_base + 0x10 = iMemGroup (4 bytes)
                    //   struct_base + 0x18 = pMemGroupUserData (8 bytes, pointer)
                    //   struct_base + 0x20 = strHost
                    
                    // Check if -0x10 and -0x08 look like pointers (high bytes non-zero)
                    if (j < 0x20) continue;
                    
                    uint64_t val_m10 = *(uint64_t*)(strHost - 0x10);
                    uint64_t val_m08 = *(uint64_t*)(strHost - 0x08);
                    
                    // At least one should look like a pointer (> 0x10000)
                    bool hasPointers = (val_m10 > 0x10000 || val_m08 > 0x10000);
                    if (!hasPointers) continue;
                    
                    // Skip HTTP buffers
                    bool isHTTP = false;
                    for (int scan = -0x60; scan < 0 && !isHTTP; scan++) {
                        if (j + scan >= 4) {
                            if (memcmp(base + j + scan, "POST", 4) == 0) isHTTP = true;
                            if (memcmp(base + j + scan, "HTTP", 4) == 0) isHTTP = true;
                            if (memcmp(base + j + scan, "find", 4) == 0) isHTTP = true;
                        }
                    }
                    if (isHTTP) continue;
                    
                    Log("REAL ProtoSSLRefT: strHost at %p", strHost);
                    Log("  pSock?=%p pHost?=%p", (void*)val_m10, (void*)val_m08);
                    
                    // Dump bytes around the expected bAllowAnyCert location
                    // Source says: strHost(+0x20) -> PeerAddr(+0x120) -> iState(+0x130) -> iClosed(+0x134) -> pSecure(+0x138) -> bAllowAnyCert(+0x140)
                    // From strHost: bAllowAnyCert = +0x120
                    // But FIFA 17 struct may differ. Dump +0x100 to +0x160
                    char hex[256]; int hlen = 0;
                    for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", strHost[0x100+h]);
                    Log("  +0x100: %s", hex);
                    hlen = 0;
                    for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", strHost[0x120+h]);
                    Log("  +0x120: %s", hex);
                    hlen = 0;
                    for (int h = 0; h < 32; h++) hlen += sprintf(hex+hlen, "%02X ", strHost[0x140+h]);
                    Log("  +0x140: %s", hex);
                    
                    // Set ONLY the byte at +0x120 to 0x01 (bAllowAnyCert from source)
                    BYTE oldVal = strHost[0x120];
                    strHost[0x120] = 0x01;
                    Log("  SET strHost[+0x120] from 0x%02X to 0x01", oldVal);
                    
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
        Log("=== FIFA 17 SSL Bypass v23 (surgical bAllowAnyCert at +0x120) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        DWORD startTick = GetTickCount();
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindAndPatchStruct();
                if (r > 0) Log("Scan %d (%lus): patched %d (total: %d)", i, elapsed/1000, r, g_patched);
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
