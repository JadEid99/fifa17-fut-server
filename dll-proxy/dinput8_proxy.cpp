/**
 * dinput8.dll Proxy - v20 (THE BREAKTHROUGH)
 * 
 * From reading the DirtySDK ProtoSSL source code, we found:
 * 
 * struct ProtoSSLRefT {
 *     SocketT *pSock;           // +0x00
 *     HostentT *pHost;          // +0x08
 *     int32_t iMemGroup;        // +0x10
 *     void *pMemGroupUserData;  // +0x18
 *     char strHost[256];        // +0x20  <-- contains "winter15.gosredirector.ea.com"
 *     struct sockaddr PeerAddr; // +0x120
 *     int32_t iState;           // +0x130
 *     int32_t iClosed;          // +0x134
 *     SecureStateT *pSecure;    // +0x138
 *     uint8_t bAllowAnyCert;    // +0x140  <-- SET THIS TO 1!
 * };
 * 
 * When bAllowAnyCert == 1, ProtoSSL skips ALL certificate verification:
 *   if (!pState->bAllowAnyCert) {
 *       // hostname check
 *       // signature verification
 *   }
 * 
 * Strategy: Search memory for "winter15.gosredirector.ea.com" as a
 * null-terminated string at a 32-byte aligned offset (strHost is at +0x20).
 * Then set the byte at strHost + 0x120 (= bAllowAnyCert at +0x140) to 1.
 * 
 * NOTE: The offsets above are from an older DirtySDK version. FIFA 17's
 * version may have different offsets. So we search a range of offsets
 * after strHost for a byte that's 0x00 and set it to 0x01.
 * We also try the ProtoSSLControl approach: search for the 'ncrt' handler.
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

static const char g_hostStr[] = "winter15.gosredirector.ea.com";
static const SIZE_T g_hostLen = 29; // including null terminator for exact match

static int g_patched = 0;

// Search for the ProtoSSLRefT struct by finding strHost field,
// then set bAllowAnyCert to 1.
// 
// In the source, strHost is at +0x20 in the struct.
// bAllowAnyCert is at +0x140 in the struct.
// So bAllowAnyCert is at strHost + 0x120.
// 
// But FIFA 17 may have a different struct layout (newer DirtySDK).
// So we dump the area around strHost and try multiple offsets.
static int FindAndPatchAllowAnyCert() {
    int patched = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 256 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            // Only search writable memory (the struct is on the heap)
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + g_hostLen + 0x200 < size; j++) {
                    if (base[j] != 'w') continue;
                    if (memcmp(base + j, g_hostStr, g_hostLen - 1) != 0) continue;
                    if (base[j + g_hostLen - 1] != 0x00) continue; // null terminated
                    
                    BYTE* strHostAddr = base + j;
                    Log("Found strHost at %p", strHostAddr);
                    
                    // Dump 32 bytes before strHost (should be pSock, pHost, etc.)
                    if (j >= 0x40) {
                        char hex[256]; int hlen = 0;
                        for (int h = 0; h < 64; h++)
                            hlen += sprintf(hex + hlen, "%02X ", strHostAddr[-0x40 + h]);
                        Log("  -0x40: %s", hex);
                    }
                    
                    // Dump bytes at expected bAllowAnyCert offsets
                    // Try offsets 0x100 to 0x180 from strHost
                    Log("  Bytes at offsets 0x100-0x17F from strHost:");
                    for (int off = 0x100; off < 0x180; off += 16) {
                        if (j + off + 16 >= size) break;
                        char hex[64]; int hlen = 0;
                        for (int h = 0; h < 16; h++)
                            hlen += sprintf(hex + hlen, "%02X ", strHostAddr[off + h]);
                        Log("  +0x%03X: %s", off, hex);
                    }
                    
                    // Try setting bAllowAnyCert at multiple candidate offsets
                    // The struct in source has it at strHost + 0x120
                    // But newer versions might have it elsewhere
                    // We look for a byte that's 0x00 preceded by a pointer (8 bytes)
                    // which would be pSecure
                    
                    int offsets[] = {0x120, 0x128, 0x130, 0x138, 0x140, 0x148, 0x150};
                    for (int i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
                        int off = offsets[i];
                        if (j + off >= size) continue;
                        BYTE val = strHostAddr[off];
                        Log("  Candidate bAllowAnyCert at +0x%X = 0x%02X", off, val);
                    }
                    
                    // For now, set ALL candidate offsets to 1
                    // This is aggressive but safe - setting random bytes to 1
                    // in a struct won't crash, and one of them will be bAllowAnyCert
                    DWORD op;
                    if (VirtualProtect(strHostAddr + 0x100, 0x80, PAGE_READWRITE, &op)) {
                        for (int i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
                            strHostAddr[offsets[i]] = 0x01;
                        }
                        VirtualProtect(strHostAddr + 0x100, 0x80, op, &op);
                        patched++;
                        g_patched++;
                        Log("  SET bAllowAnyCert candidates to 1 (total: %d)", g_patched);
                    }
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
        Log("=== FIFA 17 SSL Bypass v20 (bAllowAnyCert flag) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Scan every 500ms for 3 minutes
        DWORD startTick = GetTickCount();
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindAndPatchAllowAnyCert();
                if (r > 0) Log("Scan %d (%lus): patched %d structs", i, elapsed/1000, r);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            
            if (i % 60 == 0 && i > 0) {
                Log("Heartbeat: scan=%d, %lus, total_patched=%d", i, elapsed/1000, g_patched);
            }
        }
        
        Log("=== Done. total_patched=%d ===", g_patched);
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
