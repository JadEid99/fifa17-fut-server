/**
 * dinput8.dll Proxy - v51: Patch bAllowAnyCert for BOTH redirector AND main server
 * 
 * v50 only scanned for "winter15.gosredirector.ea.com" hostname.
 * v51 also scans for "127.0.0.1" to catch the main server SSL struct.
 * 
 * The game uses TLS on BOTH connections when secure=1 in the redirect response.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

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

// Hook connect() via IAT to detect when the game connects to port 42230
// Then find the ProtoSSL struct and set bAllowAnyCert
typedef int (WSAAPI* connect_t)(SOCKET, const struct sockaddr*, int);
static connect_t g_real_connect = NULL;
static int g_patched = 0;

// Search for the ProtoSSL connection struct and set offset +0x384 to 1
// The struct is identified by having the hostname at some offset
// and a sockaddr_in with port 42230 at another offset.
// From Ghidra: param_1 is the outer connection struct.
// The hostname is at param_1 + 0x58 area (from FUN_1461364f0 call with param_1+0x58)
// Actually, we need to find the struct differently.
// 
// The Ghidra code shows param_1 + 0x384 is the flag.
// param_1 + 0x386 is another flag.
// param_1 + 0x388 is checked for value 2.
// param_1 + 0x170 is a pointer to the SSL context.
// param_1 + 0x168 is the connection state (0x15, 0x1e, 0x1f, etc.)
//
// The connection state at +0x168 should be between 0x14 and 0x20 during handshake.
// We can search for structs where +0x168 has a value in this range.
//
// But simpler: the Ghidra code for FUN_14612f230 shows param_1[0x2d] which is
// offset 0x168 (0x2d * 8 = 0x168). And param_1[0x2e] = offset 0x170 (SSL context).
// The hostname is stored somewhere we can search for.
//
// SIMPLEST APPROACH: Hook connect() and when port 42230 is detected,
// search ALL writable memory for the connect target address (127.0.0.1:42230)
// in a sockaddr_in struct, then look backwards for the connection struct.
//
// Actually even simpler: the Ghidra code shows the cert handler receives param_1
// which is the same struct used throughout. The flag at +0x384 just needs to be
// set to non-zero. We can scan memory for structs that have the connection state
// value 0x14-0x20 at offset +0x168 and set +0x384 = 1.

static void SetAllowAnyCert() {
    // Search for the pattern: connection state at +0x168 in range 0x14-0x20
    // This identifies active SSL connections
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x400 &&
            mbi.Protect == PAGE_READWRITE) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                // Search for hostnames that indicate ProtoSSL connection structs
                // The redirector uses "winter15.gosredirector.ea.com"
                // The main server uses "127.0.0.1" (from our redirect response)
                const char* hostnames[] = {
                    "winter15.gosredirector.ea.com",
                    "127.0.0.1",
                    NULL
                };
                
                for (const char** hp = hostnames; *hp; hp++) {
                    const char* needle = *hp;
                    int needleLen = (int)strlen(needle);
                    
                    for (SIZE_T j = 0; j + 0x400 < size; j++) {
                        if (base[j] != needle[0]) continue;
                        if (j + needleLen >= size) continue;
                        if (memcmp(base + j, needle, needleLen) != 0) continue;
                        if (base[j + needleLen] != 0) continue;
                        
                        BYTE* hostname = base + j;
                        
                        // hostname is at param_1 + 0x58 (from Ghidra)
                        int hostOff = 0x58;
                        if (j < (SIZE_T)hostOff) continue;
                        
                        BYTE* structBase = hostname - hostOff;
                        
                        // Don't check state - just patch any struct with the hostname
                        // The hostname is written before TLS starts, so we can catch it early
                        BYTE* flagAddr = structBase + 0x384;
                        if (flagAddr >= base && flagAddr < base + size) {
                            uint32_t state = *(uint32_t*)(structBase + 0x168);
                            BYTE oldVal = *flagAddr;
                            *flagAddr = 1;
                            if (oldVal != 1) {
                                Log("SET bAllowAnyCert at %p (struct=%p, host=%s, state=0x%X, old=0x%02X)",
                                    flagAddr, structBase, needle, state, oldVal);
                            }
                            g_patched++;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v51 (bAllowAnyCert for redirector + main server) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    // Scan every 20ms for 5 minutes
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 15000; i++) {
        Sleep(20);
        
        __try {
            SetAllowAnyCert();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        if (i % 200 == 0 && i > 0) {
            DWORD elapsed = GetTickCount() - startTick;
            Log("Progress: scan %d, %lu ms, patches: %d", i, elapsed, g_patched);
        }
    }
    
    Log("=== Done. patches: %d ===", g_patched);
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
