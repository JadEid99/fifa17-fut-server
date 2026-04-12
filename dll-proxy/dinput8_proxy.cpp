/**
 * dinput8.dll Proxy - v50: Set REAL bAllowAnyCert at offset 0x384
 * 
 * From Ghidra analysis of FUN_146132210 (cert verification handler):
 *   if (*(char*)(param_1 + 900) != '\0') break;  // skip ALL verification
 * 
 * 900 decimal = 0x384 hex. This is the REAL bAllowAnyCert flag.
 * We were patching 0xC20 before — WRONG offset.
 * 
 * param_1 is the ProtoSSL connection struct. We find it by looking for
 * the hostname string and calculating the offset.
 * 
 * From the Ghidra code, param_1+0x386 is also checked ("ncrt" flag).
 * param_1+0x388 is checked for value 2.
 * We set param_1+0x384 = 1 to bypass everything.
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
                // Search for the hostname "winter15.gosredirector.ea.com" 
                // which is stored in the connection struct
                for (SIZE_T j = 0; j + 0x400 < size; j++) {
                    if (base[j] != 'w') continue;
                    if (memcmp(base + j, "winter15.gosredirector.ea.com", 29) != 0) continue;
                    if (base[j + 29] != 0) continue;
                    
                    // Found hostname. Now we need to figure out what offset
                    // the hostname is at relative to the struct base (param_1).
                    // From Ghidra: FUN_1461364f0(param_1 + 0x58, ...) does hostname match
                    // So hostname might be at param_1 + 0x58.
                    // Then param_1 = hostname_addr - 0x58
                    // And bAllowAnyCert = param_1 + 0x384 = hostname_addr + 0x32C
                    
                    // But we're not sure about the 0x58 offset. Let's try multiple.
                    // Also check: param_1 + 0x168 should be a connection state value
                    
                    BYTE* hostname = base + j;
                    
                    // Try different struct base offsets
                    int offsets[] = {0x58, 0x100, 0x150, 0x200};
                    for (int k = 0; k < 4; k++) {
                        int hostOff = offsets[k];
                        if (j < (SIZE_T)hostOff) continue;
                        
                        BYTE* structBase = hostname - hostOff;
                        
                        // Check if +0x168 has a plausible connection state
                        uint32_t state = *(uint32_t*)(structBase + 0x168);
                        
                        // Set +0x384 regardless (it's just a byte, safe to set)
                        BYTE* flagAddr = structBase + 0x384;
                        if (flagAddr >= base && flagAddr < base + size) {
                            BYTE oldVal = *flagAddr;
                            *flagAddr = 1;
                            // Also set +0x386 (ncrt flag from Ghidra)
                            if (flagAddr + 2 < base + size) {
                                *(flagAddr + 2) = 1;
                            }
                            Log("Set bAllowAnyCert: hostname at %p, struct guess at %p (hostOff=0x%X), state=0x%X, old=0x%02X",
                                hostname, structBase, hostOff, state, oldVal);
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
    Log("=== FIFA 17 SSL Bypass v50 (REAL bAllowAnyCert at +0x384) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    // Scan every 200ms for 5 minutes
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 1500; i++) {
        Sleep(200);
        
        __try {
            SetAllowAnyCert();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        if (i % 50 == 0 && i > 0) {
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
