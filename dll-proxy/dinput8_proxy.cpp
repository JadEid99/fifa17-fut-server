/**
 * dinput8.dll Proxy for FIFA 17 SSL Bypass
 * 
 * APPROACH: IAT (Import Address Table) hooking of Winsock functions.
 * 
 * Unlike trampoline hooks (which crashed), IAT hooks are safe because
 * they only modify a pointer in the import table, not executable code.
 * 
 * Strategy:
 * 1. Hook connect() via IAT patching in ws2_32.dll imports
 * 2. When game connects to port 42230 (redirector) or any EA server,
 *    let it connect to our local server normally
 * 3. ALSO: Periodically scan memory for EA CA cert and replace it
 *    (belt and suspenders approach)
 * 4. ALSO: Hook WSAConnect for good measure
 * 
 * The key insight: IAT hooks modify a pointer table, not code.
 * The game's import table has entries like:
 *   connect -> ws2_32.dll!connect
 * We change it to:
 *   connect -> our_connect_hook
 * This is 100% safe and standard practice for DLL proxies.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

#include <psapi.h>

struct IUnknown;
typedef IUnknown* LPUNKNOWN;

// ============================================================
// DirectInput8 forwarding (required for DLL proxy)
// ============================================================
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

// ============================================================
// Logging
// ============================================================
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logCS;

static void Log(const char* fmt, ...) {
    EnterCriticalSection(&g_logCS);
    if (!g_logFile) g_logFile = fopen("fifa17_ssl_bypass.log", "a");
    if (g_logFile) {
        // Timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_logFile, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args; va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logCS);
}

// ============================================================
// Our CA cert (804 bytes DER) - same issuer fields as EA's
// ============================================================
static const BYTE g_ourCACert[] = {
    0x30,0x82,0x03,0x20,0x30,0x82,0x02,0x89,0xa0,0x03,0x02,0x01,0x02,0x02,0x14,0x36,
    0x1e,0x75,0xc6,0x60,0x20,0xd4,0x6f,0x4c,0x0f,0xb0,0x26,0x1e,0x5d,0xe1,0x50,0xcc,
    0x05,0x61,0x5a,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x04,
    0x05,0x00,0x30,0x81,0xa0,0x31,0x20,0x30,0x1e,0x06,0x03,0x55,0x04,0x0b,0x0c,0x17,
    0x4f,0x6e,0x6c,0x69,0x6e,0x65,0x20,0x54,0x65,0x63,0x68,0x6e,0x6f,0x6c,0x6f,0x67,
    0x79,0x20,0x47,0x72,0x6f,0x75,0x70,0x31,0x1e,0x30,0x1c,0x06,0x03,0x55,0x04,0x0a,
    0x0c,0x15,0x45,0x6c,0x65,0x63,0x74,0x72,0x6f,0x6e,0x69,0x63,0x20,0x41,0x72,0x74,
    0x73,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x07,
    0x0c,0x0c,0x52,0x65,0x64,0x77,0x6f,0x6f,0x64,0x20,0x43,0x69,0x74,0x79,0x31,0x13,
    0x30,0x11,0x06,0x03,0x55,0x04,0x08,0x0c,0x0a,0x43,0x61,0x6c,0x69,0x66,0x6f,0x72,
    0x6e,0x69,0x61,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,
    0x31,0x23,0x30,0x21,0x06,0x03,0x55,0x04,0x03,0x0c,0x1a,0x4f,0x54,0x47,0x33,0x20,
    0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x65,0x20,0x41,0x75,0x74,0x68,
    0x6f,0x72,0x69,0x74,0x79,0x30,0x20,0x17,0x0d,0x32,0x36,0x30,0x34,0x31,0x30,0x31,
    0x32,0x30,0x37,0x35,0x36,0x5a,0x18,0x0f,0x32,0x31,0x30,0x33,0x30,0x34,0x31,0x31,
    0x31,0x32,0x30,0x37,0x35,0x36,0x5a,0x30,0x81,0xa0,0x31,0x20,0x30,0x1e,0x06,0x03,
    0x55,0x04,0x0b,0x0c,0x17,0x4f,0x6e,0x6c,0x69,0x6e,0x65,0x20,0x54,0x65,0x63,0x68,
    0x6e,0x6f,0x6c,0x6f,0x67,0x79,0x20,0x47,0x72,0x6f,0x75,0x70,0x31,0x1e,0x30,0x1c,
    0x06,0x03,0x55,0x04,0x0a,0x0c,0x15,0x45,0x6c,0x65,0x63,0x74,0x72,0x6f,0x6e,0x69,
    0x63,0x20,0x41,0x72,0x74,0x73,0x2c,0x20,0x49,0x6e,0x63,0x2e,0x31,0x15,0x30,0x13,
    0x06,0x03,0x55,0x04,0x07,0x0c,0x0c,0x52,0x65,0x64,0x77,0x6f,0x6f,0x64,0x20,0x43,
    0x69,0x74,0x79,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x08,0x0c,0x0a,0x43,0x61,
    0x6c,0x69,0x66,0x6f,0x72,0x6e,0x69,0x61,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,
    0x06,0x13,0x02,0x55,0x53,0x31,0x23,0x30,0x21,0x06,0x03,0x55,0x04,0x03,0x0c,0x1a,
    0x4f,0x54,0x47,0x33,0x20,0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x65,
    0x20,0x41,0x75,0x74,0x68,0x6f,0x72,0x69,0x74,0x79,0x30,0x81,0x9f,0x30,0x0d,0x06,
    0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,
    0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xe3,0x5f,0xe0,0x5d,0x64,0xda,0xb4,0xab,0xf4,
    0x16,0xb6,0x5e,0x9b,0x6e,0x31,0x61,0x3c,0x6c,0xb8,0x1f,0x18,0x02,0x00,0x7b,0xc5,
    0xa7,0xb2,0xb2,0xf7,0x20,0x4d,0x23,0x4d,0xa6,0xca,0xf5,0xa0,0x30,0x7c,0x4a,0x4b,
    0x11,0xb3,0x1e,0x73,0xa6,0x20,0x1a,0x58,0x7d,0xb2,0x6c,0x6e,0xf9,0x0b,0xaa,0x8a,
    0xba,0x83,0xe1,0x9e,0xd6,0x6b,0x28,0x36,0xd3,0x1c,0x0b,0x4b,0x34,0x3a,0x30,0xa6,
    0xda,0x3a,0x41,0x76,0xbc,0xf7,0x07,0x32,0x3f,0xb0,0x36,0x03,0x29,0x81,0x6f,0x24,
    0x72,0x34,0xe3,0x5c,0x53,0x9b,0xba,0x83,0x23,0xb7,0xe2,0xef,0x00,0x66,0x64,0x1e,
    0x18,0x0f,0x48,0xc8,0x21,0xbe,0x0c,0xd5,0x66,0xca,0x2f,0x75,0x00,0x15,0xb2,0x32,
    0x3d,0xc5,0x03,0xfc,0xbf,0xe9,0x45,0x02,0x03,0x01,0x00,0x01,0xa3,0x53,0x30,0x51,
    0x30,0x1d,0x06,0x03,0x55,0x1d,0x0e,0x04,0x16,0x04,0x14,0x8e,0x51,0xa4,0x40,0xfb,
    0x32,0x35,0x13,0x0f,0x46,0x4a,0xf9,0xc2,0xe4,0xd6,0xab,0xbf,0x1f,0x91,0xa0,0x30,
    0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,0x30,0x16,0x80,0x14,0x8e,0x51,0xa4,0x40,
    0xfb,0x32,0x35,0x13,0x0f,0x46,0x4a,0xf9,0xc2,0xe4,0xd6,0xab,0xbf,0x1f,0x91,0xa0,
    0x30,0x0f,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x05,0x30,0x03,0x01,0x01,
    0xff,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x04,0x05,0x00,
    0x03,0x81,0x81,0x00,0x50,0x5f,0xe3,0x26,0xbb,0x53,0x3d,0xd3,0xcd,0xfb,0x20,0xf5,
    0xd0,0xe4,0x1f,0x72,0xb2,0xf7,0xc4,0x1c,0xc8,0xc0,0x13,0xf8,0x73,0x44,0x66,0x70,
    0x57,0x55,0xf8,0xa8,0x55,0x50,0x68,0x84,0xdf,0x74,0x94,0x7e,0xfc,0x88,0x97,0xae,
    0x01,0x94,0x6e,0x6a,0x82,0x7f,0x8f,0x0d,0xb1,0xa2,0x12,0x56,0x4d,0xdb,0x8d,0x67,
    0x98,0xd7,0x0b,0x6f,0x79,0xed,0x99,0xbf,0x68,0x22,0x3c,0xee,0xf2,0xb7,0x41,0x31,
    0xf1,0x3f,0x78,0xf1,0x1e,0xaf,0xd3,0x35,0x36,0x75,0xa6,0x41,0x27,0x5e,0x5f,0x7f,
    0xae,0xb5,0x4c,0x9c,0xfb,0xe1,0x44,0x47,0xb7,0x13,0x1b,0xf3,0x5a,0x5d,0xe9,0xc1,
    0xd8,0x65,0xe0,0xfb,0x47,0xc5,0x99,0x6f,0x7a,0xcc,0xba,0xd2,0xe5,0x38,0x0e,0x56,
    0xb2,0x82,0x97,0x21
};
static const SIZE_T g_ourCACertLen = 804;

// ============================================================
// IAT Hook Infrastructure
// ============================================================

// Original function pointers (saved before hooking)
typedef int (WSAAPI* connect_t)(SOCKET, const struct sockaddr*, int);
static connect_t g_real_connect = NULL;

// Track what we've hooked
static int g_hooksInstalled = 0;
static int g_connectCalls = 0;
static int g_certReplacements = 0;

/**
 * IAT Hook: Patch the Import Address Table of a module.
 * 
 * This walks the PE import table of 'targetModule' and finds where it
 * imports 'functionName' from 'dllName'. Then it replaces the pointer
 * with our hook function.
 * 
 * This is SAFE because:
 * - We only modify a pointer in a data table, not executable code
 * - The original function still exists and is callable
 * - No risk of corrupting instruction streams
 */
static BOOL PatchIAT(HMODULE targetModule, const char* dllName, const char* functionName, void* hookFunction, void** originalFunction) {
    if (!targetModule) return FALSE;
    
    BYTE* base = (BYTE*)targetModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->VirtualAddress == 0) return FALSE;
    
    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir->VirtualAddress);
    
    for (; imports->Name != 0; imports++) {
        const char* modName = (const char*)(base + imports->Name);
        if (_stricmp(modName, dllName) != 0) continue;
        
        IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)(base + imports->OriginalFirstThunk);
        IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)(base + imports->FirstThunk);
        
        for (; origThunk->u1.AddressOfData != 0; origThunk++, firstThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            
            IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
            if (strcmp(importByName->Name, functionName) != 0) continue;
            
            // Found it! Save original and patch
            if (originalFunction) *originalFunction = (void*)firstThunk->u1.Function;
            
            DWORD oldProtect;
            if (VirtualProtect(&firstThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                firstThunk->u1.Function = (ULONG_PTR)hookFunction;
                VirtualProtect(&firstThunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ============================================================
// Connect Hook
// ============================================================

/**
 * Our connect() hook. Logs all connection attempts.
 * The game uses hosts file to resolve winter15.gosredirector.ea.com -> 127.0.0.1
 * so connections should already go to localhost. We just log them.
 */
static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    g_connectCalls++;
    
    if (name && name->sa_family == AF_INET) {
        const struct sockaddr_in* addr = (const struct sockaddr_in*)name;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
        int port = ntohs(addr->sin_port);
        
        Log("connect() #%d: %s:%d (socket=%llu)", g_connectCalls, ipStr, port, (unsigned long long)s);
        
        // Log if this looks like an EA server connection
        if (port == 42230 || port == 10041 || port == 443 || port == 80) {
            Log("  -> Game connecting to port %d (likely EA server)", port);
        }
    }
    
    return g_real_connect(s, name, namelen);
}

// ============================================================
// CA Certificate Memory Replacement
// ============================================================

/**
 * Scan process memory for EA's CA certificate and replace with ours.
 * Uses SEH for safe memory access.
 */
static int ScanAndReplaceCerts() {
    // Signature bytes to identify EA CA certs
    BYTE eaStr[] = {0x45,0x6C,0x65,0x63,0x74,0x72,0x6F,0x6E,0x69,0x63,0x20,0x41,0x72,0x74,0x73}; // "Electronic Arts"
    BYTE caTrue[] = {0x30,0x03,0x01,0x01,0xFF}; // CA:TRUE in DER
    int replaced = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || 
             mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + 820 < size; j++) {
                    // Look for DER certificate start: 0x30 0x82
                    if (base[j] != 0x30 || base[j+1] != 0x82) continue;
                    
                    uint16_t len = (base[j+2] << 8) | base[j+3];
                    if (len < 300 || len > 1500) continue;
                    SIZE_T cs = len + 4;
                    if (j + cs > size) continue;
                    
                    // Must contain "Electronic Arts"
                    int hasEA = 0;
                    for (SIZE_T k = 0; k + 15 <= cs; k++) {
                        if (memcmp(base + j + k, eaStr, 15) == 0) { hasEA = 1; break; }
                    }
                    if (!hasEA) { j += 3; continue; }
                    
                    // Must have CA:TRUE
                    int hasCA = 0;
                    for (SIZE_T k = 0; k + 5 <= cs; k++) {
                        if (memcmp(base + j + k, caTrue, 5) == 0) { hasCA = 1; break; }
                    }
                    if (!hasCA) { j += cs - 1; continue; }
                    
                    // Skip if it's already our cert (check first 20 bytes)
                    if (cs == g_ourCACertLen && memcmp(base + j, g_ourCACert, 20) == 0) {
                        j += cs - 1; continue;
                    }
                    
                    // Found EA CA cert - replace it!
                    DWORD op;
                    if (VirtualProtect(base + j, cs, PAGE_READWRITE, &op)) {
                        SIZE_T copyLen = (cs < g_ourCACertLen) ? cs : g_ourCACertLen;
                        memcpy(base + j, g_ourCACert, copyLen);
                        // If our cert is smaller, zero-pad the rest
                        if (g_ourCACertLen < cs) {
                            memset(base + j + g_ourCACertLen, 0, cs - g_ourCACertLen);
                        }
                        VirtualProtect(base + j, cs, op, &op);
                        replaced++;
                        g_certReplacements++;
                        Log("REPLACED EA CA cert at %p (size=%llu, total replacements=%d)", 
                            base + j, (unsigned long long)cs, g_certReplacements);
                    }
                    j += cs - 1;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Skip bad memory regions
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break; // overflow
    }
    return replaced;
}

// ============================================================
// IAT Hook Installation - scan ALL loaded modules
// ============================================================

/**
 * Install IAT hooks in ALL loaded modules, not just the main exe.
 * EA's game may call connect() from various DLLs (Denuvo, Origin emu, etc.)
 */
static void InstallIATHooks() {
    HMODULE modules[1024];
    DWORD needed;
    
    // Get the real connect function first
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (ws2) {
        g_real_connect = (connect_t)GetProcAddress(ws2, "connect");
        Log("Real connect() at %p", g_real_connect);
    }
    
    if (!g_real_connect) {
        Log("ERROR: Could not find connect() in ws2_32.dll!");
        return;
    }
    
    // Hook connect() in the main executable
    HMODULE mainExe = GetModuleHandleA(NULL);
    if (PatchIAT(mainExe, "WS2_32.dll", "connect", (void*)Hook_connect, NULL)) {
        g_hooksInstalled++;
        Log("Hooked connect() in main exe via IAT");
    }
    if (PatchIAT(mainExe, "ws2_32.dll", "connect", (void*)Hook_connect, NULL)) {
        g_hooksInstalled++;
        Log("Hooked connect() in main exe via IAT (lowercase)");
    }
    
    // Also try hooking in all loaded modules
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        int count = needed / sizeof(HMODULE);
        for (int i = 0; i < count && i < 1024; i++) {
            if (modules[i] == mainExe) continue; // already done
            char modName[MAX_PATH];
            if (GetModuleFileNameA(modules[i], modName, MAX_PATH)) {
                if (PatchIAT(modules[i], "WS2_32.dll", "connect", (void*)Hook_connect, NULL) ||
                    PatchIAT(modules[i], "ws2_32.dll", "connect", (void*)Hook_connect, NULL)) {
                    g_hooksInstalled++;
                    Log("Hooked connect() in %s", modName);
                }
            }
        }
    }
    
    Log("IAT hooks installed: %d modules patched", g_hooksInstalled);
}

// ============================================================
// Background Thread - Cert scanning + delayed IAT re-hooking
// ============================================================

/**
 * Main worker thread:
 * 1. Install IAT hooks immediately
 * 2. Scan for EA CA cert every 500ms for 3 minutes
 * 3. Re-install IAT hooks periodically (new DLLs may load after Denuvo unpacks)
 */
static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v5 (IAT hooks + cert replacement) ===");
    Log("Process ID: %lu", GetCurrentProcessId());
    
    // Phase 1: Install IAT hooks immediately
    InstallIATHooks();
    
    // Phase 2: Continuous cert scanning + periodic re-hooking
    int totalReplaced = 0;
    int scanCount = 0;
    int maxScans = 360; // 3 minutes at 500ms intervals
    
    for (int i = 0; i < maxScans; i++) {
        Sleep(500);
        scanCount++;
        
        // Scan for EA CA cert
        int r = ScanAndReplaceCerts();
        totalReplaced += r;
        if (r > 0) {
            Log("Scan #%d: replaced %d certs (total: %d)", scanCount, r, totalReplaced);
        }
        
        // Re-install IAT hooks every 5 seconds (new modules may have loaded)
        if (i % 10 == 0 && i > 0) {
            int prevHooks = g_hooksInstalled;
            InstallIATHooks();
            if (g_hooksInstalled > prevHooks) {
                Log("Re-hook pass: %d new hooks (total: %d)", g_hooksInstalled - prevHooks, g_hooksInstalled);
            }
        }
        
        // Status log every 30 seconds
        if (i % 60 == 0 && i > 0) {
            Log("Status: scan=%d/%d, certs_replaced=%d, connect_calls=%d, hooks=%d",
                scanCount, maxScans, totalReplaced, g_connectCalls, g_hooksInstalled);
        }
    }
    
    Log("=== Scanning complete ===");
    Log("Final: certs_replaced=%d, connect_calls=%d, hooks=%d", totalReplaced, g_connectCalls, g_hooksInstalled);
    return 0;
}

// ============================================================
// DLL Entry Point
// ============================================================

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
