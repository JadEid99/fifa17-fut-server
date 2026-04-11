/**
 * dinput8.dll Proxy for FIFA 17 SSL Bypass - v7
 * 
 * v6 findings: DLL thread died silently after initial scan.
 * Likely cause: GetModuleHandleExA or other API calls crashing
 * in Denuvo-protected process.
 * 
 * v7 changes:
 * - Remove all GetModuleHandleExA calls (suspected crash cause)
 * - Add SEH around the entire scan loop, not just inner scan
 * - Log at start of every major operation so we can see where it dies
 * - Simpler diagnostic: just count OTG string occurrences, no module lookup
 * - Add a heartbeat log every 5 seconds so we know the thread is alive
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct IUnknown;
typedef IUnknown* LPUNKNOWN;

// ============================================================
// DirectInput8 forwarding
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
// Our CA cert (804 bytes DER)
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

// Search patterns
static const BYTE g_otgPattern[] = "Online Technology Group"; // 23 bytes
static const SIZE_T g_otgPatternLen = 23;
static const char g_setCACertStr[] = "installed CA cert";
static const SIZE_T g_setCACertStrLen = 17;


// ============================================================
// Safe memory scan helper - wraps entire region scan in SEH
// ============================================================

// Scan a single memory region for a byte pattern. Returns count of matches.
// Logs each match address. Entirely wrapped in SEH.
static int ScanRegionForPattern(BYTE* base, SIZE_T size, const BYTE* pattern, SIZE_T patLen, const char* label, bool logEach) {
    int count = 0;
    __try {
        for (SIZE_T j = 0; j + patLen <= size; j++) {
            if (base[j] == pattern[0] && memcmp(base + j, pattern, patLen) == 0) {
                count++;
                if (logEach) {
                    Log("  %s at %p (offset +%llu in region %p)", label, base + j, (unsigned long long)j, base);
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // region became invalid mid-scan
    }
    return count;
}

// ============================================================
// Strategy 1: Full memory scan for DER certs with "OTG" + CA:TRUE
// ============================================================

static int g_certReplacements = 0;

static int ScanAndReplaceCerts() {
    BYTE caTrue[] = {0x30,0x03,0x01,0x01,0xFF};
    int replaced = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) { // any readable page
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + 820 < size; j++) {
                    if (base[j] != 0x30 || base[j+1] != 0x82) continue;
                    
                    uint16_t len = (base[j+2] << 8) | base[j+3];
                    if (len < 300 || len > 1500) continue;
                    SIZE_T cs = len + 4;
                    if (j + cs > size) continue;
                    
                    // Must contain "Online Technology Group"
                    int hasOTG = 0;
                    for (SIZE_T k = 0; k + g_otgPatternLen <= cs; k++) {
                        if (memcmp(base + j + k, g_otgPattern, g_otgPatternLen) == 0) { hasOTG = 1; break; }
                    }
                    if (!hasOTG) { j += 3; continue; }
                    
                    // Must have CA:TRUE
                    int hasCA = 0;
                    for (SIZE_T k = 0; k + 5 <= cs; k++) {
                        if (memcmp(base + j + k, caTrue, 5) == 0) { hasCA = 1; break; }
                    }
                    if (!hasCA) { j += cs - 1; continue; }
                    
                    // Skip our own cert (exact match)
                    if (cs == g_ourCACertLen && memcmp(base + j, g_ourCACert, g_ourCACertLen) == 0) {
                        j += cs - 1; continue;
                    }
                    
                    Log("FOUND EA CA cert at %p size=%llu protect=0x%lx", base + j, (unsigned long long)cs, mbi.Protect);
                    
                    // Log first 32 bytes
                    char hex[100];
                    int hlen = 0;
                    for (int h = 0; h < 16 && h < (int)cs; h++)
                        hlen += sprintf(hex + hlen, "%02X ", base[j+h]);
                    Log("  Bytes: %s", hex);
                    
                    DWORD op;
                    if (VirtualProtect(base + j, cs, PAGE_READWRITE, &op)) {
                        if (cs >= g_ourCACertLen) {
                            memcpy(base + j, g_ourCACert, g_ourCACertLen);
                            if (cs > g_ourCACertLen) memset(base + j + g_ourCACertLen, 0, cs - g_ourCACertLen);
                        } else {
                            memcpy(base + j, g_ourCACert, cs);
                        }
                        VirtualProtect(base + j, cs, op, &op);
                        replaced++;
                        g_certReplacements++;
                        Log("REPLACED at %p (total: %d)", base + j, g_certReplacements);
                    } else {
                        Log("VirtualProtect FAILED at %p err=%lu", base + j, GetLastError());
                    }
                    j += cs - 1;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // skip
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return replaced;
}

// ============================================================
// Strategy 2: Count "Online Technology Group" strings in memory
// (lightweight diagnostic - no module lookups)
// ============================================================

static int CountOTGStrings() {
    int total = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 100 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            total += ScanRegionForPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize,
                g_otgPattern, g_otgPatternLen, "OTG", true);
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return total;
}

// ============================================================
// Strategy 3: Count "installed CA cert" strings
// ============================================================

static int CountSetCACertStrings() {
    int total = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 100 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            total += ScanRegionForPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize,
                (const BYTE*)g_setCACertStr, g_setCACertStrLen, "SetCACert", true);
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return total;
}


// ============================================================
// Background Thread - with full SEH protection and heartbeat
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v7 (safe diagnostics) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Phase 1: Initial cert scan
        Log("Phase 1: initial cert scan...");
        int r = ScanAndReplaceCerts();
        Log("Phase 1 done: %d replaced", r);
        
        // Phase 2: Loop with cert scan + periodic diagnostics
        int totalReplaced = r;
        DWORD startTick = GetTickCount();
        int loopCount = 0;
        bool did5s = false, did15s = false, did30s = false, did60s = false;
        
        while (true) {
            Sleep(200);
            loopCount++;
            DWORD elapsed = GetTickCount() - startTick;
            
            // Stop after 3 minutes
            if (elapsed > 180000) break;
            
            // Cert replacement scan every iteration
            __try {
                r = ScanAndReplaceCerts();
                totalReplaced += r;
                if (r > 0) Log("Loop %d (%lus): replaced %d (total: %d)", loopCount, elapsed/1000, r, totalReplaced);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Loop %d: cert scan EXCEPTION", loopCount);
            }
            
            // Heartbeat every 5 seconds
            if (elapsed >= 5000 && !did5s) {
                did5s = true;
                Log("--- 5s heartbeat: loop=%d, replaced=%d ---", loopCount, totalReplaced);
                
                // Diagnostic: count OTG strings
                Log("Searching for 'Online Technology Group' strings...");
                __try {
                    int otg = CountOTGStrings();
                    Log("OTG strings found: %d", otg);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("OTG search EXCEPTION");
                }
            }
            
            if (elapsed >= 15000 && !did15s) {
                did15s = true;
                Log("--- 15s heartbeat: loop=%d, replaced=%d ---", loopCount, totalReplaced);
                
                // Diagnostic: search for SetCACert string
                Log("Searching for 'installed CA cert' string...");
                __try {
                    int scc = CountSetCACertStrings();
                    Log("SetCACert strings found: %d", scc);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("SetCACert search EXCEPTION");
                }
            }
            
            if (elapsed >= 30000 && !did30s) {
                did30s = true;
                Log("--- 30s heartbeat: loop=%d, replaced=%d ---", loopCount, totalReplaced);
                
                // Another OTG search (Denuvo should be fully unpacked by now)
                Log("30s OTG search...");
                __try {
                    int otg = CountOTGStrings();
                    Log("30s OTG strings: %d", otg);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("30s OTG search EXCEPTION");
                }
            }
            
            if (elapsed >= 60000 && !did60s) {
                did60s = true;
                Log("--- 60s heartbeat: loop=%d, replaced=%d ---", loopCount, totalReplaced);
            }
        }
        
        Log("=== Done. loops=%d, total_replaced=%d ===", loopCount, totalReplaced);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("FATAL: PatchThread top-level exception!");
    }
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
