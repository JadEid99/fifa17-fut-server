/**
 * dinput8.dll Proxy for FIFA 17 SSL Bypass - v8
 * 
 * v7 findings (CRITICAL):
 * - "Online Technology Group" found at 6-7 memory locations
 * - At 5s: 0x541FEE, 0x27CE84E, 0x7FFD4DAC93B0/9475/9698/98FF
 * - At 30s: NEW heap copies at 0x27E12450/27E1F4F0/27E23D37
 * - "installed CA cert" at 0x1439316B1 (main exe +0x39316B1)
 * - BUT cert scan found 0 matches!
 * 
 * The cert IS in memory but our DER cert scanner isn't matching it.
 * Possible reasons:
 * 1. The cert might not start with 0x30 0x82 (maybe stored differently)
 * 2. The length field might be outside our 300-1500 range
 * 3. CA:TRUE might not be present (maybe it's a leaf cert, not CA)
 * 
 * v8 approach: Instead of looking for complete DER certs, look for the
 * "Online Technology Group" string and dump the surrounding bytes.
 * This will tell us EXACTLY what format the cert is stored in.
 * Then we can write a targeted replacement.
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

// Log a hex dump of memory at addr, len bytes
static void LogHexDump(const char* label, BYTE* addr, SIZE_T len) {
    Log("%s at %p (%llu bytes):", label, addr, (unsigned long long)len);
    for (SIZE_T i = 0; i < len; i += 16) {
        char hex[64] = {0};
        char ascii[20] = {0};
        int hpos = 0;
        for (SIZE_T j = i; j < i + 16 && j < len; j++) {
            hpos += sprintf(hex + hpos, "%02X ", addr[j]);
            ascii[j - i] = (addr[j] >= 32 && addr[j] < 127) ? (char)addr[j] : '.';
        }
        ascii[16] = 0;
        Log("  %04llX: %-48s %s", (unsigned long long)i, hex, ascii);
    }
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

static const BYTE g_otgPattern[] = "Online Technology Group";
static const SIZE_T g_otgPatternLen = 23;


// ============================================================
// Targeted analysis: find OTG strings and dump surrounding context
// to understand the cert format
// ============================================================

static int g_certReplacements = 0;

// Find all OTG strings, dump 256 bytes before and 512 bytes after each one.
// Look backwards for 0x30 0x82 to find the DER cert start.
// This is the KEY diagnostic that will tell us the cert format.
static void AnalyzeOTGLocations() {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int found = 0;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 100 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + g_otgPatternLen <= size; j++) {
                    if (base[j] != 'O' || memcmp(base + j, g_otgPattern, g_otgPatternLen) != 0) continue;
                    
                    found++;
                    BYTE* otgAddr = base + j;
                    Log("=== OTG #%d at %p (region %p+%llu, protect=0x%lx) ===",
                        found, otgAddr, base, (unsigned long long)j, mbi.Protect);
                    
                    // Dump 128 bytes BEFORE the OTG string (to find cert start)
                    SIZE_T beforeLen = (j >= 128) ? 128 : j;
                    if (beforeLen > 0) {
                        LogHexDump("  BEFORE OTG", otgAddr - beforeLen, beforeLen);
                    }
                    
                    // Dump 64 bytes starting from OTG
                    SIZE_T afterLen = (j + 64 <= size) ? 64 : (size - j);
                    LogHexDump("  AT OTG", otgAddr, afterLen);
                    
                    // Look backwards for 0x30 0x82 (DER SEQUENCE start)
                    for (int back = 4; back <= 256 && j >= (SIZE_T)back; back++) {
                        if (otgAddr[-back] == 0x30 && otgAddr[-back+1] == 0x82) {
                            uint16_t derLen = (otgAddr[-back+2] << 8) | otgAddr[-back+3];
                            SIZE_T totalLen = derLen + 4;
                            Log("  Possible DER cert at %p (-%d from OTG), length field=%d, total=%llu",
                                otgAddr - back, back, derLen, (unsigned long long)totalLen);
                            
                            // Check if CA:TRUE exists within this cert
                            BYTE caTrue[] = {0x30,0x03,0x01,0x01,0xFF};
                            bool hasCA = false;
                            if (totalLen <= 2000) {
                                for (SIZE_T k = 0; k + 5 <= totalLen; k++) {
                                    if (memcmp(otgAddr - back + k, caTrue, 5) == 0) {
                                        hasCA = true;
                                        break;
                                    }
                                }
                            }
                            Log("  CA:TRUE present: %s", hasCA ? "YES" : "NO");
                            
                            // Dump the first 64 bytes of this potential cert
                            SIZE_T dumpLen = (totalLen < 64) ? totalLen : 64;
                            LogHexDump("  DER cert start", otgAddr - back, dumpLen);
                            break; // only report first match
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("  EXCEPTION scanning region %p", base);
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    Log("Total OTG locations analyzed: %d", found);
}

// ============================================================
// Cert replacement: now with relaxed matching
// Look for 0x30 0x82 with ANY length that contains OTG string
// Don't require CA:TRUE (maybe EA's cert doesn't have it)
// ============================================================

static int ScanAndReplaceCerts() {
    int replaced = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + 400 < size; j++) {
                    if (base[j] != 0x30 || base[j+1] != 0x82) continue;
                    
                    uint16_t len = (base[j+2] << 8) | base[j+3];
                    // Relaxed range: 200 to 2000 bytes
                    if (len < 200 || len > 2000) continue;
                    SIZE_T cs = len + 4;
                    if (j + cs > size) continue;
                    
                    // Must contain "Online Technology Group"
                    int hasOTG = 0;
                    for (SIZE_T k = 0; k + g_otgPatternLen <= cs; k++) {
                        if (memcmp(base + j + k, g_otgPattern, g_otgPatternLen) == 0) { hasOTG = 1; break; }
                    }
                    if (!hasOTG) { j += 3; continue; }
                    
                    // Skip our own cert
                    if (cs == g_ourCACertLen && memcmp(base + j, g_ourCACert, g_ourCACertLen) == 0) {
                        j += cs - 1; continue;
                    }
                    
                    Log("MATCH: DER+OTG at %p size=%llu protect=0x%lx", base + j, (unsigned long long)cs, mbi.Protect);
                    
                    // Log first 32 bytes
                    char hex[100]; int hlen = 0;
                    for (int h = 0; h < 16 && h < (int)cs; h++)
                        hlen += sprintf(hex + hlen, "%02X ", base[j+h]);
                    Log("  Bytes: %s", hex);
                    
                    // Replace with our cert
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
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return replaced;
}


// ============================================================
// Background Thread
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v8 (targeted OTG analysis) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Phase 1: Initial cert scan with relaxed matching
        Log("Phase 1: initial cert scan (relaxed)...");
        int r = ScanAndReplaceCerts();
        Log("Phase 1 done: %d replaced", r);
        int totalReplaced = r;
        
        DWORD startTick = GetTickCount();
        int loopCount = 0;
        bool didAnalysis10s = false;
        bool didAnalysis30s = false;
        
        while (true) {
            Sleep(200);
            loopCount++;
            DWORD elapsed = GetTickCount() - startTick;
            if (elapsed > 180000) break;
            
            // Cert scan every iteration
            __try {
                r = ScanAndReplaceCerts();
                totalReplaced += r;
                if (r > 0) Log("Loop %d (%lus): replaced %d (total: %d)", loopCount, elapsed/1000, r, totalReplaced);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Loop %d: scan EXCEPTION", loopCount);
            }
            
            // At 10 seconds: full OTG analysis with hex dumps
            if (elapsed >= 10000 && !didAnalysis10s) {
                didAnalysis10s = true;
                Log("=== 10s ANALYSIS: dumping all OTG locations ===");
                __try {
                    AnalyzeOTGLocations();
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("OTG analysis EXCEPTION");
                }
            }
            
            // At 30 seconds: another analysis (new heap copies may exist)
            if (elapsed >= 30000 && !didAnalysis30s) {
                didAnalysis30s = true;
                Log("=== 30s ANALYSIS: dumping all OTG locations ===");
                __try {
                    AnalyzeOTGLocations();
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("30s OTG analysis EXCEPTION");
                }
            }
            
            // Heartbeat every 30s
            if (loopCount % 150 == 0) {
                Log("Heartbeat: loop=%d, elapsed=%lus, replaced=%d", loopCount, elapsed/1000, totalReplaced);
            }
        }
        
        Log("=== Done. loops=%d, total_replaced=%d ===", loopCount, totalReplaced);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("FATAL: PatchThread exception!");
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
