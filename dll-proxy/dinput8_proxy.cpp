/**
 * dinput8.dll Proxy for FIFA 17 SSL Bypass - v6
 * 
 * APPROACH: Aggressive CA cert replacement with multiple strategies.
 * 
 * Previous findings:
 * - IAT hooking: FAILED (Denuvo resolves Winsock via GetProcAddress, not IAT)
 * - Trampoline hooking: CRASHED (modifying code in Denuvo-protected process)
 * - Periodic scan: Found 0 certs (timing issue - cert not in memory yet)
 * 
 * New strategy:
 * 1. Scan VERY aggressively - every 100ms, starting immediately
 * 2. Also scan the game's .rdata/.data sections specifically
 * 3. Also search for the cert by looking for the "installed CA cert" string
 *    reference and patching the cert data pointer
 * 4. When we find ANY EA cert, replace it AND log the exact address
 *    so we can understand where it lives
 * 5. Also try: find the SetCACert function by string reference and
 *    patch the cert data it loads
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
static bool g_logInit = false;

static void Log(const char* fmt, ...) {
    if (!g_logInit) return;
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

// Unique bytes from EA's ORIGINAL CA cert that differ from ours.
// We extracted these from the find_cert_on_disk.js scan that found the cert
// in our own dinput8.dll. The EA cert has a different public key and signature.
// We'll search for the issuer string "Online Technology Group" which is common
// to both EA's cert and ours, plus "CA:TRUE" marker.

// Search pattern: the OID + "Online Technology Group" in DER encoding
// This appears in the Subject of the CA cert
static const BYTE g_searchPattern[] = {
    0x4F,0x6E,0x6C,0x69,0x6E,0x65,0x20,0x54,0x65,0x63,0x68,0x6E,0x6F,0x6C,0x6F,0x67,
    0x79,0x20,0x47,0x72,0x6F,0x75,0x70  // "Online Technology Group"
};
static const SIZE_T g_searchPatternLen = 23;

// "installed CA cert" string to find the SetCACert function
static const char g_setCACertStr[] = "installed CA cert";


// ============================================================
// Strategy 1: Full memory scan for DER certificates
// ============================================================

static int g_certReplacements = 0;

static int ScanAndReplaceCerts() {
    BYTE caTrue[] = {0x30,0x03,0x01,0x01,0xFF}; // CA:TRUE
    int replaced = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
            
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
                    for (SIZE_T k = 0; k + g_searchPatternLen <= cs; k++) {
                        if (memcmp(base + j + k, g_searchPattern, g_searchPatternLen) == 0) { hasOTG = 1; break; }
                    }
                    if (!hasOTG) { j += 3; continue; }
                    
                    // Must have CA:TRUE
                    int hasCA = 0;
                    for (SIZE_T k = 0; k + 5 <= cs; k++) {
                        if (memcmp(base + j + k, caTrue, 5) == 0) { hasCA = 1; break; }
                    }
                    if (!hasCA) { j += cs - 1; continue; }
                    
                    // Skip our own cert
                    if (cs == g_ourCACertLen && memcmp(base + j, g_ourCACert, g_ourCACertLen) == 0) {
                        j += cs - 1; continue;
                    }
                    
                    // Found an EA CA cert!
                    Log("FOUND EA CA cert at %p size=%llu protect=0x%lx region=%p+%llu",
                        base + j, (unsigned long long)cs, mbi.Protect,
                        mbi.BaseAddress, (unsigned long long)mbi.RegionSize);
                    
                    // Log first 32 bytes for identification
                    char hex[128];
                    for (int h = 0; h < 16 && h < (int)cs; h++)
                        sprintf(hex + h*3, "%02X ", base[j+h]);
                    Log("  First 16 bytes: %s", hex);
                    
                    // Try to replace
                    DWORD op;
                    if (VirtualProtect(base + j, cs, PAGE_READWRITE, &op)) {
                        if (cs >= g_ourCACertLen) {
                            memcpy(base + j, g_ourCACert, g_ourCACertLen);
                            if (cs > g_ourCACertLen) memset(base + j + g_ourCACertLen, 0, cs - g_ourCACertLen);
                        } else {
                            // Our cert is bigger - just copy what fits
                            memcpy(base + j, g_ourCACert, cs);
                        }
                        VirtualProtect(base + j, cs, op, &op);
                        replaced++;
                        g_certReplacements++;
                        Log("REPLACED at %p (total: %d)", base + j, g_certReplacements);
                    } else {
                        Log("VirtualProtect FAILED at %p error=%lu", base + j, GetLastError());
                    }
                    j += cs - 1;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Skip bad regions
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return replaced;
}

// ============================================================
// Strategy 2: Search for "Online Technology Group" string
// anywhere in memory (not just in DER cert structure)
// This catches the cert even if it's stored differently
// ============================================================

static int ScanForOTGString() {
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 100 &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + g_searchPatternLen < size; j++) {
                    if (memcmp(base + j, g_searchPattern, g_searchPatternLen) == 0) {
                        found++;
                        // Check if this is inside a DER cert (look backwards for 0x30 0x82)
                        int isDER = 0;
                        for (int back = 4; back < 200 && j >= (SIZE_T)back; back++) {
                            if (base[j - back] == 0x30 && base[j - back + 1] == 0x82) {
                                uint16_t len = (base[j - back + 2] << 8) | base[j - back + 3];
                                if (len >= 300 && len <= 1500) {
                                    isDER = 1;
                                    Log("OTG string at %p is inside DER cert at %p (len=%d)",
                                        base + j, base + j - back, len + 4);
                                    break;
                                }
                            }
                        }
                        if (!isDER) {
                            // Log module info for this address
                            HMODULE mod = NULL;
                            char modName[MAX_PATH] = "unknown";
                            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)(base + j), &mod);
                            if (mod) GetModuleFileNameA(mod, modName, MAX_PATH);
                            Log("OTG string at %p (not in DER cert) module=%s protect=0x%lx",
                                base + j, modName, mbi.Protect);
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return found;
}

// ============================================================
// Strategy 3: Find "installed CA cert" string reference
// ============================================================

static void FindSetCACertString() {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int found = 0;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 100 &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            SIZE_T slen = strlen(g_setCACertStr);
            
            __try {
                for (SIZE_T j = 0; j + slen < size; j++) {
                    if (memcmp(base + j, g_setCACertStr, slen) == 0) {
                        found++;
                        HMODULE mod = NULL;
                        char modName[MAX_PATH] = "unknown";
                        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(base + j), &mod);
                        if (mod) GetModuleFileNameA(mod, modName, MAX_PATH);
                        Log("'installed CA cert' string at %p module=%s", base + j, modName);
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    Log("Found %d instances of 'installed CA cert' string", found);
}


// ============================================================
// Background Thread
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v6 (aggressive cert scan) ===");
    Log("Process ID: %lu", GetCurrentProcessId());
    
    HMODULE mainExe = GetModuleHandleA(NULL);
    char exePath[MAX_PATH];
    GetModuleFileNameA(mainExe, exePath, MAX_PATH);
    Log("Main exe: %s at %p", exePath, mainExe);
    
    // Phase 1: Immediate scan (game just loaded, Denuvo may not have unpacked yet)
    Log("Phase 1: Initial scan...");
    int r = ScanAndReplaceCerts();
    Log("Initial scan: %d certs replaced", r);
    
    // Phase 2: Aggressive scanning every 100ms for 3 minutes
    // Also do string searches periodically for diagnostics
    int totalReplaced = r;
    int scanCount = 0;
    int maxScans = 1800; // 3 minutes at 100ms
    bool didStringSearch = false;
    bool didSetCACertSearch = false;
    
    for (int i = 0; i < maxScans; i++) {
        Sleep(100);
        scanCount++;
        
        r = ScanAndReplaceCerts();
        totalReplaced += r;
        if (r > 0) {
            Log("Scan #%d: replaced %d (total: %d)", scanCount, r, totalReplaced);
        }
        
        // At 5 seconds, do a diagnostic string search
        if (i == 50 && !didStringSearch) {
            didStringSearch = true;
            Log("--- Diagnostic: searching for 'Online Technology Group' strings ---");
            int otgCount = ScanForOTGString();
            Log("Found %d OTG string instances", otgCount);
        }
        
        // At 10 seconds, search for SetCACert string
        if (i == 100 && !didSetCACertSearch) {
            didSetCACertSearch = true;
            Log("--- Diagnostic: searching for 'installed CA cert' string ---");
            FindSetCACertString();
        }
        
        // At 20 seconds, do another OTG search (Denuvo should be unpacked by now)
        if (i == 200) {
            Log("--- Diagnostic: 20s OTG search ---");
            ScanForOTGString();
        }
        
        // Status every 30 seconds
        if (i % 300 == 0 && i > 0) {
            Log("Status: scan=%d/%d, replaced=%d", scanCount, maxScans, totalReplaced);
        }
    }
    
    Log("=== Scanning complete. Total replaced: %d ===", totalReplaced);
    return 0;
}

// ============================================================
// DLL Entry Point
// ============================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_logCS);
        g_logInit = true;
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
