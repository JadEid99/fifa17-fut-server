/**
 * dinput8.dll Proxy - v15
 * 
 * Strategy: Find the parsed CA cert struct in memory and replace
 * the RSA public key modulus with our CA's modulus.
 * 
 * From v8 analysis, the parsed cert fields are stored as null-terminated
 * strings at addresses like 0x27D90A60:
 *   "US" (padded to 32 bytes)
 *   "California" (padded to 32 bytes)  
 *   "Redwood City" (padded to 32 bytes)
 *   "Electronic Arts, Inc." (padded to 32 bytes)
 *   "Online Technology Group" (padded to 32 bytes)
 * 
 * The RSA public key modulus (128 bytes for 1024-bit) should be nearby.
 * This version dumps 2048 bytes around each "Online Technology Group"
 * occurrence that's in the padded-string format (followed by null bytes).
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

// Our CA's RSA modulus (128 bytes, from the 712-byte CA cert we generated)
// This is what we want to replace EA's CA modulus with.
static const BYTE g_ourCAModulus[] = {
    0xcc,0xee,0xf0,0xa2,0xbe,0x51,0x6f,0x51,0x8f,0x17,0xac,0xf9,0xba,0x7a,0x82,0x04,
    0x72,0xce,0xa4,0x7e,0xa7,0x89,0xc8,0xc2,0xc9,0x71,0x05,0x4d,0xb9,0xf3,0xab,0x5b,
    0xfc,0x00,0x5a,0x94,0x86,0x5f,0xff,0xb3,0x0d,0x6b,0xc8,0xdc,0x98,0x6d,0x72,0x24,
    0xd5,0xd2,0xca,0xd2,0x9f,0xe2,0xa4,0x5f,0xa5,0xa7,0x56,0x73,0x75,0x5e,0xf2,0xca,
    0x92,0x3d,0x06,0x95,0xd5,0xf5,0x2f,0x08,0xf4,0x1b,0x56,0xa1,0x0d,0x04,0xce,0x80,
    0x93,0x70,0xaf,0xa7,0x64,0xf9,0x0c,0x38,0x40,0x81,0x07,0x9c,0xfd,0x16,0x71,0xc5,
    0xd7,0x18,0x58,0x2f,0xb6,0x2b,0xc5,0xd4,0x6d,0x4b,0x89,0xf3,0xf5,0xd4,0x04,0x12,
    0x50,0x8c,0x50,0xb5,0x5f,0x5c,0x50,0x69,0x39,0x1c,0x5a,0x3e,0xa3,0xa2,0x7e,0x5d
};

static const BYTE g_otgPattern[] = "Online Technology Group";
static const SIZE_T g_otgLen = 23;

// Search for parsed CA cert structs (padded string format)
// and dump the surrounding memory to find the RSA modulus
static void FindAndDumpParsedCerts() {
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
                for (SIZE_T j = 0; j + g_otgLen < size; j++) {
                    if (memcmp(base + j, g_otgPattern, g_otgLen) != 0) continue;
                    
                    // Check if this is the padded-string format (followed by null bytes)
                    // The parsed struct has each field padded to ~32 bytes
                    bool isPadded = (j + g_otgLen + 5 < size) && 
                                    base[j + g_otgLen] == 0x00 &&
                                    base[j + g_otgLen + 1] == 0x00;
                    
                    if (!isPadded) continue; // skip DER cert occurrences
                    
                    found++;
                    Log("=== PARSED CA STRUCT #%d at %p (region %p, protect=0x%lx) ===",
                        found, base + j, base, mbi.Protect);
                    
                    // Dump 512 bytes BEFORE (should contain US, California, etc.)
                    SIZE_T beforeLen = (j >= 512) ? 512 : j;
                    if (beforeLen > 0) {
                        Log("--- %llu bytes BEFORE OTG ---", (unsigned long long)beforeLen);
                        BYTE* start = base + j - beforeLen;
                        for (SIZE_T i = 0; i < beforeLen; i += 32) {
                            char hex[128] = {0};
                            char ascii[40] = {0};
                            int hlen = 0;
                            SIZE_T lineLen = (i + 32 <= beforeLen) ? 32 : (beforeLen - i);
                            for (SIZE_T k = 0; k < lineLen; k++) {
                                hlen += sprintf(hex + hlen, "%02X ", start[i + k]);
                                ascii[k] = (start[i+k] >= 32 && start[i+k] < 127) ? (char)start[i+k] : '.';
                            }
                            Log("  %04llX: %-96s %s", (unsigned long long)i, hex, ascii);
                        }
                    }
                    
                    // Dump 1024 bytes AFTER (should contain the RSA key)
                    SIZE_T afterLen = (j + 1024 <= size) ? 1024 : (size - j);
                    Log("--- %llu bytes FROM OTG onwards ---", (unsigned long long)afterLen);
                    BYTE* start = base + j;
                    for (SIZE_T i = 0; i < afterLen; i += 32) {
                        char hex[128] = {0};
                        char ascii[40] = {0};
                        int hlen = 0;
                        SIZE_T lineLen = (i + 32 <= afterLen) ? 32 : (afterLen - i);
                        for (SIZE_T k = 0; k < lineLen; k++) {
                            hlen += sprintf(hex + hlen, "%02X ", start[i + k]);
                            ascii[k] = (start[i+k] >= 32 && start[i+k] < 127) ? (char)start[i+k] : '.';
                        }
                        Log("  %04llX: %-96s %s", (unsigned long long)i, hex, ascii);
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    Log("Found %d parsed CA cert structs", found);
}

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v15 (dump parsed CA struct to find RSA key) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Wait 20 seconds for Denuvo to unpack, then dump
        Sleep(20000);
        Log("Starting parsed cert struct search...");
        FindAndDumpParsedCerts();
        
        // Do another dump at 40 seconds
        Sleep(20000);
        Log("Second search at 40s...");
        FindAndDumpParsedCerts();
        
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
