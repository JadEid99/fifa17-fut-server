/**
 * dinput8.dll Proxy - v17
 * 
 * v16 found server cert keys but not the CA cert key.
 * The CA cert struct doesn't use "OTG3 Certificate Authority" as CN
 * in the same padded format, or it's stored differently.
 * 
 * New approach: Search for the 0x80 0x00 0x00 0x00 key-size marker
 * followed by 128 bytes of high-entropy data (RSA modulus).
 * Filter out our known server cert modulus.
 * Log ALL candidates so we can identify the CA's key.
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

// Our CA's RSA modulus (128 bytes)
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

// Our server cert's modulus (first 16 bytes for identification)
static const BYTE g_serverModStart[] = {
    0xAE,0x09,0x93,0x5A,0x26,0x6D,0x20,0x34,0xCB,0xC3,0x7B,0x1B,0x94,0x4E,0xE0,0x6C
};

// Known server cert modulus from v16 logs (first 16 bytes)
static const BYTE g_serverModV16[] = {
    0x13,0x8B,0xFC,0xAE,0xB6,0xB2,0x75,0xEB,0x45,0xF6,0x83,0x1C,0x43,0x8D,0x37,0x3E
};

// Search for "Electronic Arts" in padded format (part of parsed cert struct)
// then look for the 0x80 key size marker and RSA modulus nearby
static void FindAllRSAKeys() {
    static const char eaStr[] = "Electronic Arts";
    static const SIZE_T eaLen = 15;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int found = 0;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & 0xFE)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + eaLen + 1 < size; j++) {
                    if (base[j] != 'E' || memcmp(base + j, eaStr, eaLen) != 0) continue;
                    // Must be padded format (null after string)
                    if (j + eaLen >= size || base[j + eaLen] != ',') continue; // "Electronic Arts, Inc."
                    // Check for null padding after the full string
                    SIZE_T strEnd = j;
                    while (strEnd < size && base[strEnd] != 0) strEnd++;
                    if (strEnd - j > 40) continue; // too long
                    if (strEnd + 1 >= size || base[strEnd + 1] != 0) continue; // not padded
                    
                    // Found a padded "Electronic Arts" field. Search for key size marker nearby.
                    // The key could be 0x100 to 0x600 bytes after this field
                    for (int off = 0x80; off < 0x600; off += 4) {
                        if (j + off + 4 + 128 >= size) break;
                        BYTE* p = base + j + off;
                        
                        // Look for key size = 128 (0x80) as uint32 LE
                        if (p[0] != 0x80 || p[1] != 0x00 || p[2] != 0x00 || p[3] != 0x00) continue;
                        
                        // Also check: 4 bytes before should be 0x0C 0x00 0x00 0x00 (type=12?)
                        // From v15: the pattern was 0C 00 00 00 80 00 00 00 <modulus>
                        if (off >= 4) {
                            BYTE* pp = p - 4;
                            if (pp[0] != 0x0C || pp[1] != 0x00 || pp[2] != 0x00 || pp[3] != 0x00) continue;
                        }
                        
                        BYTE* modulus = p + 4;
                        
                        // Check entropy - at least 12 of first 16 bytes should be non-zero
                        int nonZero = 0;
                        for (int k = 0; k < 16; k++) if (modulus[k] != 0) nonZero++;
                        if (nonZero < 12) continue;
                        
                        found++;
                        
                        // Identify what cert this belongs to
                        bool isServerKey = (memcmp(modulus, g_serverModV16, 16) == 0);
                        bool isOurCA = (memcmp(modulus, g_ourCAModulus, 16) == 0);
                        
                        // Check for "winter15" nearby (server cert indicator)
                        bool hasWinter = false;
                        for (int scan = -0x400; scan < 0x400 && !hasWinter; scan += 32) {
                            SIZE_T pos = j + scan;
                            if (pos < size - 8 && memcmp(base + pos, "winter15", 8) == 0) hasWinter = true;
                        }
                        
                        // Check for "OTG3 Cert" nearby (CA cert indicator)
                        bool hasOTG3 = false;
                        for (int scan = -0x400; scan < 0x400 && !hasOTG3; scan += 32) {
                            SIZE_T pos = j + scan;
                            if (pos < size - 10 && memcmp(base + pos, "OTG3 Cert", 9) == 0) hasOTG3 = true;
                        }
                        
                        char hex[64]; int hlen = 0;
                        for (int h = 0; h < 16; h++) hlen += sprintf(hex+hlen, "%02X ", modulus[h]);
                        
                        Log("RSA KEY #%d at %p (EA str at %p, off=+0x%X) %s%s%s",
                            found, modulus, base + j, off + 4,
                            isServerKey ? "[SERVER]" : "",
                            isOurCA ? "[OUR_CA]" : "",
                            hasWinter ? " near:winter15" : "");
                        Log("  Modulus: %s", hex);
                        Log("  hasOTG3=%d hasWinter=%d", hasOTG3, hasWinter);
                    }
                    
                    j = strEnd; // skip past this string
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    Log("Total RSA key candidates found: %d", found);
}

static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v17 (find ALL RSA keys near EA cert structs) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        // Wait 25 seconds then dump all keys
        Sleep(25000);
        Log("Searching for all RSA keys...");
        FindAllRSAKeys();
        
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
