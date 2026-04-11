/**
 * dinput8.dll Proxy - v16
 * 
 * v15 found the PARSED SERVER CERT struct with RSA modulus at offset +0x388.
 * Now we need to find the PARSED CA CERT struct and replace its RSA modulus.
 * 
 * The CA cert is self-signed, so its subject = issuer = "OTG3 Certificate Authority".
 * We search for the CA's parsed struct, find its RSA modulus, and replace it
 * with our CA's modulus. Then the game verifies our server cert against our
 * CA key and it passes.
 * 
 * From v15 struct layout (each field is 32 bytes padded):
 *   -0x180: Issuer.C = "US"
 *   -0x160: Issuer.ST = "California"  
 *   -0x140: Issuer.L = "Redwood City"
 *   -0x120: Issuer.O = "Electronic Arts, Inc."
 *   -0x100: Issuer.OU = "Online Technology Group"
 *   ... more padding ...
 *   +0x100: Subject.CN = "OTG3 Certificate Authority" (or server CN)
 *   ... more fields ...
 *   +0x384: key size = 0x80 (128)
 *   +0x388: RSA modulus (128 bytes)
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

// Our CA's RSA modulus (128 bytes) - from the 712-byte CA cert
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

// Search pattern: "OTG3 Certificate Authority" followed by null padding
// This identifies the CN field in the parsed cert struct
static const char g_otg3CN[] = "OTG3 Certificate Authority";
static const SIZE_T g_otg3CNLen = 26;

static int g_replacements = 0;

// Find parsed cert structs where CN = "OTG3 Certificate Authority"
// and the struct has the key size marker (0x80 = 128 at a known offset).
// Then replace the RSA modulus.
static int FindAndReplaceCAKey() {
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
                for (SIZE_T j = 0; j + g_otg3CNLen + 0x300 < size; j++) {
                    // Look for "OTG3 Certificate Authority" + null padding
                    if (base[j] != 'O' || memcmp(base + j, g_otg3CN, g_otg3CNLen) != 0) continue;
                    if (base[j + g_otg3CNLen] != 0x00) continue; // must be null-terminated + padded
                    
                    // This could be the CN field. In the server cert struct from v15,
                    // the CN was at offset +0x100 from OTG string, and the RSA key
                    // was at +0x388 from OTG. So key is at CN + 0x288.
                    // But for the CA cert, the layout might differ.
                    
                    // Look for the key size marker: 0x80 0x00 0x00 0x00 (128 as uint32)
                    // followed by 128 bytes of non-zero data (the modulus)
                    // Search in a range after the CN field
                    for (int off = 0x100; off < 0x400; off += 4) {
                        if (j + off + 4 + 128 >= size) break;
                        
                        BYTE* p = base + j + off;
                        if (p[0] == 0x80 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00) {
                            // Check if followed by non-zero data (RSA modulus)
                            BYTE* modulus = p + 4;
                            int nonZero = 0;
                            for (int k = 0; k < 16; k++) if (modulus[k] != 0) nonZero++;
                            if (nonZero < 8) continue; // too many zeros, not a key
                            
                            // Check if this is already our modulus
                            if (memcmp(modulus, g_ourCAModulus, 128) == 0) continue;
                            
                            // Found a candidate! Log it
                            Log("FOUND RSA key at %p (CN at %p, offset +0x%X from CN)",
                                modulus, base + j, off + 4);
                            
                            char hex[64]; int hlen = 0;
                            for (int h = 0; h < 16; h++) hlen += sprintf(hex+hlen, "%02X ", modulus[h]);
                            Log("  Current modulus (first 16): %s", hex);
                            
                            // Check what CN this belongs to - is it the CA cert?
                            // The CA cert has CN = "OTG3 Certificate Authority"
                            // Look for "winter15" nearby - if found, this is the server cert
                            bool isServerCert = false;
                            for (int scan = -0x400; scan < 0x400; scan += 32) {
                                if (j + scan >= 0 && j + scan + 30 < size) {
                                    if (memcmp(base + j + scan, "winter15", 8) == 0) {
                                        isServerCert = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (isServerCert) {
                                Log("  This is the SERVER cert key, skipping");
                                continue;
                            }
                            
                            Log("  This appears to be the CA cert key! Replacing...");
                            
                            DWORD op;
                            if (VirtualProtect(modulus, 128, PAGE_READWRITE, &op)) {
                                memcpy(modulus, g_ourCAModulus, 128);
                                VirtualProtect(modulus, 128, op, &op);
                                replaced++;
                                g_replacements++;
                                Log("  REPLACED CA modulus at %p (total: %d)", modulus, g_replacements);
                                
                                // Log new modulus
                                hlen = 0;
                                for (int h = 0; h < 16; h++) hlen += sprintf(hex+hlen, "%02X ", modulus[h]);
                                Log("  New modulus (first 16): %s", hex);
                            }
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return replaced;
}


static DWORD WINAPI PatchThread(LPVOID) {
    __try {
        Log("=== FIFA 17 SSL Bypass v16 (replace CA RSA modulus in parsed struct) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        int totalReplaced = 0;
        DWORD startTick = GetTickCount();
        
        // Scan every 500ms for 3 minutes
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindAndReplaceCAKey();
                totalReplaced += r;
                if (r > 0) Log("Scan %d (%lus): replaced %d (total: %d)", i, elapsed/1000, r, totalReplaced);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Scan %d: EXCEPTION", i);
            }
            
            if (i % 60 == 0 && i > 0) {
                Log("Heartbeat: scan=%d, %lus, replaced=%d", i, elapsed/1000, totalReplaced);
            }
        }
        
        Log("=== Done. replaced=%d ===", totalReplaced);
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
