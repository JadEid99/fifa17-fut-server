/**
 * dinput8.dll Proxy - v25
 * 
 * BREAKTHROUGH from reading DirtySDK source:
 * 
 * CA certs are stored in a GLOBAL LINKED LIST: _ProtoSSL_CACerts
 * Each node is ProtoSSLCACertT with:
 *   - Subject identity (padded string fields)
 *   - Key exponent data + size
 *   - Key modulus size + pointer (modulus appended after struct)
 *   - pNext pointer
 * 
 * The modulus is allocated RIGHT AFTER the struct.
 * From v15 dump, the CA struct has padded fields ending with
 * "OTG3 Certificate Authority", then the modulus follows.
 * 
 * Strategy: Find "OTG3 Certificate Authority" in padded format,
 * scan forward for the 128-byte RSA modulus, and replace it.
 * The modulus is high-entropy data after the last string field.
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
static const BYTE g_ourMod[] = {
    0xcc,0xee,0xf0,0xa2,0xbe,0x51,0x6f,0x51,0x8f,0x17,0xac,0xf9,0xba,0x7a,0x82,0x04,
    0x72,0xce,0xa4,0x7e,0xa7,0x89,0xc8,0xc2,0xc9,0x71,0x05,0x4d,0xb9,0xf3,0xab,0x5b,
    0xfc,0x00,0x5a,0x94,0x86,0x5f,0xff,0xb3,0x0d,0x6b,0xc8,0xdc,0x98,0x6d,0x72,0x24,
    0xd5,0xd2,0xca,0xd2,0x9f,0xe2,0xa4,0x5f,0xa5,0xa7,0x56,0x73,0x75,0x5e,0xf2,0xca,
    0x92,0x3d,0x06,0x95,0xd5,0xf5,0x2f,0x08,0xf4,0x1b,0x56,0xa1,0x0d,0x04,0xce,0x80,
    0x93,0x70,0xaf,0xa7,0x64,0xf9,0x0c,0x38,0x40,0x81,0x07,0x9c,0xfd,0x16,0x71,0xc5,
    0xd7,0x18,0x58,0x2f,0xb6,0x2b,0xc5,0xd4,0x6d,0x4b,0x89,0xf3,0xf5,0xd4,0x04,0x12,
    0x50,0x8c,0x50,0xb5,0x5f,0x5c,0x50,0x69,0x39,0x1c,0x5a,0x3e,0xa3,0xa2,0x7e,0x5d
};

// Our CA's RSA exponent: 01 00 01 (65537)
static const BYTE g_ourExp[] = {0x01, 0x00, 0x01};

static int g_replaced = 0;
static bool g_dumpDone = false;

// Find ProtoSSLCACertT nodes by looking for "OTG3 Certificate Authority"
// in padded format (the Subject.strCommon field of the CA cert node).
// Then find the RSA modulus after it and replace.
static int FindAndReplaceCAModulus() {
    static const char otg3[] = "Redwood City";
    static const SIZE_T otg3Len = 12;
    int replaced = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 512 &&
            mbi.Protect == PAGE_READWRITE) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + otg3Len + 256 < size; j++) {
                    if (base[j] != 'O' || memcmp(base + j, otg3, otg3Len) != 0) continue;
                    // Check padded format
                    if (j + otg3Len >= size || base[j + otg3Len] != 0x00) continue;
                    if (j + otg3Len + 1 < size && base[j + otg3Len + 1] != 0x00) continue;
                    
                    Log("REDWOOD at %p", base + j);
                    
                    // Dump 512 bytes after OTG3 to find the modulus
                    // Dump first 3 unique instances
                    static int dumpCount = 0;
                    if (dumpCount < 6) {
                        dumpCount++;
                        for (int doff = 0; doff < 1024; doff += 32) {
                            if (j + doff + 32 >= size) break;
                            char dhex[128]; int dhlen = 0;
                            char dasc[40] = {0};
                            for (int h = 0; h < 32; h++) {
                                dhlen += sprintf(dhex+dhlen, "%02X ", base[j+doff+h]);
                                dasc[h] = (base[j+doff+h] >= 32 && base[j+doff+h] < 127) ? (char)base[j+doff+h] : '.';
                            }
                            Log("  +%03X: %s %s", doff, dhex, dasc);
                        }
                    }
                    
                    // Scan forward from OTG3 for the RSA modulus.
                    // After the CN field (32 bytes padded), there should be:
                    // - more struct fields (key exp size, key exp data, key mod size)
                    // - then the modulus (128 bytes of high-entropy data)
                    // Look for 0x80 0x00 0x00 0x00 (key mod size = 128) followed by data
                    // OR just look for a 128-byte high-entropy block
                    
                    for (int off = 32; off < 256; off += 4) {
                        if (j + off + 132 >= size) break;
                        BYTE* p = base + j + off;
                        
                        // Check for key size marker: 0x80 as int32
                        if (p[0] == 0x80 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00) {
                            BYTE* mod = p + 4;
                            
                            // Verify it's high-entropy (not zeros or ASCII)
                            int nonZero = 0, highByte = 0;
                            for (int k = 0; k < 32; k++) {
                                if (mod[k] != 0) nonZero++;
                                if (mod[k] > 0x7F) highByte++;
                            }
                            if (nonZero < 24 || highByte < 8) continue;
                            
                            // Skip if already our modulus
                            if (memcmp(mod, g_ourMod, 128) == 0) continue;
                            
                            char hex[64]; int hlen = 0;
                            for (int h = 0; h < 16; h++) hlen += sprintf(hex+hlen, "%02X ", mod[h]);
                            Log("  FOUND modulus at %p (+%d from OTG3): %s", mod, off+4, hex);
                            
                            // Replace!
                            memcpy(mod, g_ourMod, 128);
                            replaced++;
                            g_replaced++;
                            Log("  REPLACED with our CA modulus (total: %d)", g_replaced);
                            
                            // Also replace exponent if nearby
                            // Exponent is usually 3 bytes (01 00 01) with a size field before it
                            // Look backwards from the key size marker for exp size (03 00 00 00)
                            for (int eback = 4; eback < 32; eback += 4) {
                                BYTE* ep = p - eback;
                                if (ep[0] == 0x03 && ep[1] == 0x00 && ep[2] == 0x00 && ep[3] == 0x00) {
                                    // Found exp size = 3, exp data should be right after
                                    BYTE* expData = ep + 4;
                                    Log("  Exp at %p: %02X %02X %02X (size at %p)", expData, expData[0], expData[1], expData[2], ep);
                                    // Our exponent is also 01 00 01, so no change needed if it matches
                                    break;
                                }
                            }
                            break; // found the modulus, done with this OTG3
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
        Log("=== FIFA 17 SSL Bypass v25 (replace CA modulus in ProtoSSLCACertT linked list) ===");
        Log("PID: %lu", GetCurrentProcessId());
        
        DWORD startTick = GetTickCount();
        for (int i = 0; i < 360; i++) {
            Sleep(500);
            DWORD elapsed = GetTickCount() - startTick;
            
            __try {
                int r = FindAndReplaceCAModulus();
                if (r > 0) Log("Scan %d (%lus): replaced %d (total: %d)", i, elapsed/1000, r, g_replaced);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
            
            if (i % 60 == 0 && i > 0) {
                Log("Heartbeat: %d, %lus, replaced=%d", i, elapsed/1000, g_replaced);
            }
        }
        Log("=== Done. replaced=%d ===", g_replaced);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("FATAL");
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
