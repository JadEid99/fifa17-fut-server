/**
 * dinput8.dll Proxy - v52: Permanent code patch for bAllowAnyCert
 * 
 * Instead of racing to set a flag in memory, we patch the actual
 * cert verification code to always skip verification.
 * 
 * From Ghidra at 146132444:
 *   CMP byte ptr [RBP + 0x384], 0x0    ; 80 bd 84 03 00 00 00
 *   JNZ LAB_1461326df                   ; 0f 85 8e 02 00 00
 * 
 * We change JNZ to JMP (unconditional): 0f 85 -> e9 XX XX XX XX 90
 * This makes cert verification ALWAYS skip, for ALL connections.
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

static int g_codePatchDone = 0;
static int g_patched = 0;

// Patch the cert verification code directly
// Find: 80 bd 84 03 00 00 00 0f 85 (CMP [RBP+0x384],0 / JNZ)
// Change JNZ to JMP: 0f 85 XX XX XX XX -> e9 XX XX XX XX 90
static void PatchCertCheck() {
    if (g_codePatchDone) return;
    
    // Search executable memory for the byte pattern
    BYTE pattern[] = { 0x80, 0xBD, 0x84, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x85 };
    int patternLen = sizeof(pattern);
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + patternLen + 4 < size; j++) {
                    if (memcmp(base + j, pattern, patternLen) != 0) continue;
                    
                    // Found the pattern! The JNZ is at offset j+7
                    BYTE* jnzAddr = base + j + 7;
                    Log("Found cert check at %p (pattern at %p)", jnzAddr, base + j);
                    Log("  Before: %02X %02X %02X %02X %02X %02X",
                        jnzAddr[0], jnzAddr[1], jnzAddr[2], jnzAddr[3], jnzAddr[4], jnzAddr[5]);
                    
                    // Change JNZ (0F 85 xx xx xx xx) to JMP (E9 xx xx xx xx 90)
                    // The displacement stays the same for JMP rel32
                    DWORD oldProtect;
                    if (VirtualProtect(jnzAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        jnzAddr[0] = 0xE9;  // JMP rel32
                        // jnzAddr[1..4] stay the same (the relative offset)
                        jnzAddr[5] = 0x90;  // NOP (pad the extra byte)
                        VirtualProtect(jnzAddr, 6, oldProtect, &oldProtect);
                        
                        Log("  After:  %02X %02X %02X %02X %02X %02X",
                            jnzAddr[0], jnzAddr[1], jnzAddr[2], jnzAddr[3], jnzAddr[4], jnzAddr[5]);
                        Log("PATCHED: JNZ -> JMP (cert verification permanently bypassed)");
                        g_codePatchDone = 1;
                        g_patched++;
                    } else {
                        Log("VirtualProtect failed: %lu", GetLastError());
                    }
                    return;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v52 (permanent code patch) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    // Try to patch the code every 100ms until successful
    // The code might not be decrypted/loaded yet at startup (Denuvo)
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 3000; i++) {
        Sleep(100);
        
        __try {
            PatchCertCheck();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        if (g_codePatchDone) {
            Log("Code patch applied after %lu ms", GetTickCount() - startTick);
            break;
        }
        
        if (i % 100 == 0 && i > 0) {
            DWORD elapsed = GetTickCount() - startTick;
            Log("Scanning for cert check... %lu ms elapsed", elapsed);
        }
    }
    
    if (!g_codePatchDone) {
        Log("WARNING: Could not find cert check pattern after 5 minutes");
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
