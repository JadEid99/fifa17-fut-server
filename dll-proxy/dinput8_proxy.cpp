/**
 * dinput8.dll Proxy - v30
 * 
 * Scans for the bAllowAnyCert check pattern in memory and patches it
 * BEFORE the game's first connection attempt.
 * 
 * Pattern: 80 BB 20 0C 00 00 00 75 (CMP BYTE [rbx+0xC20], 0; JNE)
 * Patch: change byte at offset +7 from 0x75 (JNE) to 0xEB (JMP)
 * This makes the bAllowAnyCert check always skip cert verification.
 * 
 * There are 3 instances of this pattern in the decrypted code.
 * The DLL scans every 100ms until all 3 are found and patched.
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

// The bAllowAnyCert check pattern (8 bytes):
// 80 BB 20 0C 00 00 00 75
// = CMP BYTE [rbx+0xC20], 0
// = JNE +XX
// We change the 0x75 (JNE) at offset 7 to 0xEB (JMP unconditional)
static const BYTE g_pattern[] = {0x80, 0xBB, 0x20, 0x0C, 0x00, 0x00, 0x00, 0x75};
static const SIZE_T g_patternLen = 8;
static const int g_patchOffset = 7; // offset of the JNE byte
static const BYTE g_patchByte = 0xEB; // JMP unconditional

static int g_patchCount = 0;
static const int g_targetPatches = 3; // we expect 3 instances

static int ScanAndPatch() {
    int patched = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        // Only scan executable memory (where Denuvo decrypts code)
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x1000 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            
            BYTE* base = (BYTE*)mbi.BaseAddress;
            SIZE_T size = mbi.RegionSize;
            
            __try {
                for (SIZE_T j = 0; j + g_patternLen <= size; j++) {
                    if (base[j] != 0x80) continue;
                    if (memcmp(base + j, g_pattern, g_patternLen) != 0) continue;
                    
                    // Found the pattern! Check if already patched
                    if (base[j + g_patchOffset] == g_patchByte) {
                        continue; // already patched
                    }
                    
                    Log("FOUND bAllowAnyCert check at %p (offset +0x%llX from region %p)",
                        base + j, (unsigned long long)j, base);
                    
                    // Patch: change JNE to JMP
                    DWORD oldProtect;
                    if (VirtualProtect(base + j + g_patchOffset, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        base[j + g_patchOffset] = g_patchByte;
                        VirtualProtect(base + j + g_patchOffset, 1, oldProtect, &oldProtect);
                        FlushInstructionCache(GetCurrentProcess(), base + j + g_patchOffset, 1);
                        patched++;
                        g_patchCount++;
                        Log("PATCHED! JNE->JMP at %p (total: %d/%d)", base + j + g_patchOffset, g_patchCount, g_targetPatches);
                    } else {
                        Log("VirtualProtect FAILED at %p, error=%lu", base + j, GetLastError());
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return patched;
}

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v30 (bAllowAnyCert pattern scan) ===");
    Log("PID: %lu", GetCurrentProcessId());
    Log("Scanning for pattern: 80 BB 20 0C 00 00 00 75");
    Log("Target: %d patches", g_targetPatches);
    
    DWORD startTick = GetTickCount();
    
    // Scan every 100ms until all patches are applied or 5 minutes elapsed
    for (int i = 0; i < 3000 && g_patchCount < g_targetPatches; i++) {
        Sleep(100);
        
        __try {
            int r = ScanAndPatch();
            if (r > 0) {
                DWORD elapsed = GetTickCount() - startTick;
                Log("Scan %d (%lu ms): patched %d new (total: %d/%d)", i, elapsed, r, g_patchCount, g_targetPatches);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("Scan %d: EXCEPTION", i);
        }
        
        // Log progress every 10 seconds
        if (i % 100 == 0 && i > 0) {
            DWORD elapsed = GetTickCount() - startTick;
            Log("Progress: scan %d, %lu ms, patches: %d/%d", i, elapsed, g_patchCount, g_targetPatches);
        }
    }
    
    DWORD elapsed = GetTickCount() - startTick;
    if (g_patchCount >= g_targetPatches) {
        Log("=== SUCCESS: All %d patches applied in %lu ms ===", g_patchCount, elapsed);
    } else {
        Log("=== INCOMPLETE: Only %d/%d patches after %lu ms ===", g_patchCount, g_targetPatches, elapsed);
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
