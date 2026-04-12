/**
 * dinput8.dll Proxy - v53: Permanent code patches for cert bypass + Origin SDK bypass
 * 
 * Patch 1: Cert verification bypass (from v52)
 *   CMP byte ptr [RBP + 0x384], 0x0 / JNZ -> JMP
 * 
 * Patch 2: Origin SDK availability check
 *   FUN_1470e2840 returns DAT_144b7c7a0 != 0
 *   We patch it to always return 1 (true)
 *   Original: 31 c0 48 39 05 XX XX XX XX 0f 95 d0 c3
 *   Patched:  b0 01 90 90 90 90 90 90 90 90 90 90 c3
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
static int g_originPatchDone = 0;
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
                    // JNZ rel32: opcode is 2 bytes (0F 85), displacement is 4 bytes
                    // JMP rel32: opcode is 1 byte (E9), displacement is 4 bytes
                    // We need to adjust: the JMP displacement must account for
                    // the instruction being 1 byte shorter (5 vs 6 bytes)
                    DWORD oldProtect;
                    if (VirtualProtect(jnzAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        // Read the original 4-byte displacement from JNZ
                        int32_t origDisp = *(int32_t*)(jnzAddr + 2);
                        // JMP is 1 byte shorter, so add 1 to displacement
                        int32_t newDisp = origDisp + 1;
                        jnzAddr[0] = 0xE9;  // JMP rel32
                        *(int32_t*)(jnzAddr + 1) = newDisp;
                        jnzAddr[5] = 0x90;  // NOP
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

// Patch 2: Origin SDK availability check
// Find: 31 c0 48 39 05 XX XX XX XX 0f 95 d0 c3
// This is FUN_1470e2840 which returns (DAT_144b7c7a0 != 0)
// Patch to: b0 01 + NOPs + c3 (always return 1)
static void PatchOriginCheck() {
    if (g_originPatchDone) return;
    
    // Pattern: XOR EAX,EAX / CMP [rip+XX], RAX / SETNZ AL / RET
    BYTE pattern[] = { 0x31, 0xC0, 0x48, 0x39, 0x05 };
    BYTE suffix[] = { 0x0F, 0x95, 0xD0, 0xC3 };
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
                for (SIZE_T j = 0; j + 13 < size; j++) {
                    if (memcmp(base + j, pattern, patternLen) != 0) continue;
                    // Check suffix at offset +9 (after 4-byte displacement)
                    if (memcmp(base + j + 9, suffix, sizeof(suffix)) != 0) continue;
                    
                    BYTE* funcAddr = base + j;
                    Log("Found Origin SDK check at %p", funcAddr);
                    Log("  Before: %02X %02X %02X %02X %02X ... %02X %02X %02X %02X",
                        funcAddr[0], funcAddr[1], funcAddr[2], funcAddr[3], funcAddr[4],
                        funcAddr[9], funcAddr[10], funcAddr[11], funcAddr[12]);
                    
                    DWORD oldProtect;
                    if (VirtualProtect(funcAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        // MOV AL, 1
                        funcAddr[0] = 0xB0;
                        funcAddr[1] = 0x01;
                        // NOP out the CMP and SETNZ (bytes 2-11)
                        for (int k = 2; k < 12; k++) funcAddr[k] = 0x90;
                        // RET is already at byte 12
                        VirtualProtect(funcAddr, 13, oldProtect, &oldProtect);
                        
                        Log("  After:  %02X %02X %02X %02X %02X ... %02X %02X %02X %02X",
                            funcAddr[0], funcAddr[1], funcAddr[2], funcAddr[3], funcAddr[4],
                            funcAddr[9], funcAddr[10], funcAddr[11], funcAddr[12]);
                        Log("PATCHED: Origin SDK check -> always returns true");
                        g_originPatchDone = 1;
                        g_patched++;
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
    Log("=== FIFA 17 SSL Bypass v53 (cert + Origin SDK patches) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 3000; i++) {
        Sleep(100);
        
        __try {
            if (!g_codePatchDone) PatchCertCheck();
            if (!g_originPatchDone) PatchOriginCheck();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        if (g_codePatchDone && g_originPatchDone) {
            Log("All patches applied after %lu ms", GetTickCount() - startTick);
            break;
        }
        
        if (i % 100 == 0 && i > 0) {
            DWORD elapsed = GetTickCount() - startTick;
            Log("Scanning... %lu ms (cert=%d, origin=%d)", elapsed, g_codePatchDone, g_originPatchDone);
        }
    }
    
    if (!g_codePatchDone) Log("WARNING: Could not find cert check pattern");
    if (!g_originPatchDone) Log("WARNING: Could not find Origin SDK check pattern");
    
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
