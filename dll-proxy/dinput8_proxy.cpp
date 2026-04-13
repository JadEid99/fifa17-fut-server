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
static int g_authBypassDone = 0;
static int g_authFlagDone = 0;
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

// Patch 3: Auth token bypass - skip Origin auth entirely, set authenticated flag
// At 146f19a11: CALL OriginRequestAuthCodeSync (5 bytes)
// At 146f19a16: TEST EAX,EAX (2 bytes)  
// At 146f19a18: JNZ error (6 bytes)
// Total: 13 bytes from 146f19a11 to 146f19a1e
// Target: 146f19a75 (MOV byte [RSI+0xe8], 1)
// We replace all 13 bytes with: MOV byte [RSI+0xe8],1 (7 bytes) + JMP +0x5C (2 bytes) + NOPs
// JMP offset: from 146f19a1c (after JMP instruction) to 146f19a7c = 0x60
// Wait: from 146f19a11+9 = 146f19a1a to 146f19a7c = 0x62. Let me recalculate.
// Patch starts at 146f19a11 (the CALL)
// MOV byte [RSI+0xe8],1 = c6 86 e8 00 00 00 01 (7 bytes, ends at 146f19a18)
// JMP rel8 to 146f19a7c: from 146f19a1a (after JMP) to 146f19a7c = 0x62
// But 0x62 > 0x7F so we need JMP rel8... 0x62 fits in signed byte (98 decimal, < 127)
// Actually 0x62 = 98 which fits. eb 62.
// Wait: 146f19a18 + 2 = 146f19a1a. Target 146f19a7c. Offset = 0x7c - 0x1a = 0x62. Yes.
static void PatchAuthBypass() {
    if (g_authBypassDone) return;
    
    // Pattern: the CALL to OriginRequestAuthCodeSync followed by TEST EAX,EAX / JNZ
    // We search for TEST EAX,EAX / JNZ with specific displacement
    BYTE pattern[] = { 0x85, 0xC0, 0x0F, 0x85, 0x8D, 0x00, 0x00, 0x00, 0x4C, 0x39, 0x74, 0x24 };
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
                for (SIZE_T j = 0; j + patternLen < size; j++) {
                    if (memcmp(base + j, pattern, patternLen) != 0) continue;
                    
                    // base+j = TEST EAX,EAX (146f19a16)
                    // base+j-5 = CALL instruction (146f19a11)
                    // We patch from CALL (j-5) through JNZ end (j+8), total 13 bytes
                    BYTE* patchStart = base + j - 5; // CALL address
                    
                    Log("Found auth call+check at %p", patchStart);
                    
                    DWORD oldProtect;
                    if (VirtualProtect(patchStart, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        // Bytes 0-6: MOV byte ptr [RSI+0xe8], 1
                        patchStart[0] = 0xC6;
                        patchStart[1] = 0x86;
                        patchStart[2] = 0xE8;
                        patchStart[3] = 0x00;
                        patchStart[4] = 0x00;
                        patchStart[5] = 0x00;
                        patchStart[6] = 0x01;
                        // Bytes 7-8: JMP to 146f19a7c (the JMP LAB_146f19ad0 after success)
                        // From patchStart+9 to target: target is at patchStart + 5 + 0x62 + 2 = ...
                        // patchStart = j-5 relative to base
                        // JMP is at patchStart+7, instruction ends at patchStart+9
                        // Target is at base+j + 0x66 (146f19a7c - 146f19a16 = 0x66, plus j)
                        // Offset = (base+j+0x66) - (patchStart+9) = (base+j+0x66) - (base+j-5+9) = 0x66+5-9 = 0x62
                        patchStart[7] = 0xEB;
                        patchStart[8] = 0x62;
                        // Bytes 9-12: NOPs (padding)
                        patchStart[9] = 0x90;
                        patchStart[10] = 0x90;
                        patchStart[11] = 0x90;
                        patchStart[12] = 0x90;
                        
                        VirtualProtect(patchStart, 13, oldProtect, &oldProtect);
                        
                        Log("  Patched: C6 86 E8 00 00 00 01 EB 62 90 90 90 90");
                        Log("PATCHED: Auth -> set [RSI+0xe8]=1 + JMP to continue");
                        g_authBypassDone = 1;
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

// Patch 4: Force authentication bypass flag
// At 1473ce785: MOV byte [RBX+0x2061], DIL  (40 88 BB 61 20 00 00)
// Change to:    MOV byte [RBX+0x2061], 1    (C6 83 61 20 00 00 01)
// This forces the built-in "auth bypass" flag to always be set to 1
static void PatchAuthFlag() {
    if (g_authFlagDone) return;
    
    BYTE pattern[] = { 0x40, 0x88, 0xBB, 0x61, 0x20, 0x00, 0x00 };
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
                for (SIZE_T j = 0; j + patternLen < size; j++) {
                    if (memcmp(base + j, pattern, patternLen) != 0) continue;
                    
                    BYTE* patchAddr = base + j;
                    Log("Found auth flag write at %p", patchAddr);
                    Log("  Before: %02X %02X %02X %02X %02X %02X %02X",
                        patchAddr[0], patchAddr[1], patchAddr[2], patchAddr[3],
                        patchAddr[4], patchAddr[5], patchAddr[6]);
                    
                    DWORD oldProtect;
                    if (VirtualProtect(patchAddr, 7, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        // MOV byte ptr [RBX+0x2061], 1
                        patchAddr[0] = 0xC6;
                        patchAddr[1] = 0x83;
                        patchAddr[2] = 0x61;
                        patchAddr[3] = 0x20;
                        patchAddr[4] = 0x00;
                        patchAddr[5] = 0x00;
                        patchAddr[6] = 0x01;
                        VirtualProtect(patchAddr, 7, oldProtect, &oldProtect);
                        
                        Log("  After:  %02X %02X %02X %02X %02X %02X %02X",
                            patchAddr[0], patchAddr[1], patchAddr[2], patchAddr[3],
                            patchAddr[4], patchAddr[5], patchAddr[6]);
                        Log("PATCHED: Auth bypass flag -> always set to 1");
                        g_authFlagDone = 1;
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
    Log("=== FIFA 17 SSL Bypass v56 (cert + Origin + auth bypass + auth flag) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 3000; i++) {
        Sleep(100);
        
        __try {
            if (!g_codePatchDone) PatchCertCheck();
            if (!g_originPatchDone) PatchOriginCheck();
            if (!g_authBypassDone) PatchAuthBypass();
            if (!g_authFlagDone) PatchAuthFlag();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        if (g_codePatchDone && g_originPatchDone && g_authBypassDone && g_authFlagDone) {
            Log("All patches applied after %lu ms", GetTickCount() - startTick);
            break;
        }
        
        if (i % 100 == 0 && i > 0) {
            DWORD elapsed = GetTickCount() - startTick;
            Log("Scanning... %lu ms (cert=%d, origin=%d, auth=%d, flag=%d)", 
                elapsed, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone);
        }
    }
    
    if (!g_codePatchDone) Log("WARNING: Could not find cert check pattern");
    if (!g_originPatchDone) Log("WARNING: Could not find Origin SDK check pattern");
    if (!g_authBypassDone) Log("WARNING: Could not find auth check pattern");
    if (!g_authFlagDone) Log("WARNING: Could not find auth flag pattern");
    
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
