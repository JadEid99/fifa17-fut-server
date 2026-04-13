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

// Patch 3: Replace OriginRequestAuthCodeSync with fake auth code provider
// Instead of skipping the auth call, we REPLACE it with code that provides
// a fake auth code. This way the game gets a token and can build the Login request.
//
// The CALL at 146f19a11 calls FUN_1470db3c0 which takes:
//   RCX = origin SDK object
//   RDX = some param  
//   R8 = pointer to output auth code pointer (local_res18 at [RSP+0x60])
//   R9 = pointer to output auth code length (local_res10 at [RSP+0x58])
//
// We allocate a code cave that:
//   1. Writes a fake auth code string pointer to [R8]
//   2. Writes the auth code length to [R9]  
//   3. Returns 0 (success)
static char g_fakeAuthCode[] = "FAKEAUTHCODE1234567890";
static char* g_fakeAuthPtr = g_fakeAuthCode;

static void PatchAuthBypass() {
    if (g_authBypassDone) return;
    
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
                    
                    BYTE* callAddr = base + j - 5; // The CALL instruction
                    Log("Found auth call at %p", callAddr);
                    
                    // Allocate a code cave near the call site
                    // We need executable memory for our fake function
                    BYTE* cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!cave) {
                        Log("Failed to allocate code cave");
                        return;
                    }
                    
                    // Get addresses of our fake auth code
                    uint64_t authCodeAddr = (uint64_t)g_fakeAuthCode;
                    uint64_t authCodeLen = strlen(g_fakeAuthCode);
                    
                    // Write the fake function in the code cave:
                    // MOV RAX, authCodeAddr    ; 48 B8 <8 bytes>
                    // MOV [R8], RAX            ; 49 89 00
                    // MOV RAX, authCodeLen     ; 48 B8 <8 bytes>
                    // MOV [R9], RAX            ; 49 89 01
                    // XOR EAX, EAX             ; 31 C0 (return 0 = success)
                    // RET                      ; C3
                    int off = 0;
                    cave[off++] = 0x48; cave[off++] = 0xB8; // MOV RAX, imm64
                    memcpy(cave + off, &authCodeAddr, 8); off += 8;
                    cave[off++] = 0x49; cave[off++] = 0x89; cave[off++] = 0x00; // MOV [R8], RAX
                    cave[off++] = 0x48; cave[off++] = 0xB8; // MOV RAX, imm64
                    memcpy(cave + off, &authCodeLen, 8); off += 8;
                    cave[off++] = 0x49; cave[off++] = 0x89; cave[off++] = 0x01; // MOV [R9], RAX
                    cave[off++] = 0x31; cave[off++] = 0xC0; // XOR EAX, EAX
                    cave[off++] = 0xC3; // RET
                    
                    Log("Code cave at %p, fake auth code at %p (\"%s\", len=%llu)", 
                        cave, g_fakeAuthCode, g_fakeAuthCode, authCodeLen);
                    
                    // Now patch the CALL instruction to call our cave instead
                    // CALL rel32: E8 <4-byte offset>
                    // offset = target - (callAddr + 5)
                    int64_t callOffset = (int64_t)cave - (int64_t)(callAddr + 5);
                    
                    if (callOffset > INT32_MAX || callOffset < INT32_MIN) {
                        Log("Code cave too far for rel32 call (offset=%lld)", callOffset);
                        // Use absolute jump instead: replace CALL with JMP to cave
                        // But we also need to handle the return... 
                        // Alternative: NOP the CALL and use the TEST+JNZ space
                        
                        // NOP the original CALL (5 bytes)
                        DWORD oldProtect;
                        if (VirtualProtect(callAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            // Write: MOV qword [RSP+0x60], fakeAuthAddr (can't do imm64 to mem)
                            // Instead: just NOP the call, set EAX=0, NOP the JNZ
                            // And write the fake auth code pointers from our DLL thread
                            
                            // Actually, let's use a different approach:
                            // Rewrite the cave to use an absolute indirect call
                            // Or just NOP everything and handle it differently
                            
                            // Simplest: NOP the CALL, XOR EAX (success), NOP the JNZ,
                            // NOP the null checks, and pre-write fake values to the stack
                            // But we can't write to RSP from here...
                            
                            // Let me try: replace CALL with indirect call through a pointer
                            // FF 15 [rip+offset] = CALL [rip+offset] (6 bytes)
                            // We need a pointer to our cave somewhere nearby
                            
                            // Store cave pointer right after the patched area
                            // Actually, use the code cave itself to store the pointer
                            uint64_t caveAddr = (uint64_t)cave;
                            // Write pointer at cave+64
                            memcpy(cave + 64, &caveAddr, 8);
                            
                            // Use MOV RAX, imm64 + CALL RAX (12 bytes, fits in 13)
                            callAddr[0] = 0x48; callAddr[1] = 0xB8; // MOV RAX, imm64
                            memcpy(callAddr + 2, &caveAddr, 8);
                            callAddr[10] = 0xFF; callAddr[11] = 0xD0; // CALL RAX
                            callAddr[12] = 0x90; // NOP
                            
                            VirtualProtect(callAddr, 13, oldProtect, &oldProtect);
                            Log("Patched CALL to use absolute address via MOV RAX + CALL RAX");
                        }
                    } else {
                        // Relative call fits
                        DWORD oldProtect;
                        if (VirtualProtect(callAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            callAddr[0] = 0xE8;
                            *(int32_t*)(callAddr + 1) = (int32_t)callOffset;
                            VirtualProtect(callAddr, 5, oldProtect, &oldProtect);
                            Log("Patched CALL with relative offset %d", (int32_t)callOffset);
                        }
                    }
                    
                    Log("PATCHED: OriginRequestAuthCodeSync -> fake auth code provider");
                    g_authBypassDone = 1;
                    g_patched++;
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
