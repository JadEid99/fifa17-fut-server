/**
 * dinput8.dll Proxy - v61: Patches 1-4 + diagnostic LSX client (no Winsock hooks)
 * 
 * Patch 1: Cert verification bypass (JNZ -> JMP)
 * Patch 2: Origin SDK availability check (always true)
 * Patch 3: Auth code provider (code cave)
 * Patch 4: Auth bypass flag ([RBX+0x2061]=1)
 * 
 * NEW: Background LSX client thread connects to our LSX server on port 4218
 * to test if the game responds to Origin auth events. No Winsock hooks -
 * Denuvo-safe. STP emulator stays untouched on port 4216.
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

// ============================================================
// Patches 1-4 (proven working, no changes)
// ============================================================
static int g_codePatchDone = 0, g_originPatchDone = 0, g_authBypassDone = 0, g_authFlagDone = 0, g_patched = 0;

static void PatchCertCheck() {
    if (g_codePatchDone) return;
    BYTE pattern[] = { 0x80, 0xBD, 0x84, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x85 };
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j + 13 < size; j++) {
                if (memcmp(base+j, pattern, 9) != 0) continue;
                BYTE* p = base+j+7; DWORD op;
                if (VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &op)) {
                    int32_t d = *(int32_t*)(p+2); p[0]=0xE9; *(int32_t*)(p+1)=d+1; p[5]=0x90;
                    VirtualProtect(p, 6, op, &op);
                    Log("PATCHED: cert bypass at %p", p); g_codePatchDone=1; g_patched++;
                } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static void PatchOriginCheck() {
    if (g_originPatchDone) return;
    BYTE pat[] = {0x31,0xC0,0x48,0x39,0x05}; BYTE suf[] = {0x0F,0x95,0xD0,0xC3};
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j+13 < size; j++) {
                if (memcmp(base+j, pat, 5)!=0 || memcmp(base+j+9, suf, 4)!=0) continue;
                BYTE* f = base+j; DWORD op;
                if (VirtualProtect(f, 13, PAGE_EXECUTE_READWRITE, &op)) {
                    f[0]=0xB0; f[1]=0x01; for(int k=2;k<12;k++) f[k]=0x90;
                    VirtualProtect(f, 13, op, &op);
                    Log("PATCHED: Origin SDK check at %p", f); g_originPatchDone=1; g_patched++;
                } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static char g_fakeAuthCode[] = "FAKEAUTHCODE1234567890";
static void PatchAuthBypass() {
    if (g_authBypassDone) return;
    BYTE pat[] = {0x85,0xC0,0x0F,0x85,0x8D,0x00,0x00,0x00,0x4C,0x39,0x74,0x24};
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j+12 < size; j++) {
                if (memcmp(base+j, pat, 12)!=0) continue;
                BYTE* ca = base+j-5;
                BYTE* cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!cave) return;
                uint64_t aa = (uint64_t)g_fakeAuthCode, al = strlen(g_fakeAuthCode); int o=0;
                cave[o++]=0x48; cave[o++]=0xB8; memcpy(cave+o,&aa,8); o+=8;
                cave[o++]=0x49; cave[o++]=0x89; cave[o++]=0x00;
                cave[o++]=0x48; cave[o++]=0xB8; memcpy(cave+o,&al,8); o+=8;
                cave[o++]=0x49; cave[o++]=0x89; cave[o++]=0x01;
                cave[o++]=0x31; cave[o++]=0xC0; cave[o++]=0xC3;
                uint64_t cv = (uint64_t)cave; DWORD op;
                if (VirtualProtect(ca, 13, PAGE_EXECUTE_READWRITE, &op)) {
                    ca[0]=0x48; ca[1]=0xB8; memcpy(ca+2,&cv,8); ca[10]=0xFF; ca[11]=0xD0; ca[12]=0x90;
                    VirtualProtect(ca, 13, op, &op);
                    Log("PATCHED: auth call -> cave at %p", cave);
                }
                g_authBypassDone=1; g_patched++; return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static void PatchAuthFlag() {
    if (g_authFlagDone) return;
    BYTE pat[] = {0x40,0x88,0xBB,0x61,0x20,0x00,0x00};
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j+7 < size; j++) {
                if (memcmp(base+j, pat, 7)!=0) continue;
                BYTE* p = base+j; DWORD op;
                if (VirtualProtect(p, 7, PAGE_EXECUTE_READWRITE, &op)) {
                    p[0]=0xC6; p[1]=0x83; p[2]=0x61; p[3]=0x20; p[4]=0x00; p[5]=0x00; p[6]=0x01;
                    VirtualProtect(p, 7, op, &op);
                    Log("PATCHED: auth flag at %p", p); g_authFlagDone=1; g_patched++;
                } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

// ============================================================
// Patch 5: Force IsLoggedIntoEA AND IsLoggedIntoNetwork to return true
// Both functions have identical structure:
//   SUB RSP,0x28 / XOR ECX,ECX / CALL ... / MOV RCX,[DAT_144b8fee8] / ...
//   They differ only in the vtable offset (0xd8 vs 0xe0)
// Pattern: 48 83 EC 28 31 C9 E8 XX XX XX XX 48 8B 0D
// We patch ALL matches to return true.
// ============================================================
static int g_loginPatchCount = 0;

static void PatchIsLoggedInFunctions() {
    // Pattern: SUB RSP,0x28 / XOR ECX,ECX / CALL rel32 / MOV RCX,[rip+XX]
    BYTE pat[] = { 0x48, 0x83, 0xEC, 0x28, 0x31, 0xC9, 0xE8 };
    BYTE check[] = { 0x48, 0x8B, 0x0D }; // MOV RCX,[rip+XX] at offset +11
    BYTE check2[] = { 0x48, 0x8B, 0x49, 0x70 }; // MOV RCX,[RCX+0x70] at offset +18
    
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j + 48 < size; j++) {
                if (memcmp(base+j, pat, 7) != 0) continue;
                if (memcmp(base+j+11, check, 3) != 0) continue;
                if (memcmp(base+j+18, check2, 4) != 0) continue;
                
                BYTE* func = base + j;
                
                // Find the vtable call offset to identify which function this is
                // At offset +27 (0x1b): 41 FF 90 XX XX XX XX = CALL [R8+XX]
                int vtableOffset = -1;
                if (func[0x1b] == 0x41 && func[0x1c] == 0xFF && func[0x1d] == 0x90) {
                    vtableOffset = *(int*)(func + 0x1e);
                }
                
                const char* name = "unknown";
                if (vtableOffset == 0xd8) name = "IsLoggedIntoNetwork";
                else if (vtableOffset == 0xe0) name = "IsLoggedIntoEA";
                else {
                    // Skip unknown functions with same pattern
                    continue;
                }
                
                Log("Found %s at %p (vtable+0x%X)", name, func, vtableOffset);
                
                // Find the JMP at the end
                int jmpOff = -1;
                for (int k = 0x20; k < 0x30; k++) {
                    if (func[k] == 0xE9) { jmpOff = k; break; }
                }
                if (jmpOff < 0) { Log("  Could not find JMP, skipping"); continue; }
                
                int32_t origDisp = *(int32_t*)(func + jmpOff + 1);
                BYTE* jmpTarget = func + jmpOff + 5 + origDisp;
                
                DWORD op;
                if (VirtualProtect(func, 32, PAGE_EXECUTE_READWRITE, &op)) {
                    int o = 0;
                    func[o++] = 0x48; func[o++] = 0x83; func[o++] = 0xEC; func[o++] = 0x28; // SUB RSP,0x28
                    func[o++] = 0xB0; func[o++] = 0x01;                                       // MOV AL, 1
                    func[o++] = 0x0F; func[o++] = 0xB6; func[o++] = 0xC8;                     // MOVZX ECX, AL
                    func[o++] = 0x48; func[o++] = 0x83; func[o++] = 0xC4; func[o++] = 0x28;   // ADD RSP,0x28
                    func[o++] = 0xE9;                                                          // JMP
                    int32_t newDisp = (int32_t)(jmpTarget - (func + o + 4));
                    *(int32_t*)(func + o) = newDisp; o += 4;
                    while (o < 32) func[o++] = 0x90;
                    VirtualProtect(func, 32, op, &op);
                    
                    Log("PATCHED: %s -> always returns true", name);
                    g_loginPatchCount++;
                    g_patched++;
                }
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

// Log all TCP connections the game has (diagnostic)
static void LogConnections() {
    Log("DIAG: Checking TCP connections for PID %lu", GetCurrentProcessId());
}

// ============================================================
// Main
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v65 (all patches + auth re-trigger) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 3000; i++) {
        Sleep(100);
        __try {
            if (!g_codePatchDone) PatchCertCheck();
            if (!g_originPatchDone) PatchOriginCheck();
            if (!g_authBypassDone) PatchAuthBypass();
            if (!g_authFlagDone) PatchAuthFlag();
            if (g_loginPatchCount < 2) PatchIsLoggedInFunctions();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        if (g_codePatchDone && g_originPatchDone && g_authBypassDone && g_authFlagDone && g_loginPatchCount >= 2) {
            Log("All patches applied after %lu ms", GetTickCount() - startTick);
            break;
        }
        if (i % 100 == 0 && i > 0)
            Log("Scanning... %lu ms (cert=%d origin=%d auth=%d flag=%d login=%d)", 
                GetTickCount()-startTick, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone, g_loginPatchCount);
    }
    if (!g_codePatchDone) Log("WARNING: cert pattern not found");
    if (!g_originPatchDone) Log("WARNING: Origin SDK pattern not found");
    if (!g_authBypassDone) Log("WARNING: auth pattern not found");
    if (!g_authFlagDone) Log("WARNING: auth flag pattern not found");
    if (g_loginPatchCount < 2) Log("WARNING: only %d/2 login patches found", g_loginPatchCount);
    Log("=== Done. patches: %d ===", g_patched);
    
    // After all patches are applied, try to re-trigger the auth token request.
    // Wait for OnlineManager to be fully initialized (it's NULL at 2s, try 15s)
    Sleep(15000);
    __try {
        // Read the OnlineManager pointer from the known global address
        // DAT_1448a3b20 is at address 0x1448a3b20 in the game's address space
        uint64_t* pOnlineMgr = (uint64_t*)0x1448a3b20;
        uint64_t onlineMgr = *pOnlineMgr;
        Log("AUTH-RETRIGGER: DAT_1448a3b20 = 0x%llX", onlineMgr);
        
        if (onlineMgr != 0) {
            // Check the auth request slot at +0x4ea0
            uint64_t* pAuthSlot = (uint64_t*)(onlineMgr + 0x4ea0);
            uint64_t authSlotVal = *pAuthSlot;
            Log("AUTH-RETRIGGER: [+0x4ea0] = 0x%llX (auth request slot)", authSlotVal);
            
            // Check +0x4ea8 too
            uint64_t* pAuthSlot2 = (uint64_t*)(onlineMgr + 0x4ea8);
            uint64_t authSlot2Val = *pAuthSlot2;
            Log("AUTH-RETRIGGER: [+0x4ea8] = 0x%llX (auth request slot 2)", authSlot2Val);
            
            // Check the auth code result at the request object
            // FUN_146f199c0 reads *param_1 (the request pointer) and if non-zero,
            // calls OriginRequestAuthCodeSync, then stores result at [lVar1+0xd8]
            // and sets [lVar1+0xe8]=1
            if (authSlotVal != 0) {
                uint64_t* pAuthResult = (uint64_t*)(authSlotVal + 0xd8);
                uint8_t* pAuthFlag = (uint8_t*)(authSlotVal + 0xe8);
                Log("AUTH-RETRIGGER: Auth object at 0x%llX: [+0xd8]=0x%llX [+0xe8]=%d",
                    authSlotVal, *pAuthResult, *pAuthFlag);
                
                // If the auth flag is not set, force it
                if (*pAuthFlag == 0) {
                    Log("AUTH-RETRIGGER: Auth flag not set, forcing [+0xe8]=1");
                    *pAuthFlag = 1;
                    // Also write a fake auth token at [+0xd8] if empty
                    if (*pAuthResult == 0) {
                        Log("AUTH-RETRIGGER: No auth token, writing fake token pointer");
                        // We can't easily create a proper token object here,
                        // but setting the flag might be enough
                    }
                }
            } else {
                Log("AUTH-RETRIGGER: Auth slot is NULL - request was already consumed and cleared");
                // The slot was cleared. We can't easily re-populate it because
                // we'd need a valid request object pointer. But we can try to
                // directly set the auth state on the Blaze connection.
            }
            
            // Also check DAT_1448a3ac3 (online mode flag)
            uint8_t* pOnlineFlag = (uint8_t*)0x1448a3ac3;
            Log("AUTH-RETRIGGER: DAT_1448a3ac3 = %d (online mode flag)", *pOnlineFlag);
        } else {
            Log("AUTH-RETRIGGER: OnlineManager is NULL!");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("AUTH-RETRIGGER: Exception reading game memory");
    }
    
    // Second dump after more time (catch state after connection attempt)
    Sleep(30000);
    __try {
        uint64_t* pOnlineMgr = (uint64_t*)0x1448a3b20;
        uint64_t onlineMgr = *pOnlineMgr;
        Log("AUTH-DUMP2: DAT_1448a3b20 = 0x%llX (after 45s)", onlineMgr);
        uint8_t* pOnlineFlag = (uint8_t*)0x1448a3ac3;
        Log("AUTH-DUMP2: DAT_1448a3ac3 = %d", *pOnlineFlag);
        if (onlineMgr != 0) {
            uint64_t* pAuthSlot = (uint64_t*)(onlineMgr + 0x4ea0);
            Log("AUTH-DUMP2: [+0x4ea0] = 0x%llX", *pAuthSlot);
            uint64_t* pAuthSlot2 = (uint64_t*)(onlineMgr + 0x4ea8);
            Log("AUTH-DUMP2: [+0x4ea8] = 0x%llX", *pAuthSlot2);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("AUTH-DUMP2: Exception");
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
