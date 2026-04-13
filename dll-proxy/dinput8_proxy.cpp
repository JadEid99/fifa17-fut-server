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
// Patch 5: Force IsLoggedIntoEA to return true
// FUN_1472d43c0 checks Origin SDK login state via vtable call.
// We patch it to: MOV AL, 1 / MOVZX ECX, AL / ADD RSP, 0x28 / JMP FUN_1477c1c70
// This skips the Origin SDK vtable call entirely.
// Pattern: 48 83 EC 28 31 C9 E8 (SUB RSP,28 / XOR ECX,ECX / CALL ...)
// ============================================================
static int g_loginPatchDone = 0;

static void PatchIsLoggedIn() {
    if (g_loginPatchDone) return;
    // Pattern: SUB RSP,0x28 / XOR ECX,ECX / CALL rel32 / MOV RCX,[rip+XX] (DAT_144b8fee8)
    // Bytes:   48 83 EC 28   31 C9   E8 XX XX XX XX   48 8B 0D XX XX XX XX
    // We match the first 7 bytes which are unique enough
    BYTE pat[] = { 0x48, 0x83, 0xEC, 0x28, 0x31, 0xC9, 0xE8 };
    // After the CALL at +6, at offset +11 there's MOV RCX,[rip+XX] = 48 8B 0D
    BYTE check[] = { 0x48, 0x8B, 0x0D };
    
    MEMORY_BASIC_INFORMATION mbi; BYTE* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0x100 &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BYTE* base = (BYTE*)mbi.BaseAddress; SIZE_T size = mbi.RegionSize;
            __try { for (SIZE_T j = 0; j + 30 < size; j++) {
                if (memcmp(base+j, pat, 7) != 0) continue;
                // Verify: at offset +11 (after CALL rel32) there should be MOV RCX,[rip+XX]
                if (memcmp(base+j+11, check, 3) != 0) continue;
                // Extra verify: at offset +18 there should be MOV RCX,[RCX+0x70] = 48 8B 49 70
                if (base[j+18] != 0x48 || base[j+19] != 0x8B || base[j+20] != 0x49 || base[j+21] != 0x70) continue;
                
                BYTE* func = base + j;
                Log("Found IsLoggedIntoEA at %p", func);
                Log("  Before: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    func[0],func[1],func[2],func[3],func[4],func[5],func[6],func[7],func[8],func[9],func[10],func[11]);
                
                // We need to keep the function's epilogue intact (ADD RSP,0x28 / JMP FUN_1477c1c70)
                // which is at offset +0x25 (37 bytes in). The JMP target is relative.
                // 
                // New code at func start:
                //   48 83 EC 28       SUB RSP, 0x28       (keep stack frame)
                //   B0 01             MOV AL, 1            (logged in = true)
                //   0F B6 C8          MOVZX ECX, AL        
                //   48 83 C4 28       ADD RSP, 0x28        
                //   E9 XX XX XX XX    JMP FUN_1477c1c70   (same as original)
                //   90 90 ...         NOP padding
                //
                // Original JMP is at offset 0x29 (func+0x29): E9 XX XX XX XX
                // We need to read the original JMP displacement and recalculate for our new position
                
                // The JMP to FUN_1477c1c70 is at func+0x29 in the original
                // Let's find it: scan for E9 after the MOVZX ECX,AL (0F B6 C8) at offset +0x22
                int jmpOffset = -1;
                for (int k = 0x20; k < 0x30; k++) {
                    if (func[k] == 0xE9) { jmpOffset = k; break; }
                }
                
                if (jmpOffset < 0) {
                    Log("  Could not find JMP instruction, skipping");
                    continue;
                }
                
                int32_t origJmpDisp = *(int32_t*)(func + jmpOffset + 1);
                BYTE* origJmpTarget = func + jmpOffset + 5 + origJmpDisp;
                Log("  JMP at offset +0x%X, target: %p", jmpOffset, origJmpTarget);
                
                DWORD op;
                if (VirtualProtect(func, 32, PAGE_EXECUTE_READWRITE, &op)) {
                    // Write new code
                    int o = 0;
                    func[o++] = 0x48; func[o++] = 0x83; func[o++] = 0xEC; func[o++] = 0x28; // SUB RSP, 0x28
                    func[o++] = 0xB0; func[o++] = 0x01;                                       // MOV AL, 1
                    func[o++] = 0x0F; func[o++] = 0xB6; func[o++] = 0xC8;                     // MOVZX ECX, AL
                    func[o++] = 0x48; func[o++] = 0x83; func[o++] = 0xC4; func[o++] = 0x28;   // ADD RSP, 0x28
                    // JMP to original target
                    func[o++] = 0xE9;
                    int32_t newDisp = (int32_t)(origJmpTarget - (func + o + 4));
                    *(int32_t*)(func + o) = newDisp; o += 4;
                    // NOP the rest
                    while (o < 32) func[o++] = 0x90;
                    
                    VirtualProtect(func, 32, op, &op);
                    Log("  After:  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                        func[0],func[1],func[2],func[3],func[4],func[5],func[6],func[7],func[8],
                        func[9],func[10],func[11],func[12],func[13],func[14],func[15],func[16]);
                    Log("PATCHED: IsLoggedIntoEA -> always returns true");
                    g_loginPatchDone = 1; g_patched++;
                }
                return;
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
    Log("=== FIFA 17 SSL Bypass v62 (cert + Origin + auth + flag + IsLoggedIn) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD startTick = GetTickCount();
    for (int i = 0; i < 3000; i++) {
        Sleep(100);
        __try {
            if (!g_codePatchDone) PatchCertCheck();
            if (!g_originPatchDone) PatchOriginCheck();
            if (!g_authBypassDone) PatchAuthBypass();
            if (!g_authFlagDone) PatchAuthFlag();
            if (!g_loginPatchDone) PatchIsLoggedIn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        if (g_codePatchDone && g_originPatchDone && g_authBypassDone && g_authFlagDone && g_loginPatchDone) {
            Log("All patches applied after %lu ms", GetTickCount() - startTick);
            break;
        }
        if (i % 100 == 0 && i > 0)
            Log("Scanning... %lu ms (cert=%d origin=%d auth=%d flag=%d login=%d)", 
                GetTickCount()-startTick, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone, g_loginPatchDone);
    }
    if (!g_codePatchDone) Log("WARNING: cert pattern not found");
    if (!g_originPatchDone) Log("WARNING: Origin SDK pattern not found");
    if (!g_authBypassDone) Log("WARNING: auth pattern not found");
    if (!g_authFlagDone) Log("WARNING: auth flag pattern not found");
    if (!g_loginPatchDone) Log("WARNING: IsLoggedIn pattern not found");
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
