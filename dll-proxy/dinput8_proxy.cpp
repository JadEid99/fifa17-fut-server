/**
 * dinput8.dll Proxy - v58: All patches + Winsock connect() hook for LSX proxy
 * 
 * Patch 1: Cert verification bypass
 *   CMP byte ptr [RBP + 0x384], 0x0 / JNZ -> JMP
 * 
 * Patch 2: Origin SDK availability check
 *   FUN_1470e2840 returns DAT_144b7c7a0 != 0
 *   Patched to always return 1 (true)
 * 
 * Patch 3: Auth code provider (code cave)
 *   Replaces OriginRequestAuthCodeSync call with fake auth code
 * 
 * Patch 4: Auth bypass flag
 *   Forces [RBX+0x2061]=1
 * 
 * Patch 5 (NEW): Winsock connect() hook
 *   Redirects connections to port 4216 (STP) -> port 4218 (our LSX proxy)
 *   This lets STP run normally for Denuvo while our proxy injects Origin auth
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
// Patch 5: Winsock connect() hook
// Redirects connections to 127.0.0.1:4216 -> 127.0.0.1:4218
// This lets STP emulator run on 4216 for Denuvo,
// while our LSX proxy on 4218 intercepts Origin auth traffic
// ============================================================

#define STP_PORT 4216
#define LSX_PROXY_PORT 4218

typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_realConnect = NULL;

static int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)name;
        unsigned short port = ntohs(addr->sin_port);
        unsigned long ip = ntohl(addr->sin_addr.s_addr);
        
        if (port == STP_PORT && ip == 0x7F000001) { // 127.0.0.1:4216
            Log("HOOK: Redirecting connect() 127.0.0.1:%d -> 127.0.0.1:%d", STP_PORT, LSX_PROXY_PORT);
            struct sockaddr_in newAddr = *addr;
            newAddr.sin_port = htons(LSX_PROXY_PORT);
            return g_realConnect(s, (struct sockaddr*)&newAddr, namelen);
        }
    }
    return g_realConnect(s, name, namelen);
}

// Inline hook: patch the first bytes of the real connect() function
// to jump to our HookedConnect, and create a trampoline with the
// original bytes + jump back for calling the real function.
static void HookWinsockConnect() {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) {
        // ws2_32 might not be loaded yet, load it
        ws2 = LoadLibraryA("ws2_32.dll");
    }
    if (!ws2) { Log("HOOK: ws2_32.dll not found"); return; }
    
    BYTE* pConnect = (BYTE*)GetProcAddress(ws2, "connect");
    if (!pConnect) { Log("HOOK: connect() not found in ws2_32.dll"); return; }
    
    Log("HOOK: connect() at %p", pConnect);
    Log("HOOK: First 16 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        pConnect[0], pConnect[1], pConnect[2], pConnect[3], pConnect[4], pConnect[5], pConnect[6], pConnect[7],
        pConnect[8], pConnect[9], pConnect[10], pConnect[11], pConnect[12], pConnect[13], pConnect[14], pConnect[15]);
    
    // Original bytes at connect():
    // 48 8B C4          mov rax, rsp          (3 bytes)
    // 48 89 58 08       mov [rax+8], rbx      (4 bytes)  = 7
    // 48 89 68 10       mov [rax+10h], rbp    (4 bytes)  = 11
    // 48 89 70 18       mov [rax+18h], rsi    (4 bytes)  = 15
    // 57                push rdi              (1 byte)   = 16
    // We need to overwrite at least 12 bytes (MOV RAX imm64 + JMP RAX)
    // but must align to instruction boundaries. 16 bytes covers 5 complete instructions.
    
    const int HOOK_SIZE = 16;
    
    // Step 1: Create trampoline - copy original bytes + jump back
    // Allocate executable memory for the trampoline
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) { Log("HOOK: VirtualAlloc for trampoline failed"); return; }
    
    // Copy original bytes
    DWORD oldProtect;
    if (!VirtualProtect(pConnect, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("HOOK: VirtualProtect failed on connect(): %lu", GetLastError());
        return;
    }
    
    memcpy(trampoline, pConnect, HOOK_SIZE);
    
    // Add jump back to original function + HOOK_SIZE
    // MOV RAX, <address>; JMP RAX
    uint64_t jumpBackAddr = (uint64_t)(pConnect + HOOK_SIZE);
    trampoline[HOOK_SIZE] = 0x48;
    trampoline[HOOK_SIZE + 1] = 0xB8;
    memcpy(trampoline + HOOK_SIZE + 2, &jumpBackAddr, 8);
    trampoline[HOOK_SIZE + 10] = 0xFF;
    trampoline[HOOK_SIZE + 11] = 0xE0;
    
    // Store trampoline pointer — g_realConnect points to the trampoline
    // so HookedConnect can call the original function
    g_realConnect = (connect_t)trampoline;
    // Step 2: Overwrite connect() with jump to HookedConnect
    uint64_t hookAddr = (uint64_t)HookedConnect;
    pConnect[0] = 0x48;
    pConnect[1] = 0xB8;
    memcpy(pConnect + 2, &hookAddr, 8);
    pConnect[10] = 0xFF;
    pConnect[11] = 0xE0;
    // NOP remaining bytes
    for (int i = 12; i < HOOK_SIZE; i++) pConnect[i] = 0x90;
    
    VirtualProtect(pConnect, HOOK_SIZE, oldProtect, &oldProtect);
    
    Log("HOOK: Inline hook installed on connect() at %p", pConnect);
    Log("HOOK: Trampoline at %p (original %d bytes + jump back)", trampoline, HOOK_SIZE);
    Log("HOOK: HookedConnect at %p", HookedConnect);
    Log("HOOK: 4216 -> 4218 redirect ACTIVE");
}

// ============================================================
// Patches 1-4 (unchanged from v56)
// ============================================================

static int g_codePatchDone = 0;
static int g_originPatchDone = 0;
static int g_authBypassDone = 0;
static int g_authFlagDone = 0;
static int g_patched = 0;

static void PatchCertCheck() {
    if (g_codePatchDone) return;
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
                    BYTE* jnzAddr = base + j + 7;
                    Log("Found cert check at %p", jnzAddr);
                    DWORD oldProtect;
                    if (VirtualProtect(jnzAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        int32_t origDisp = *(int32_t*)(jnzAddr + 2);
                        int32_t newDisp = origDisp + 1;
                        jnzAddr[0] = 0xE9;
                        *(int32_t*)(jnzAddr + 1) = newDisp;
                        jnzAddr[5] = 0x90;
                        VirtualProtect(jnzAddr, 6, oldProtect, &oldProtect);
                        Log("PATCHED: JNZ -> JMP (cert bypass)");
                        g_codePatchDone = 1; g_patched++;
                    }
                    return;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static void PatchOriginCheck() {
    if (g_originPatchDone) return;
    BYTE pattern[] = { 0x31, 0xC0, 0x48, 0x39, 0x05 };
    BYTE suffix[] = { 0x0F, 0x95, 0xD0, 0xC3 };
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
                    if (memcmp(base + j, pattern, sizeof(pattern)) != 0) continue;
                    if (memcmp(base + j + 9, suffix, sizeof(suffix)) != 0) continue;
                    BYTE* funcAddr = base + j;
                    Log("Found Origin SDK check at %p", funcAddr);
                    DWORD oldProtect;
                    if (VirtualProtect(funcAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        funcAddr[0] = 0xB0; funcAddr[1] = 0x01;
                        for (int k = 2; k < 12; k++) funcAddr[k] = 0x90;
                        VirtualProtect(funcAddr, 13, oldProtect, &oldProtect);
                        Log("PATCHED: Origin SDK check -> always true");
                        g_originPatchDone = 1; g_patched++;
                    }
                    return;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

static char g_fakeAuthCode[] = "FAKEAUTHCODE1234567890";

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
                    BYTE* callAddr = base + j - 5;
                    Log("Found auth call at %p", callAddr);
                    BYTE* cave = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!cave) { Log("Failed to allocate code cave"); return; }
                    uint64_t authCodeAddr = (uint64_t)g_fakeAuthCode;
                    uint64_t authCodeLen = strlen(g_fakeAuthCode);
                    int off = 0;
                    cave[off++] = 0x48; cave[off++] = 0xB8;
                    memcpy(cave + off, &authCodeAddr, 8); off += 8;
                    cave[off++] = 0x49; cave[off++] = 0x89; cave[off++] = 0x00;
                    cave[off++] = 0x48; cave[off++] = 0xB8;
                    memcpy(cave + off, &authCodeLen, 8); off += 8;
                    cave[off++] = 0x49; cave[off++] = 0x89; cave[off++] = 0x01;
                    cave[off++] = 0x31; cave[off++] = 0xC0;
                    cave[off++] = 0xC3;
                    uint64_t caveAddr = (uint64_t)cave;
                    DWORD oldProtect;
                    if (VirtualProtect(callAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        callAddr[0] = 0x48; callAddr[1] = 0xB8;
                        memcpy(callAddr + 2, &caveAddr, 8);
                        callAddr[10] = 0xFF; callAddr[11] = 0xD0;
                        callAddr[12] = 0x90;
                        VirtualProtect(callAddr, 13, oldProtect, &oldProtect);
                        Log("PATCHED: Auth call -> code cave at %p", cave);
                    }
                    g_authBypassDone = 1; g_patched++;
                    return;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

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
                    Log("Found auth flag at %p", patchAddr);
                    DWORD oldProtect;
                    if (VirtualProtect(patchAddr, 7, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        patchAddr[0] = 0xC6; patchAddr[1] = 0x83;
                        patchAddr[2] = 0x61; patchAddr[3] = 0x20;
                        patchAddr[4] = 0x00; patchAddr[5] = 0x00;
                        patchAddr[6] = 0x01;
                        VirtualProtect(patchAddr, 7, oldProtect, &oldProtect);
                        Log("PATCHED: Auth flag -> always 1");
                        g_authFlagDone = 1; g_patched++;
                    }
                    return;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
}

// ============================================================
// Main patch thread
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 SSL Bypass v60 (cert + Origin + auth + flag + inline connect hook) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    // Hook connect() FIRST (before game tries to connect to STP)
    HookWinsockConnect();
    
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
            Log("Scanning... %lu ms (cert=%d, origin=%d, auth=%d, flag=%d)", 
                GetTickCount() - startTick, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone);
        }
    }
    
    if (!g_codePatchDone) Log("WARNING: cert check pattern not found");
    if (!g_originPatchDone) Log("WARNING: Origin SDK check pattern not found");
    if (!g_authBypassDone) Log("WARNING: auth check pattern not found");
    if (!g_authFlagDone) Log("WARNING: auth flag pattern not found");
    
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
