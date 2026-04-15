/**
 * dinput8.dll Proxy - v97
 * 
 * Patch 1: Cert verification bypass (JNZ -> JMP)
 * Patch 2: Origin SDK availability check (always true)
 * Patch 3: FUN_1470db3c0 body replacement (fake auth code, instant return)
 * Patch 4: Auth bypass flag ([RBX+0x2061]=1)
 * Patch 5+6: IsLoggedIntoEA + IsLoggedIntoNetwork (always true)
 * Patch 7: SDK gate + login vtable + PreAuth disconnect NOP
 * Patch 8: FUN_146e1cf10 (PreAuth response handler) -> always call post_PreAuth
 *          Bypasses the RPC framework entirely - even if PreAuth response parsing
 *          fails (ERR_TIMEOUT), we still trigger the Login flow.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")

struct IUnknown; typedef IUnknown* LPUNKNOWN;
typedef HRESULT(WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
static HMODULE g_realDinput8 = NULL;
static DirectInput8Create_t g_realDirectInput8Create = NULL;
static void LoadRealDinput8() {
    if (g_realDinput8) return;
    char sd[MAX_PATH]; GetSystemDirectoryA(sd, MAX_PATH); strcat_s(sd, "\\dinput8.dll");
    g_realDinput8 = LoadLibraryA(sd);
    if (g_realDinput8) g_realDirectInput8Create = (DirectInput8Create_t)GetProcAddress(g_realDinput8, "DirectInput8Create");
}
extern "C" {
    __declspec(dllexport) HRESULT WINAPI DirectInput8Create(HINSTANCE h, DWORD v, REFIID r, LPVOID* p, LPUNKNOWN u) { LoadRealDinput8(); return g_realDirectInput8Create ? g_realDirectInput8Create(h,v,r,p,u) : E_FAIL; }
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
        va_list args; va_start(args, fmt); vfprintf(g_logFile, fmt, args); va_end(args);
        fprintf(g_logFile, "\n"); fflush(g_logFile);
    }
    LeaveCriticalSection(&g_logCS);
}

static int g_codePatchDone=0, g_originPatchDone=0, g_authBypassDone=0, g_authFlagDone=0, g_patched=0, g_loginPatchCount=0, g_sdkGateDone=0;
static char g_fakeAuthCode[] = "FAKEAUTHCODE1234567890";
static volatile int g_caveExecuted = 0;
static volatile uint64_t g_preAuthParam1 = 0;  // saved from PreAuth cave for login flow

// Patch 1: Cert bypass
static void PatchCertCheck() {
    if (g_codePatchDone) return;
    BYTE pat[] = {0x80,0xBD,0x84,0x03,0x00,0x00,0x00,0x0F,0x85};
    MEMORY_BASIC_INFORMATION mbi; BYTE* a = NULL;
    while (VirtualQuery(a, &mbi, sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && mbi.RegionSize>0x100 && (mbi.Protect==PAGE_EXECUTE_READ||mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)) {
            BYTE* b=(BYTE*)mbi.BaseAddress; SIZE_T s=mbi.RegionSize;
            __try { for(SIZE_T j=0;j+13<s;j++) { if(memcmp(b+j,pat,9)!=0) continue;
                BYTE* p=b+j+7; DWORD op;
                if(VirtualProtect(p,6,PAGE_EXECUTE_READWRITE,&op)) { int32_t d=*(int32_t*)(p+2); p[0]=0xE9; *(int32_t*)(p+1)=d+1; p[5]=0x90; VirtualProtect(p,6,op,&op); Log("PATCHED: cert bypass at %p",p); g_codePatchDone=1; g_patched++; } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        } a=(BYTE*)mbi.BaseAddress+mbi.RegionSize; if((ULONG_PTR)a<(ULONG_PTR)mbi.BaseAddress) break;
    }
}

// Patch 2: Origin SDK check -> always true
static void PatchOriginCheck() {
    if (g_originPatchDone) return;
    BYTE pat[]={0x31,0xC0,0x48,0x39,0x05}; BYTE suf[]={0x0F,0x95,0xD0,0xC3};
    MEMORY_BASIC_INFORMATION mbi; BYTE* a=NULL;
    while (VirtualQuery(a,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && mbi.RegionSize>0x100 && (mbi.Protect==PAGE_EXECUTE_READ||mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)) {
            BYTE* b=(BYTE*)mbi.BaseAddress; SIZE_T s=mbi.RegionSize;
            __try { for(SIZE_T j=0;j+13<s;j++) { if(memcmp(b+j,pat,5)!=0||memcmp(b+j+9,suf,4)!=0) continue;
                BYTE* f=b+j; DWORD op;
                if(VirtualProtect(f,13,PAGE_EXECUTE_READWRITE,&op)) { f[0]=0xB0;f[1]=0x01;for(int k=2;k<12;k++)f[k]=0x90; VirtualProtect(f,13,op,&op); Log("PATCHED: Origin SDK check at %p",f); g_originPatchDone=1; g_patched++; } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        } a=(BYTE*)mbi.BaseAddress+mbi.RegionSize; if((ULONG_PTR)a<(ULONG_PTR)mbi.BaseAddress) break;
    }
}

// Patch 3: Replace FUN_1470db3c0 body with fake auth code provider
static void PatchAuthBypass() {
    if (g_authBypassDone) return;
    BYTE pat[]={0x85,0xC0,0x0F,0x85,0x8D,0x00,0x00,0x00,0x4C,0x39,0x74,0x24};
    MEMORY_BASIC_INFORMATION mbi; BYTE* a=NULL;
    while (VirtualQuery(a,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && mbi.RegionSize>0x100 && (mbi.Protect==PAGE_EXECUTE_READ||mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)) {
            BYTE* b=(BYTE*)mbi.BaseAddress; SIZE_T s=mbi.RegionSize;
            __try { for(SIZE_T j=0;j+12<s;j++) { if(memcmp(b+j,pat,12)!=0) continue;
                BYTE* callInstr=b+j-5;
                if(callInstr[0]!=0xE8) continue;
                int32_t callDisp=*(int32_t*)(callInstr+1);
                BYTE* targetFunc=callInstr+5+callDisp;
                Log("AUTH: call site at %p, target FUN_1470db3c0 at %p", callInstr, targetFunc);
                uint64_t aa=(uint64_t)g_fakeAuthCode, al=strlen(g_fakeAuthCode), ma=(uint64_t)&g_caveExecuted;
                DWORD op;
                if(VirtualProtect(targetFunc,48,PAGE_EXECUTE_READWRITE,&op)) {
                    int o=0;
                    // Write marker
                    targetFunc[o++]=0x48;targetFunc[o++]=0xB8;memcpy(targetFunc+o,&ma,8);o+=8;
                    targetFunc[o++]=0xC7;targetFunc[o++]=0x00;targetFunc[o++]=1;targetFunc[o++]=0;targetFunc[o++]=0;targetFunc[o++]=0;
                    // Return error (EAX=1) — no auth code provided
                    // This prevents CreateAccount from being sent
                    // The Login from PreAuth should fire without interference
                    targetFunc[o++]=0xB8;targetFunc[o++]=0x01;targetFunc[o++]=0x00;targetFunc[o++]=0x00;targetFunc[o++]=0x00; // MOV EAX, 1
                    targetFunc[o++]=0xC3; // RET
                    VirtualProtect(targetFunc,48,op,&op);
                    Log("PATCHED: FUN_1470db3c0 body -> fake auth code"); g_authBypassDone=1; g_patched++;
                } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        } a=(BYTE*)mbi.BaseAddress+mbi.RegionSize; if((ULONG_PTR)a<(ULONG_PTR)mbi.BaseAddress) break;
    }
}

// Patch 4: Auth flag
static void PatchAuthFlag() {
    if (g_authFlagDone) return;
    BYTE pat[]={0x40,0x88,0xBB,0x61,0x20,0x00,0x00};
    MEMORY_BASIC_INFORMATION mbi; BYTE* a=NULL;
    while (VirtualQuery(a,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && mbi.RegionSize>0x100 && (mbi.Protect==PAGE_EXECUTE_READ||mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)) {
            BYTE* b=(BYTE*)mbi.BaseAddress; SIZE_T s=mbi.RegionSize;
            __try { for(SIZE_T j=0;j+7<s;j++) { if(memcmp(b+j,pat,7)!=0) continue;
                BYTE* p=b+j; DWORD op;
                if(VirtualProtect(p,7,PAGE_EXECUTE_READWRITE,&op)) { p[0]=0xC6;p[1]=0x83;p[2]=0x61;p[3]=0x20;p[4]=0;p[5]=0;p[6]=1; VirtualProtect(p,7,op,&op); Log("PATCHED: auth flag at %p",p); g_authFlagDone=1; g_patched++; } return;
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        } a=(BYTE*)mbi.BaseAddress+mbi.RegionSize; if((ULONG_PTR)a<(ULONG_PTR)mbi.BaseAddress) break;
    }
}

// Patch 7: FUN_1471a5da0 (SDK gate) -> always return 1
// This gates the ENTIRE login flow. DAT_144b86bf8 is NULL so it returns 0.
// Game base is always 0x140000000 (no ASLR). Function at fixed address.
// ALSO patches FUN_146e19a00 (PreAuth completion) to skip disconnect.
static void PatchSdkGateCheck() {
    if (g_sdkGateDone) return;
    
    // Part A: SDK gate -> always return 1
    BYTE* func = (BYTE*)0x1471a5da0;
    __try {
        Log("SDK GATE: addr=%p bytes=%02X %02X %02X %02X", func, func[0],func[1],func[2],func[3]);
        if (func[0] == 0x48) {
            DWORD op;
            if (VirtualProtect(func, 16, PAGE_EXECUTE_READWRITE, &op)) {
                func[0]=0xB0; func[1]=0x01; func[2]=0xC3;
                for (int k=3; k<16; k++) func[k]=0x90;
                VirtualProtect(func, 16, op, &op);
                Log("PATCHED: SDK gate -> always 1");
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    // Part B: Patch ALL login type vtable[0x10] functions to return 1
    // Type 0 (Login): vtable at 0x14389f938
    // Type 1 (SilentLogin): vtable at 0x14389fa70
    // Type 3 (ExpressLogin): vtable at 0x14389fb98
    uint64_t vtables[] = { 0x14389f938, 0x14389fa70, 0x14389fb98 };
    const char* names[] = { "Login", "SilentLogin", "ExpressLogin" };
    for (int v = 0; v < 3; v++) {
        __try {
            uint64_t* vt = (uint64_t*)vtables[v];
            uint64_t fa = vt[2]; // +0x10 = index 2
            if (fa > 0x140000000 && fa < 0x150000000) {
                BYTE* f = (BYTE*)fa;
                Log("LOGIN %s: vtable=%p [+0x10]=0x%llX bytes=%02X %02X %02X",
                    names[v], vt, fa, f[0], f[1], f[2]);
                // Only patch if not already patched (B0 01 C3)
                if (f[0] != 0xB0 || f[1] != 0x01) {
                    DWORD op;
                    if (VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &op)) {
                        f[0]=0xB0; f[1]=0x01; f[2]=0xC3;
                        VirtualProtect(f, 8, op, &op);
                        Log("PATCHED: %s vtable check -> return 1", names[v]);
                    }
                } else {
                    Log("LOGIN %s: already patched", names[v]);
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    
    // Part C: Replace FUN_146e19a00 entirely with a RET
    // This function disconnects, cleans up, and schedules error callbacks.
    // Since our DLL cave (Patch 8) handles post-PreAuth directly,
    // we don't need FUN_146e19a00 to do anything — just return.
    __try {
        BYTE* pah = (BYTE*)0x146e19a00;
        Log("PREAUTH_COMPLETION: addr=%p bytes=%02X %02X %02X %02X", pah, pah[0], pah[1], pah[2], pah[3]);
        DWORD op;
        if (VirtualProtect(pah, 4, PAGE_EXECUTE_READWRITE, &op)) {
            pah[0] = 0xC3; // RET
            pah[1] = 0x90; // NOP
            pah[2] = 0x90; // NOP
            pah[3] = 0x90; // NOP
            VirtualProtect(pah, 4, op, &op);
            Log("PATCHED: FUN_146e19a00 -> immediate RET (no disconnect/cleanup)");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    g_sdkGateDone = 1; g_patched++;
}

// Patch 8: Patch FUN_146e1cf10 (PreAuth response handler) to always take success path
// Instead of replacing the entire function with a cave, we just NOP the conditional
// jump so param_3 != 0 (ERR_TIMEOUT) still takes the success path.
// The original code will run naturally and call FUN_146e1c3f0 (Login processor).
static int g_preAuthPatchDone = 0;
static void PatchPreAuthHandler() {
    if (g_preAuthPatchDone) return;
    
    BYTE* func = (BYTE*)0x146e1cf10;
    __try {
        // Log first 128 bytes for analysis
        Log("PREAUTH_HANDLER: first 128 bytes:");
        for (int row = 0; row < 128; row += 16) {
            Log("  +%02X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                row, func[row], func[row+1], func[row+2], func[row+3],
                func[row+4], func[row+5], func[row+6], func[row+7],
                func[row+8], func[row+9], func[row+10], func[row+11],
                func[row+12], func[row+13], func[row+14], func[row+15]);
        }
        
        // APPROACH: Instead of finding the JNZ, patch the function entry to
        // force param_3 (R8D) to 0 before the original code runs.
        // We insert: XOR R8D, R8D (3 bytes: 45 31 C0) at the start,
        // shifting the original prologue into a small trampoline.
        //
        // Original: 48 89 5C 24 08 48 89 74 ...
        // Patched:  Jump to cave that does XOR R8D,R8D then runs original prologue
        
        BYTE* cave = (BYTE*)VirtualAlloc(NULL, 128, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cave) { Log("PREAUTH_HANDLER: cave alloc failed"); return; }
        
        int o = 0;
        // Save param_1 (RCX) to g_preAuthParam1 for the Login flow later
        // PUSH RAX
        cave[o++] = 0x50;
        // MOV RAX, &g_preAuthParam1
        cave[o++] = 0x48; cave[o++] = 0xB8;
        uint64_t saveAddr = (uint64_t)&g_preAuthParam1;
        memcpy(cave + o, &saveAddr, 8); o += 8;
        // MOV [RAX], RCX
        cave[o++] = 0x48; cave[o++] = 0x89; cave[o++] = 0x08;
        // POP RAX
        cave[o++] = 0x58;
        
        // XOR R8D, R8D — force param_3 = 0 (success path)
        cave[o++] = 0x45; cave[o++] = 0x31; cave[o++] = 0xC0;
        
        // Copy the original first 14 bytes (that we'll overwrite with the jump)
        memcpy(cave + o, func, 14); o += 14;
        
        // Jump back to func + 14 (continue original code)
        // MOV RAX, func+14 / JMP RAX
        cave[o++] = 0x48; cave[o++] = 0xB8;
        uint64_t retAddr = (uint64_t)(func + 14);
        memcpy(cave + o, &retAddr, 8); o += 8;
        cave[o++] = 0xFF; cave[o++] = 0xE0;
        
        Log("PREAUTH_HANDLER: Cave at %p, %d bytes (XOR R8D + trampoline)", cave, o);
        
        // Patch func to jump to cave
        DWORD op;
        if (VirtualProtect(func, 16, PAGE_EXECUTE_READWRITE, &op)) {
            int p = 0;
            func[p++] = 0x48; func[p++] = 0xB8;
            uint64_t caveAddr = (uint64_t)cave;
            memcpy(func + p, &caveAddr, 8); p += 8;
            func[p++] = 0xFF; func[p++] = 0xE0;
            while (p < 14) func[p++] = 0x90;
            VirtualProtect(func, 16, op, &op);
            Log("PATCHED: FUN_146e1cf10 -> XOR R8D,R8D trampoline (always success path)");
        }
        
        g_preAuthPatchDone = 1;
        g_patched++;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("PREAUTH_HANDLER: Exception");
    }
}

// Patch 16: FUN_146e151d0 (CreateAccount response handler)
// The TDF decoder NEVER populates the response object for CreateAccount.
// The original handler crashes because it reads zeros and dereferences null.
// We MUST bypass the handler.
//
// Bypass cave: set state bytes (0x8c0=1, 0x8c6=0) and return.
// The server will send a proactive SilentLogin notification after CreateAccount.
static int g_createAcctPatchDone = 0;
static volatile int g_createAcctCalled = 0;
static volatile uint64_t g_createAcctParam1 = 0;

static void PatchCreateAccountHandler() {
    if (g_createAcctPatchDone) return;
    
    BYTE* func = (BYTE*)0x146e151d0;
    __try {
        Log("CA_HANDLER: addr=%p bytes=%02X %02X %02X %02X %02X %02X",
            func, func[0], func[1], func[2], func[3], func[4], func[5]);
        
        BYTE* cave = (BYTE*)VirtualAlloc(NULL, 256, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cave) { Log("CA_HANDLER: cave alloc failed"); return; }
        
        int o = 0;
        cave[o++] = 0x53; cave[o++] = 0x56;
        cave[o++] = 0x48; cave[o++] = 0x83; cave[o++] = 0xEC; cave[o++] = 0x28;
        cave[o++] = 0x48; cave[o++] = 0x89; cave[o++] = 0xCB;
        
        // Save param_1 and set flag
        cave[o++] = 0x48; cave[o++] = 0xB8;
        uint64_t p1Addr = (uint64_t)&g_createAcctParam1;
        memcpy(cave + o, &p1Addr, 8); o += 8;
        cave[o++] = 0x48; cave[o++] = 0x89; cave[o++] = 0x08;
        cave[o++] = 0x48; cave[o++] = 0xB8;
        uint64_t flagAddr = (uint64_t)&g_createAcctCalled;
        memcpy(cave + o, &flagAddr, 8); o += 8;
        cave[o++] = 0xC7; cave[o++] = 0x00;
        cave[o++] = 0x01; cave[o++] = 0x00; cave[o++] = 0x00; cave[o++] = 0x00;
        
        // Get state via vtable+0xb8
        cave[o++] = 0x48; cave[o++] = 0x8B; cave[o++] = 0x03;
        cave[o++] = 0x48; cave[o++] = 0x89; cave[o++] = 0xD9;
        cave[o++] = 0xFF; cave[o++] = 0x90;
        cave[o++] = 0xB8; cave[o++] = 0x00; cave[o++] = 0x00; cave[o++] = 0x00;
        cave[o++] = 0x48; cave[o++] = 0x89; cave[o++] = 0xC6;
        
        // state[0x8bc] = 0
        cave[o++] = 0xC7; cave[o++] = 0x86;
        cave[o++] = 0xBC; cave[o++] = 0x08; cave[o++] = 0x00; cave[o++] = 0x00;
        cave[o++] = 0x00; cave[o++] = 0x00; cave[o++] = 0x00; cave[o++] = 0x00;
        // state[0x8c0] = 1
        cave[o++] = 0xC6; cave[o++] = 0x86;
        cave[o++] = 0xC0; cave[o++] = 0x08; cave[o++] = 0x00; cave[o++] = 0x00;
        cave[o++] = 0x01;
        // state[0x8c6] = 0
        cave[o++] = 0xC6; cave[o++] = 0x86;
        cave[o++] = 0xC6; cave[o++] = 0x08; cave[o++] = 0x00; cave[o++] = 0x00;
        cave[o++] = 0x00;
        
        cave[o++] = 0x48; cave[o++] = 0x83; cave[o++] = 0xC4; cave[o++] = 0x28;
        cave[o++] = 0x5E; cave[o++] = 0x5B; cave[o++] = 0xC3;
        
        Log("CA_HANDLER: Cave at %p, %d bytes (bypass + state bytes)", cave, o);
        
        DWORD op;
        if (VirtualProtect(func, 16, PAGE_EXECUTE_READWRITE, &op)) {
            int p = 0;
            func[p++] = 0x48; func[p++] = 0xB8;
            uint64_t caveAddr = (uint64_t)cave;
            memcpy(func + p, &caveAddr, 8); p += 8;
            func[p++] = 0xFF; func[p++] = 0xE0;
            while (p < 14) func[p++] = 0x90;
            VirtualProtect(func, 16, op, &op);
            Log("PATCHED: FUN_146e151d0 -> bypass cave (state bytes, no OSDK)");
            g_createAcctPatchDone = 1;
            g_patched++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("CA_HANDLER: Exception");
    }
}

// Patch 9: FUN_1470e0390 (Origin::OriginSDK::CheckOnline) -> always return success
// Also patch FUN_1470da720 (GetGameVersion) -> return 0 + write expected bytes
// Also patch FUN_145e280b0 (memcmp for version) -> always return 0 (match)
static int g_originCheckOnlineDone = 0;
static void PatchOriginCheckOnline() {
    if (g_originCheckOnlineDone) return;
    
    // Part A: FUN_1470e0390 -> always online
    BYTE* func = (BYTE*)0x1470e0390;
    __try {
        Log("ORIGIN_CHECK_ONLINE: addr=%p bytes=%02X %02X %02X %02X", func, func[0], func[1], func[2], func[3]);
        DWORD op;
        if (VirtualProtect(func, 32, PAGE_EXECUTE_READWRITE, &op)) {
            int o = 0;
            func[o++] = 0x48; func[o++] = 0x85; func[o++] = 0xD2; // TEST RDX, RDX
            func[o++] = 0x74; func[o++] = 0x03;                     // JZ +3
            func[o++] = 0xC6; func[o++] = 0x02; func[o++] = 0x01;  // MOV BYTE [RDX], 1
            func[o++] = 0x31; func[o++] = 0xC0;                     // XOR EAX, EAX
            func[o++] = 0xC3;                                        // RET
            while (o < 32) func[o++] = 0x90;
            VirtualProtect(func, 32, op, &op);
            Log("PATCHED: FUN_1470e0390 (OriginCheckOnline) -> always online");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    // Part B: FUN_1470da720 (GetGameVersion) -> return 0 (success)
    // This function gets the game version from Origin/STP. We make it return 0.
    __try {
        BYTE* gv = (BYTE*)0x1470da720;
        Log("GET_GAME_VERSION: addr=%p bytes=%02X %02X %02X %02X", gv, gv[0], gv[1], gv[2], gv[3]);
        DWORD op;
        if (VirtualProtect(gv, 8, PAGE_EXECUTE_READWRITE, &op)) {
            gv[0] = 0x31; gv[1] = 0xC0; // XOR EAX, EAX (return 0)
            gv[2] = 0xC3;                // RET
            for (int k=3; k<8; k++) gv[k] = 0x90;
            VirtualProtect(gv, 8, op, &op);
            Log("PATCHED: FUN_1470da720 (GetGameVersion) -> return 0");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    // Part C: FUN_145e280b0 (memcmp for version check) -> always return 0 (match)
    // This compares the version bytes. We make it always say "match".
    __try {
        BYTE* mc = (BYTE*)0x145e280b0;
        Log("VERSION_CMP: addr=%p bytes=%02X %02X %02X %02X", mc, mc[0], mc[1], mc[2], mc[3]);
        DWORD op;
        if (VirtualProtect(mc, 8, PAGE_EXECUTE_READWRITE, &op)) {
            mc[0] = 0x31; mc[1] = 0xC0; // XOR EAX, EAX (return 0 = match)
            mc[2] = 0xC3;                // RET
            for (int k=3; k<8; k++) mc[k] = 0x90;
            VirtualProtect(mc, 8, op, &op);
            Log("PATCHED: FUN_145e280b0 (version compare) -> always match");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    // Part D: Instead of patching OSDK functions (which breaks startup),
    // we delay-patch them. The PatchThread runs in a loop, so these will
    // be applied after the game has loaded.
    // For now, skip the OSDK patches here — they'll be applied later
    // in the main patch loop when the game is past the loading screen.
    
    g_originCheckOnlineDone = 1;
    g_patched++;
}

// Patch 5+6: IsLoggedIntoEA + IsLoggedIntoNetwork -> always true
static void PatchIsLoggedInFunctions() {
    BYTE pat[]={0x48,0x83,0xEC,0x28,0x31,0xC9,0xE8};
    BYTE chk[]={0x48,0x8B,0x0D}; BYTE chk2[]={0x48,0x8B,0x49,0x70};
    MEMORY_BASIC_INFORMATION mbi; BYTE* a=NULL;
    while (VirtualQuery(a,&mbi,sizeof(mbi))) {
        if (mbi.State==MEM_COMMIT && mbi.RegionSize>0x100 && (mbi.Protect==PAGE_EXECUTE_READ||mbi.Protect==PAGE_EXECUTE_READWRITE||mbi.Protect==PAGE_EXECUTE_WRITECOPY)) {
            BYTE* b=(BYTE*)mbi.BaseAddress; SIZE_T s=mbi.RegionSize;
            __try { for(SIZE_T j=0;j+48<s;j++) {
                if(memcmp(b+j,pat,7)!=0||memcmp(b+j+11,chk,3)!=0||memcmp(b+j+18,chk2,4)!=0) continue;
                BYTE* f=b+j; int vt=-1;
                if(f[0x1b]==0x41&&f[0x1c]==0xFF&&f[0x1d]==0x90) vt=*(int*)(f+0x1e);
                const char* nm="?"; if(vt==0xd8) nm="IsLoggedIntoNetwork"; else if(vt==0xe0) nm="IsLoggedIntoEA"; else continue;
                int jo=-1; for(int k=0x20;k<0x30;k++) if(f[k]==0xE9){jo=k;break;}
                if(jo<0) continue;
                int32_t od=*(int32_t*)(f+jo+1); BYTE* jt=f+jo+5+od; DWORD op;
                if(VirtualProtect(f,32,PAGE_EXECUTE_READWRITE,&op)) {
                    int o=0; f[o++]=0x48;f[o++]=0x83;f[o++]=0xEC;f[o++]=0x28; f[o++]=0xB0;f[o++]=0x01; f[o++]=0x0F;f[o++]=0xB6;f[o++]=0xC8; f[o++]=0x48;f[o++]=0x83;f[o++]=0xC4;f[o++]=0x28;
                    f[o++]=0xE9; int32_t nd=(int32_t)(jt-(f+o+4)); *(int32_t*)(f+o)=nd; o+=4; while(o<32)f[o++]=0x90;
                    VirtualProtect(f,32,op,&op); Log("PATCHED: %s -> true",nm); g_loginPatchCount++; g_patched++;
                }
            }} __except(EXCEPTION_EXECUTE_HANDLER) {}
        } a=(BYTE*)mbi.BaseAddress+mbi.RegionSize; if((ULONG_PTR)a<(ULONG_PTR)mbi.BaseAddress) break;
    }
}

// ============================================================
// Main thread
// ============================================================
static DWORD WINAPI PatchThread(LPVOID) {
    Log("=== FIFA 17 v96 (EARLY SDK object in DllMain + all patches) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD st = GetTickCount();
    uint64_t realVtable = 0;
    for (int i=0; i<3000; i++) {
        Sleep(100);
        __try {
            if(!g_codePatchDone) PatchCertCheck();
            if(!g_originPatchDone) PatchOriginCheck();
            if(!g_authBypassDone) PatchAuthBypass();
            if(!g_authFlagDone) PatchAuthFlag();
            if(g_loginPatchCount<2) PatchIsLoggedInFunctions();
            if(!g_sdkGateDone) PatchSdkGateCheck();
            if(!g_preAuthPatchDone) PatchPreAuthHandler();
            // Patch 19: Login check must be patched BEFORE PreAuth runs
            {
                static int loginCheckPatched = 0;
                if (!loginCheckPatched) {
                    __try {
                        BYTE* f = (BYTE*)0x146e1dae0;
                        DWORD op;
                        if (VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &op)) {
                            f[0] = 0xB0; f[1] = 0x01; f[2] = 0xC3;
                            for (int k=3; k<8; k++) f[k] = 0x90;
                            VirtualProtect(f, 8, op, &op);
                            Log("PATCHED: FUN_146e1dae0 (login check) -> return 1 (EARLY)");
                            loginCheckPatched = 1;
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
            // Patch 18: Age check must also be patched early
            {
                static int ageCheckPatched = 0;
                if (!ageCheckPatched) {
                    __try {
                        BYTE* f = (BYTE*)0x14717d5d0;
                        DWORD op;
                        if (VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &op)) {
                            f[0] = 0xC3;
                            for (int k=1; k<8; k++) f[k] = 0x90;
                            VirtualProtect(f, 8, op, &op);
                            Log("PATCHED: FUN_14717d5d0 (age check) -> RET (EARLY)");
                            ageCheckPatched = 1;
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
            // Patch 16 REMOVED — let the RPC framework handle CreateAccount naturally
            // if(!g_createAcctPatchDone) PatchCreateAccountHandler();
            if(!g_originCheckOnlineDone) PatchOriginCheckOnline();
            // Try to capture the real vtable from the auth request object
            if (realVtable == 0) {
                uint64_t* pOM = (uint64_t*)0x1448a3b20;
                if (*pOM != 0) {
                    uint64_t* pSlot = (uint64_t*)(*pOM + 0x4ea0);
                    if (*pSlot != 0) {
                        realVtable = *(uint64_t*)(*pSlot);
                        Log("AUTH: Captured vtable 0x%llX from slot 0x%llX at %lu ms", realVtable, *pSlot, GetTickCount()-st);
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        if(g_codePatchDone&&g_originPatchDone&&g_authBypassDone&&g_authFlagDone&&g_loginPatchCount>=2&&g_sdkGateDone&&g_preAuthPatchDone&&g_originCheckOnlineDone) { Log("All patches in %lu ms",GetTickCount()-st); break; }
    }
    Log("patches: %d (cert=%d orig=%d auth=%d flag=%d login=%d)", g_patched, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone, g_loginPatchCount);
    
    // The original auth request fired at ~100ms, called FUN_1470db3c0 (unpatched),
    // which blocked for 15s in STP timeout, returned error, slot was cleared.
    // Our patch to FUN_1470db3c0 body landed at ~640ms but the function was already
    // executing. We wait for the 15s timeout to complete, then re-inject a fake
    // request object so the game processes it with our patched function.
    Log("AUTH: Checking login gate globals...");
    __try {
        uint64_t* pSdkMgr = (uint64_t*)0x144b86bf8;
        uint8_t* pSdkErr = (uint8_t*)0x144b86bdf;
        Log("AUTH: DAT_144b86bf8 = 0x%llX (Origin SDK manager)", *pSdkMgr);
        Log("AUTH: DAT_144b86bdf = %d (error flag)", *pSdkErr);
        if (*pSdkMgr == 0) {
            Log("AUTH: SDK manager STILL NULL (DllMain didn't set it). Creating now...");
            // Same fake object creation as DllMain (fallback)
            // Allocate a fake SDK manager object with a vtable
            // The login flow accesses vtable offsets: +0x138, +0x188, +0x60, +0xa8, etc.
            // We need a vtable large enough and all entries pointing to safe stubs.
            
            // Allocate fake vtable (0x200 bytes = 64 entries, covers up to offset +0x1F8)
            BYTE* fakeVtable = (BYTE*)VirtualAlloc(NULL, 0x400, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            // Allocate fake object (0x1000 bytes for safety)
            BYTE* fakeObj = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (fakeVtable && fakeObj) {
                memset(fakeObj, 0, 0x1000);
                
                // Create stub functions in the vtable memory:
                // Stub 1: return 0 (for most vtable calls) - XOR EAX,EAX / RET
                BYTE* stubRet0 = fakeVtable + 0x300;
                stubRet0[0] = 0x31; stubRet0[1] = 0xC0; stubRet0[2] = 0xC3; // XOR EAX,EAX / RET
                
                // Stub 2: return 1 (for +0x138 which must return 1 for login)
                BYTE* stubRet1 = fakeVtable + 0x310;
                stubRet1[0] = 0xB0; stubRet1[1] = 0x01; stubRet1[2] = 0xC3; // MOV AL,1 / RET
                
                // Stub 3: dynamically return the Blaze hub pointer (for +0x188)
                // Instead of hardcoding, the stub reads it at call time:
                //   MOV RAX, [0x1448a3b20]     ; OnlineManager ptr
                //   TEST RAX, RAX
                //   JZ .ret0
                //   MOV RAX, [RAX + 0xb10]     ; connection manager
                //   TEST RAX, RAX
                //   JZ .ret0
                //   MOV RAX, [RAX + 0xf8]      ; Blaze hub
                //   RET
                // .ret0: XOR EAX,EAX / RET
                BYTE* stubRetHub = fakeVtable + 0x320;
                int h = 0;
                // MOV RAX, [0x1448a3b20]  = 48 A1 <8-byte abs addr>
                // Actually x64 doesn't have MOV RAX,[abs64] for memory. Use:
                // MOV RAX, 0x1448a3b20 / MOV RAX, [RAX]
                uint64_t omAddr = 0x1448a3b20;
                stubRetHub[h++]=0x48; stubRetHub[h++]=0xB8; memcpy(stubRetHub+h, &omAddr, 8); h+=8; // MOV RAX, imm64
                stubRetHub[h++]=0x48; stubRetHub[h++]=0x8B; stubRetHub[h++]=0x00;                   // MOV RAX, [RAX]
                stubRetHub[h++]=0x48; stubRetHub[h++]=0x85; stubRetHub[h++]=0xC0;                   // TEST RAX, RAX
                stubRetHub[h++]=0x74; stubRetHub[h++]=0x14;                                         // JZ +20 (to ret0)
                // MOV RAX, [RAX + 0xb10]
                stubRetHub[h++]=0x48; stubRetHub[h++]=0x8B; stubRetHub[h++]=0x80;
                stubRetHub[h++]=0x10; stubRetHub[h++]=0x0B; stubRetHub[h++]=0x00; stubRetHub[h++]=0x00; // disp32 = 0xb10
                stubRetHub[h++]=0x48; stubRetHub[h++]=0x85; stubRetHub[h++]=0xC0;                   // TEST RAX, RAX
                stubRetHub[h++]=0x74; stubRetHub[h++]=0x08;                                         // JZ +8 (to ret0)
                // MOV RAX, [RAX + 0xf8]
                stubRetHub[h++]=0x48; stubRetHub[h++]=0x8B; stubRetHub[h++]=0x80;
                stubRetHub[h++]=0xF8; stubRetHub[h++]=0x00; stubRetHub[h++]=0x00; stubRetHub[h++]=0x00; // disp32 = 0xf8
                stubRetHub[h++]=0xC3;                                                               // RET
                // ret0:
                stubRetHub[h++]=0x31; stubRetHub[h++]=0xC0;                                         // XOR EAX, EAX
                stubRetHub[h++]=0xC3;                                                               // RET
                Log("AUTH: +0x188 stub: dynamic Blaze hub reader (%d bytes)", h);
                
                // Fill all vtable entries with stubRet0 (safe default)
                uint64_t ret0Addr = (uint64_t)stubRet0;
                uint64_t ret1Addr = (uint64_t)stubRet1;
                uint64_t retHubAddr = (uint64_t)stubRetHub;
                for (int i = 0; i < 64; i++) {
                    memcpy(fakeVtable + i*8, &ret0Addr, 8);
                }
                // Override +0x138 to return 1 (login permission)
                memcpy(fakeVtable + 0x138, &ret1Addr, 8);
                // Override +0x188 to return Blaze hub (connection object)
                memcpy(fakeVtable + 0x188, &retHubAddr, 8);
                
                // Set the object's vtable pointer
                *(uint64_t*)fakeObj = (uint64_t)fakeVtable;
                
                // Write the fake object pointer to DAT_144b86bf8
                *pSdkMgr = (uint64_t)fakeObj;
                Log("AUTH: Fake SDK object at %p, vtable at %p", fakeObj, fakeVtable);
                Log("AUTH: DAT_144b86bf8 = 0x%llX (after write)", *pSdkMgr);
                Log("AUTH: vtable[0x138/8] = ret1 (login OK), all others = ret0 (safe)");
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { Log("AUTH: Exception creating fake SDK object"); }
    
    Log("AUTH: Polling for slot to clear + forcing 0x53f flag...");
    Sleep(1000);
    
    for (int wait = 0; wait < 300; wait++) {
        __try {
            uint64_t* pOM = (uint64_t*)0x1448a3b20;
            if (*pOM != 0) {
                uint64_t om = *pOM;
                uint8_t* pAuthFail = (uint8_t*)(om + 0x4ece);
                if (*pAuthFail != 0) { *pAuthFail = 0; Log("AUTH: Cleared +0x4ece at %d ms", 1000+wait*100); }
                // Force +0x53f flag on every poll iteration
                uint64_t cm = *(uint64_t*)(om + 0xb10);
                if (cm != 0) {
                    uint64_t bh = *(uint64_t*)(cm + 0xf8);
                    if (bh != 0) {
                        uint8_t* pF = (uint8_t*)(bh + 0x53f);
                        if (*pF == 0) { *pF = 1; }
                    }
                }
                // Still try to capture vtable if we missed it
                uint64_t* pSlot = (uint64_t*)(om + 0x4ea0);
                if (*pSlot != 0 && realVtable == 0) {
                    realVtable = *(uint64_t*)(*pSlot);
                    Log("AUTH: Late vtable capture 0x%llX", realVtable);
                }
                if (*pSlot == 0 && g_caveExecuted == 0) {
                    Log("AUTH: Slot cleared at %d ms", 1000+wait*100);
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        Sleep(100);
    }
    
    __try {
        uint64_t* pOM = (uint64_t*)0x1448a3b20;
        uint64_t om = *pOM;
        Log("AUTH: OnlineMgr=0x%llX", om);
        if (om == 0) { Log("AUTH: NULL!"); goto done; }
        
        uint64_t* pSlot = (uint64_t*)(om + 0x4ea0);
        Log("AUTH: slot=0x%llX cave=%d", *pSlot, g_caveExecuted);
        
        if (*pSlot != 0 || g_caveExecuted != 0) { Log("AUTH: skip (slot busy or cave ran)"); goto done; }
        
        // Allocate fake request object
        BYTE* fr = (BYTE*)VirtualAlloc(NULL, 0x200, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!fr) { Log("AUTH: alloc failed"); goto done; }
        memset(fr, 0, 0x200);
        
        if (realVtable != 0) {
            // Use the REAL vtable from the original request object
            // This ensures the destructor properly transfers the auth token
            *(uint64_t*)fr = realVtable;
            Log("AUTH: Using real vtable 0x%llX", realVtable);
        } else {
            // Fallback: fake vtable with RET stubs
            BYTE* fv = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!fv) { Log("AUTH: vtable alloc failed"); goto done; }
            fv[32] = 0xC3;
            uint64_t ra = (uint64_t)(fv + 32);
            for (int k=0; k<4; k++) memcpy(fv+k*8, &ra, 8);
            *(uint64_t*)fr = (uint64_t)fv;
            Log("AUTH: Using fake vtable (real not captured)");
        }
        strcpy((char*)(fr+0x18), "FIFA17_PC");
        
        // Inject into slot
        *pSlot = (uint64_t)fr;
        Log("AUTH: Injected fake request %p into slot", fr);
        
        // Wait for game tick to process it
        Sleep(5000);
        Log("AUTH: cave=%d slot=0x%llX", g_caveExecuted, *pSlot);
        
        if (g_caveExecuted) {
            Log("AUTH: >>> CAVE EXECUTED! Auth code provided! <<<");
            Log("AUTH: req[+0xd8]=0x%llX req[+0xe8]=%d", *(uint64_t*)(fr+0xd8), *(uint8_t*)(fr+0xe8));
            
            // Don't call FUN_146f39b20 from DLL thread - it doesn't work
            // The Q key press from the batch script will trigger the reconnect
            // on the game's main thread, which is the correct way
            uint32_t* pSt = (uint32_t*)(om + 0x13b8);
            Log("AUTH: state=%d. Auth ready.", *pSt);
            
            // Diagnostic: trace the callback chain with null checks at each step
            uint64_t cm2 = *(uint64_t*)(om + 0xb10);
            Log("AUTH: OnlineMgr+0xb10 = 0x%llX", cm2);
            if (cm2 != 0) {
                uint64_t bHub = *(uint64_t*)(cm2 + 0xf8);
                Log("AUTH: +0xb10+0xf8 (BlazeHub) = 0x%llX", bHub);
                if (bHub != 0) {
                    // Scan BlazeHub for heap pointers that could be the login state machine
                    Log("AUTH: Scanning BlazeHub for ConnectionManager pointers...");
                    int found = 0;
                    for (int off = 0; off < 0x2000 && found < 20; off += 8) {
                        uint64_t val = *(uint64_t*)(bHub + off);
                        // Look for heap pointers (allocated objects)
                        if (val > 0x40000000ULL && val < 0x80000000ULL) {
                            // Check if this pointer's first 8 bytes look like a vtable
                            // (vtable pointers are in the 0x140000000-0x150000000 range)
                            uint64_t possibleVtable = *(uint64_t*)val;
                            if (possibleVtable > 0x140000000ULL && possibleVtable < 0x150000000ULL) {
                                Log("AUTH:   +0x%X = 0x%llX -> vtable=0x%llX", off, val, possibleVtable);
                                found++;
                            }
                        }
                    }
                    Log("AUTH: Found %d objects with vtables in BlazeHub", found);
                } else { Log("AUTH: BlazeHub is NULL"); }
            } else { Log("AUTH: ConnMgr wrapper is NULL"); }
            
            // Force the +0x53f flag on the Blaze hub
            // This flag gates the post-PreAuth callback chain
            uint64_t connMgr = *(uint64_t*)(om + 0xb10);
            if (connMgr != 0) {
                uint64_t bHub = *(uint64_t*)(connMgr + 0xf8);
                if (bHub != 0) {
                    uint8_t* pFlag = (uint8_t*)(bHub + 0x53f);
                    Log("AUTH: BlazeHub(%p)+0x53f = %d", (void*)bHub, *pFlag);
                    if (*pFlag == 0) { *pFlag = 1; Log("AUTH: Forced +0x53f = 1"); }
                } else { Log("AUTH: BlazeHub is NULL"); }
            } else { Log("AUTH: ConnMgr is NULL"); }
        } else {
            Log("AUTH: Cave NOT executed after 5s");
            Log("AUTH: state=%d", *(uint32_t*)(om + 0x13b8));
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { Log("AUTH: Exception"); }
    
done:
    // Apply OSDK patches AFTER game has loaded (these functions are needed during startup)
    // Auth injection completes at ~20s, these patches apply right after
    Log("AUTH: Applying OSDK patches (post-load)...");
    {
        uint64_t osdkFuncs[] = { 0x1470da970, 0x1470daa30, 0x1470db760 };
        const char* osdkNames[] = { "GetProfileSync", "GetSettingSync", "SetPresence" };
        for (int i = 0; i < 3; i++) {
            __try {
                BYTE* f = (BYTE*)osdkFuncs[i];
                DWORD op;
                if (VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &op)) {
                    f[0] = 0x31; f[1] = 0xC0;
                    f[2] = 0xC3;
                    for (int k=3; k<8; k++) f[k] = 0x90;
                    VirtualProtect(f, 8, op, &op);
                    Log("PATCHED: %s -> return 0 (post-load)", osdkNames[i]);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        
        // Patch 17: NOP the OSDK Logout function
        __try {
            BYTE* logoutFn = (BYTE*)0x1472d62a0;
            DWORD op;
            if (VirtualProtect(logoutFn, 8, PAGE_EXECUTE_READWRITE, &op)) {
                logoutFn[0] = 0xC3;
                for (int k=1; k<8; k++) logoutFn[k] = 0x90;
                VirtualProtect(logoutFn, 8, op, &op);
                Log("PATCHED: FUN_1472d62a0 (OSDK Logout) -> RET");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        
        // Patch 18: Skip age check in FUN_14717d5d0
        // This function checks the user's age and shows "OSDK_UNDERAGE_ERROR"
        // if the DOB is missing or the user is too young.
        // We patch it to return immediately — skip the entire age check.
        __try {
            BYTE* ageCheckFn = (BYTE*)0x14717d5d0;
            Log("AGE_CHECK: addr=%p bytes=%02X %02X %02X %02X", ageCheckFn, ageCheckFn[0], ageCheckFn[1], ageCheckFn[2], ageCheckFn[3]);
            DWORD op;
            if (VirtualProtect(ageCheckFn, 8, PAGE_EXECUTE_READWRITE, &op)) {
                ageCheckFn[0] = 0xC3; // RET
                for (int k=1; k<8; k++) ageCheckFn[k] = 0x90;
                VirtualProtect(ageCheckFn, 8, op, &op);
                Log("PATCHED: FUN_14717d5d0 (age check) -> RET (skip age restriction)");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("AGE_CHECK: Exception");
        }
        
        // Patch 19: Make FUN_146e1dae0 always return true (1)
        // Frida v41 showed: Login job is created but FUN_146e1dae0 returns false
        // because the login type array (loginSM+0x218 to +0x220) is empty.
        // The array is empty because the PreAuth TDF decoder doesn't populate it.
        // Returning true makes the Login flow proceed to send the actual Login RPC.
        __try {
            BYTE* loginCheckFn = (BYTE*)0x146e1dae0;
            Log("LOGIN_CHECK: addr=%p bytes=%02X %02X %02X %02X", loginCheckFn, loginCheckFn[0], loginCheckFn[1], loginCheckFn[2], loginCheckFn[3]);
            DWORD op;
            if (VirtualProtect(loginCheckFn, 8, PAGE_EXECUTE_READWRITE, &op)) {
                loginCheckFn[0] = 0xB0; loginCheckFn[1] = 0x01; // MOV AL, 1
                loginCheckFn[2] = 0xC3; // RET
                for (int k=3; k<8; k++) loginCheckFn[k] = 0x90;
                VirtualProtect(loginCheckFn, 8, op, &op);
                Log("PATCHED: FUN_146e1dae0 (login check) -> return 1 (always proceed)");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("LOGIN_CHECK: Exception");
        }
    }
    
    // Keep forcing +0x53f flag continuously in background
    // This ensures it's set before any connection attempt
    Log("AUTH: Starting continuous flag enforcer (+0x53f + connState)...");
    for (int i = 0; i < 6000; i++) { // 10 minutes
        __try {
            uint64_t* pOM = (uint64_t*)0x1448a3b20;
            if (*pOM != 0) {
                uint64_t om = *pOM;
                
                // Force connState to 0 (idle/ready) — prevent OSDK errors from setting it to 2
                uint32_t* pState = (uint32_t*)(om + 0x13b8);
                if (*pState == 2) { *pState = 0; }
                
                uint64_t cm = *(uint64_t*)(om + 0xb10);
                if (cm != 0) {
                    uint64_t bh = *(uint64_t*)(cm + 0xf8);
                    if (bh != 0) {
                        uint8_t* pF = (uint8_t*)(bh + 0x53f);
                        if (*pF == 0) { *pF = 1; }
                    }
                }
                
                // CreateAccount handled by sync cave (state bytes set, no OSDK screen)
                // CreateAccount handled by trampoline (original handler runs)
                if (g_createAcctCalled == 1) {
                    g_createAcctCalled = 2;
                    Log("CA-DETECT: CreateAccount handler ran (original code with R8D=0)");
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_logCS);
        LoadRealDinput8();
        
        // CRITICAL: Create fake SDK object BEFORE game init runs
        // DAT_144b86bf8 must be non-NULL when the BlazeHub is created,
        // otherwise the login state machine is never initialized.
        // DllMain runs before the game's entry point, so this is early enough.
        __try {
            uint64_t* pSdkMgr = (uint64_t*)0x144b86bf8;
            if (*pSdkMgr == 0) {
                // Allocate fake vtable (0x400 bytes = covers up to offset +0x1F8)
                BYTE* fv = (BYTE*)VirtualAlloc(NULL, 0x400, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                // Allocate fake object (0x1000 bytes)
                BYTE* fo = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                if (fv && fo) {
                    memset(fo, 0, 0x1000);
                    // Stub: XOR EAX,EAX / RET (return 0)
                    BYTE* stubRet0 = fv + 0x300;
                    stubRet0[0] = 0x31; stubRet0[1] = 0xC0; stubRet0[2] = 0xC3;
                    // Stub: MOV AL,1 / RET (return 1)
                    BYTE* stubRet1 = fv + 0x310;
                    stubRet1[0] = 0xB0; stubRet1[1] = 0x01; stubRet1[2] = 0xC3;
                    // Dynamic Blaze hub reader stub
                    BYTE* stubHub = fv + 0x320;
                    uint64_t omAddr = 0x1448a3b20;
                    int h = 0;
                    stubHub[h++]=0x48; stubHub[h++]=0xB8; memcpy(stubHub+h,&omAddr,8); h+=8;
                    stubHub[h++]=0x48; stubHub[h++]=0x8B; stubHub[h++]=0x00;
                    stubHub[h++]=0x48; stubHub[h++]=0x85; stubHub[h++]=0xC0;
                    stubHub[h++]=0x74; stubHub[h++]=0x14;
                    stubHub[h++]=0x48; stubHub[h++]=0x8B; stubHub[h++]=0x80;
                    stubHub[h++]=0x10; stubHub[h++]=0x0B; stubHub[h++]=0x00; stubHub[h++]=0x00;
                    stubHub[h++]=0x48; stubHub[h++]=0x85; stubHub[h++]=0xC0;
                    stubHub[h++]=0x74; stubHub[h++]=0x08;
                    stubHub[h++]=0x48; stubHub[h++]=0x8B; stubHub[h++]=0x80;
                    stubHub[h++]=0xF8; stubHub[h++]=0x00; stubHub[h++]=0x00; stubHub[h++]=0x00;
                    stubHub[h++]=0xC3;
                    stubHub[h++]=0x31; stubHub[h++]=0xC0; stubHub[h++]=0xC3;
                    
                    // Fill vtable with ret0
                    uint64_t r0 = (uint64_t)stubRet0;
                    uint64_t r1 = (uint64_t)stubRet1;
                    uint64_t rh = (uint64_t)stubHub;
                    for (int i = 0; i < 64; i++) memcpy(fv+i*8, &r0, 8);
                    memcpy(fv + 0x138, &r1, 8); // login permission = 1
                    memcpy(fv + 0x188, &rh, 8); // Blaze hub reader
                    
                    *(uint64_t*)fo = (uint64_t)fv; // vtable pointer
                    // Set +0x3a0 to a fake user ID (used by FUN_1470da6d0)
                    *(uint64_t*)(fo + 0x3a0) = 33068179;
                    
                    *pSdkMgr = (uint64_t)fo;
                    // Can't use Log() here safely (logCS might not be ready)
                    // but we initialized it above, so it should be fine
                    Log("EARLY: Fake SDK object at %p, vtable at %p", fo, fv);
                    Log("EARLY: DAT_144b86bf8 = 0x%llX (set BEFORE game init)", *pSdkMgr);
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // If the address isn't mapped yet, we'll set it in the background thread
        }
        
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_realDinput8) FreeLibrary(g_realDinput8);
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCS);
    }
    return TRUE;
}
