/**
 * dinput8.dll Proxy - v68
 * 
 * Patch 1: Cert verification bypass (JNZ -> JMP)
 * Patch 2: Origin SDK availability check (always true)
 * Patch 3: FUN_1470db3c0 body replacement (fake auth code, instant return)
 * Patch 4: Auth bypass flag ([RBX+0x2061]=1)
 * Patch 5+6: IsLoggedIntoEA + IsLoggedIntoNetwork (always true)
 * 
 * After patches: Re-inject fake auth request into the cleared slot so the
 * game's tick function processes it with our patched FUN_1470db3c0.
 * Then clear disconnect state to trigger reconnect with Login.
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
                    // MOV RAX, &fakeAuthCode / MOV [R8], RAX
                    targetFunc[o++]=0x48;targetFunc[o++]=0xB8;memcpy(targetFunc+o,&aa,8);o+=8;
                    targetFunc[o++]=0x49;targetFunc[o++]=0x89;targetFunc[o++]=0x00;
                    // MOV RAX, strlen / MOV [R9], RAX
                    targetFunc[o++]=0x48;targetFunc[o++]=0xB8;memcpy(targetFunc+o,&al,8);o+=8;
                    targetFunc[o++]=0x49;targetFunc[o++]=0x89;targetFunc[o++]=0x01;
                    // XOR EAX,EAX / RET
                    targetFunc[o++]=0x31;targetFunc[o++]=0xC0;targetFunc[o++]=0xC3;
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
    
    // Part C: Don't NOP PreAuth disconnect - let normal callback flow work
    // PreAuth → disconnect → callback → check login type → send Login on new connection
    Log("PREAUTH: Not patching disconnect (normal callback flow)");
    
    g_sdkGateDone = 1; g_patched++;
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
    Log("=== FIFA 17 v91 (safe callback chain trace) ===");
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
        if(g_codePatchDone&&g_originPatchDone&&g_authBypassDone&&g_authFlagDone&&g_loginPatchCount>=2&&g_sdkGateDone) { Log("All patches in %lu ms",GetTickCount()-st); break; }
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
            Log("AUTH: SDK manager is NULL. Creating fake object...");
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
                    // Dump a range around +0x750 to find the login state machine
                    Log("AUTH: BlazeHub dump around +0x740:");
                    for (int off = 0x740; off <= 0x790; off += 8) {
                        uint64_t val = *(uint64_t*)(bHub + off);
                        Log("AUTH:   +0x%X = 0x%llX %s", off, val,
                            (val > 0x140000000ULL && val < 0x150000000ULL) ? "(code ptr?)" :
                            (val > 0x10000000ULL && val < 0x800000000ULL) ? "(heap ptr?)" : "");
                    }
                    uint64_t loginSM = *(uint64_t*)(bHub + 0x750);
                    Log("AUTH: BlazeHub+0x750 (LoginSM) = 0x%llX", loginSM);
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
    // Keep forcing +0x53f flag continuously in background
    // This ensures it's set before any connection attempt
    Log("AUTH: Starting continuous +0x53f flag enforcer...");
    for (int i = 0; i < 6000; i++) { // 10 minutes
        __try {
            uint64_t* pOM = (uint64_t*)0x1448a3b20;
            if (*pOM != 0) {
                uint64_t om = *pOM;
                uint64_t cm = *(uint64_t*)(om + 0xb10);
                if (cm != 0) {
                    uint64_t bh = *(uint64_t*)(cm + 0xf8);
                    if (bh != 0) {
                        uint8_t* pF = (uint8_t*)(bh + 0x53f);
                        if (*pF == 0) { *pF = 1; }
                    }
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
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_realDinput8) FreeLibrary(g_realDinput8);
        if (g_logFile) fclose(g_logFile);
        DeleteCriticalSection(&g_logCS);
    }
    return TRUE;
}
