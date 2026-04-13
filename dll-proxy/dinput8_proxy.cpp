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

static int g_codePatchDone=0, g_originPatchDone=0, g_authBypassDone=0, g_authFlagDone=0, g_patched=0, g_loginPatchCount=0;
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
    Log("=== FIFA 17 v68 (patches + auth re-injection) ===");
    Log("PID: %lu", GetCurrentProcessId());
    
    DWORD st = GetTickCount();
    for (int i=0; i<3000; i++) {
        Sleep(100);
        __try {
            if(!g_codePatchDone) PatchCertCheck();
            if(!g_originPatchDone) PatchOriginCheck();
            if(!g_authBypassDone) PatchAuthBypass();
            if(!g_authFlagDone) PatchAuthFlag();
            if(g_loginPatchCount<2) PatchIsLoggedInFunctions();
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        if(g_codePatchDone&&g_originPatchDone&&g_authBypassDone&&g_authFlagDone&&g_loginPatchCount>=2) { Log("All patches in %lu ms",GetTickCount()-st); break; }
    }
    Log("patches: %d (cert=%d orig=%d auth=%d flag=%d login=%d)", g_patched, g_codePatchDone, g_originPatchDone, g_authBypassDone, g_authFlagDone, g_loginPatchCount);
    
    // The original auth request fired at ~100ms, called FUN_1470db3c0 (unpatched),
    // which blocked for 15s in STP timeout, returned error, slot was cleared.
    // Our patch to FUN_1470db3c0 body landed at ~640ms but the function was already
    // executing. We wait for the 15s timeout to complete, then re-inject a fake
    // request object so the game processes it with our patched function.
    Log("AUTH: Waiting 18s for STP timeout to complete...");
    Sleep(18000);
    
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
        BYTE* fv = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!fr || !fv) { Log("AUTH: alloc failed"); goto done; }
        memset(fr, 0, 0x200);
        
        // Fake vtable: all entries point to a RET stub
        fv[32] = 0xC3; // RET instruction
        uint64_t ra = (uint64_t)(fv + 32);
        for (int k=0; k<4; k++) memcpy(fv+k*8, &ra, 8);
        *(uint64_t*)fr = (uint64_t)fv;           // +0x00: vtable
        strcpy((char*)(fr+0x18), "FIFA17_PC");    // +0x18: client ID
        
        // Inject into slot
        *pSlot = (uint64_t)fr;
        Log("AUTH: Injected fake request %p into slot", fr);
        
        // Wait for game tick to process it
        Sleep(5000);
        Log("AUTH: cave=%d slot=0x%llX", g_caveExecuted, *pSlot);
        
        if (g_caveExecuted) {
            Log("AUTH: >>> CAVE EXECUTED! Auth code provided! <<<");
            Log("AUTH: req[+0xd8]=0x%llX req[+0xe8]=%d", *(uint64_t*)(fr+0xd8), *(uint8_t*)(fr+0xe8));
            
            // Clear disconnect state to trigger reconnect
            uint32_t* pSt = (uint32_t*)(om + 0x13b8);
            Log("AUTH: state=%d, clearing...", *pSt);
            *(uint8_t*)(om + 0x13a8) = 0;
            *(uint16_t*)(om + 0x13b4) = 0;
            *pSt = 0;
            Log("AUTH: State cleared. Reconnect should happen now.");
        } else {
            Log("AUTH: Cave NOT executed after 5s");
            Log("AUTH: state=%d", *(uint32_t*)(om + 0x13b8));
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { Log("AUTH: Exception"); }
    
done:
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
