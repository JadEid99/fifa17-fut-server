/**
 * dinput8.dll Proxy for FIFA 17 SSL Bypass
 * 
 * This DLL gets loaded by FIFA 17 instead of the real dinput8.dll.
 * It forwards all DirectInput8 calls to the real system DLL, and
 * also patches the ProtoSSL certificate verification to always succeed.
 * 
 * Build with:
 *   cl /LD /O2 dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Forward declare what we need from dinput
struct IUnknown;
typedef IUnknown* LPUNKNOWN;

// ============================================================
// DirectInput8 forwarding
// ============================================================

typedef HRESULT(WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
typedef HRESULT(WINAPI* DllCanUnloadNow_t)(void);
typedef HRESULT(WINAPI* DllGetClassObject_t)(REFCLSID, REFIID, LPVOID*);
typedef HRESULT(WINAPI* DllRegisterServer_t)(void);
typedef HRESULT(WINAPI* DllUnregisterServer_t)(void);

static HMODULE g_realDinput8 = NULL;
static DirectInput8Create_t g_realDirectInput8Create = NULL;

static void LoadRealDinput8() {
    if (g_realDinput8) return;
    
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    strcat_s(systemDir, "\\dinput8.dll");
    
    g_realDinput8 = LoadLibraryA(systemDir);
    if (g_realDinput8) {
        g_realDirectInput8Create = (DirectInput8Create_t)GetProcAddress(g_realDinput8, "DirectInput8Create");
    }
}

extern "C" {
    __declspec(dllexport) HRESULT WINAPI DirectInput8Create(
        HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter) {
        LoadRealDinput8();
        if (g_realDirectInput8Create)
            return g_realDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
        return E_FAIL;
    }

    __declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
        LoadRealDinput8();
        auto fn = (DllCanUnloadNow_t)GetProcAddress(g_realDinput8, "DllCanUnloadNow");
        return fn ? fn() : S_FALSE;
    }

    __declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
        LoadRealDinput8();
        auto fn = (DllGetClassObject_t)GetProcAddress(g_realDinput8, "DllGetClassObject");
        return fn ? fn(rclsid, riid, ppv) : E_FAIL;
    }

    __declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
        LoadRealDinput8();
        auto fn = (DllRegisterServer_t)GetProcAddress(g_realDinput8, "DllRegisterServer");
        return fn ? fn() : E_FAIL;
    }

    __declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) {
        LoadRealDinput8();
        auto fn = (DllUnregisterServer_t)GetProcAddress(g_realDinput8, "DllUnregisterServer");
        return fn ? fn() : E_FAIL;
    }
}

// ============================================================
// SSL Bypass - Patch ProtoSSL certificate verification
// ============================================================

static FILE* g_logFile = NULL;

static void Log(const char* fmt, ...) {
    if (!g_logFile) {
        g_logFile = fopen("fifa17_ssl_bypass.log", "a");
    }
    if (g_logFile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
}

// Search for a byte pattern in a memory range
static BYTE* FindPattern(BYTE* start, SIZE_T size, const BYTE* pattern, const char* mask, SIZE_T patternLen) {
    for (SIZE_T i = 0; i <= size - patternLen; i++) {
        bool found = true;
        for (SIZE_T j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && start[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return &start[i];
    }
    return NULL;
}

static void PatchSSL() {
    Log("=== FIFA 17 SSL Bypass DLL ===");
    
    HMODULE gameModule = GetModuleHandleA("FIFA17.exe");
    if (!gameModule) {
        Log("ERROR: Could not find FIFA17.exe module");
        return;
    }
    
    BYTE* baseAddr = (BYTE*)gameModule;
    
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
    SIZE_T moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    Log("FIFA17.exe base=0x%p size=0x%llX", baseAddr, (unsigned long long)moduleSize);
    
    // Pattern 1: The error handling path (JE that decides to disconnect)
    // 40 38 BB 86 03 00 00 74 13 BA 0F A2 FF E7 8D 92 F3 5D 00 18
    BYTE pattern1[] = { 
        0x40, 0x38, 0xBB, 0x86, 0x03, 0x00, 0x00,
        0x74, 0x13,
        0xBA, 0x0F, 0xA2, 0xFF, 0xE7,
        0x8D, 0x92, 0xF3, 0x5D, 0x00, 0x18
    };
    char mask1[] = "xxxxxxxxxxxxxxxxxxxx";
    
    Log("Searching for patterns (waiting for Denuvo)...");
    
    BYTE* found1 = NULL;
    for (int attempt = 0; attempt < 30; attempt++) {
        found1 = FindPattern(baseAddr, moduleSize, pattern1, mask1, sizeof(pattern1));
        if (found1) break;
        Sleep(1000);
        if (attempt % 10 == 0) Log("Scan attempt %d/30...", attempt);
    }
    
    if (found1) {
        Log("Found error handler pattern at 0x%p (+0x%llX)", found1, (unsigned long long)(found1 - baseAddr));
        
        // Patch JE -> JMP
        BYTE* jeAddr = found1 + 7;
        DWORD oldProtect;
        VirtualProtect(jeAddr, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
        jeAddr[0] = 0xEB;
        VirtualProtect(jeAddr, 2, oldProtect, &oldProtect);
        Log("Patched JE -> JMP at 0x%p", jeAddr);
        
        // Patch disconnect function
        BYTE* callAddr = found1 + 20;
        if (callAddr[0] == 0xE8) {
            int32_t callOffset = *(int32_t*)(callAddr + 1);
            BYTE* targetFunc = callAddr + 5 + callOffset;
            VirtualProtect(targetFunc, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
            targetFunc[0] = 0x31; targetFunc[1] = 0xC0; targetFunc[2] = 0xC3;
            VirtualProtect(targetFunc, 3, oldProtect, &oldProtect);
            Log("Patched disconnect func at 0x%p to return 0", targetFunc);
        }
    } else {
        Log("Error handler pattern not found");
    }
    
    // Pattern 2: Find the _ProtoSSLUpdate or state machine function
    // that processes the Certificate message. We need to find where
    // the cert verification result is checked and force it to succeed.
    //
    // From the state machine code at +0x6126463:
    //   83 BB 8C 00 00 00 06  = cmp dword [rbx+0x8C], 6
    //   0F 85 CB 00 00 00     = jne +0xCB
    // State 6 is the cert processing state.
    
    BYTE pattern2[] = {
        0x83, 0xBB, 0x8C, 0x00, 0x00, 0x00, 0x06,  // cmp [rbx+0x8C], 6
        0x0F, 0x85                                    // jne (start of)
    };
    char mask2[] = "xxxxxxxxx";
    
    BYTE* found2 = FindPattern(baseAddr, moduleSize, pattern2, mask2, sizeof(pattern2));
    if (found2) {
        Log("Found state 6 check at 0x%p (+0x%llX)", found2, (unsigned long long)(found2 - baseAddr));
        
        // Read the full jne offset
        int32_t jneOffset = *(int32_t*)(found2 + 9);
        BYTE* jneTarget = found2 + 13 + jneOffset;
        Log("State 6 jne target: 0x%p (skips cert processing)", jneTarget);
        
        // The code AFTER the jne (at found2+13) is the cert processing block.
        // We need to find the call within this block that does verification
        // and patch it. Let's scan the next 256 bytes for CALL instructions.
        Log("Scanning cert processing block for CALL instructions...");
        for (int i = 13; i < 256; i++) {
            if (found2[i] == 0xE8) {
                int32_t offset = *(int32_t*)(found2 + i + 1);
                BYTE* target = found2 + i + 5 + offset;
                // Check if target is within the game module
                if (target >= baseAddr && target < baseAddr + moduleSize) {
                    Log("  CALL at +%d -> 0x%p (+0x%llX)", i, target, (unsigned long long)(target - baseAddr));
                }
            }
        }
    } else {
        Log("State 6 pattern not found");
    }
    
    // Pattern 3: Search for the actual _VerifyCertificate function
    // In newer DirtySDK, the return value might not be -30 directly.
    // Instead, look for the memcmp pattern: the function calls memcmp
    // and checks the result. In x64, after a call, the result is in eax.
    // The pattern would be: call memcmp; test eax, eax; jne error
    // Which is: E8 xx xx xx xx 85 C0 75 xx (or 0F 85 for far jne)
    
    // Actually, let's try a different approach: search for the pattern
    // where the function loads the hash size and compares.
    // In ProtoSSL: memcmp(pCert->HashData, ..., pCert->iHashSize)
    // If iHashSize is loaded into a register and then used as the 3rd arg
    // to memcmp (rcx=ptr1, rdx=ptr2, r8=size on Windows x64)
    
    // Let's just try to find and hook ALL calls near the cert processing
    // by patching the state machine to skip state 6 entirely.
    // Change: cmp [rbx+0x8C], 6 -> cmp [rbx+0x8C], 0xFF (never matches)
    if (found2) {
        // Don't skip state 6 - instead patch the functions it calls
        
        // Patch all functions called from the cert processing block
        // These are the actual cert verification functions
        DWORD oldProt2;
        
        // Skip global function patches - let them run normally
        Log("Skipping global patches on +0x612E770 and +0x612EBA0");
        
        // Instead of patching the functions to return 0, patch the CALL sites
        // to NOP out the calls and set eax=0 manually.
        // This way the cert parsing still happens but verification calls are skipped.
        
        // CALL at +130 -> 0x612E770 (verification)
        // Replace: E8 xx xx xx xx with: 31 C0 90 90 90 (xor eax,eax; nop; nop; nop)
        BYTE* call1 = found2 + 130;
        if (call1[0] == 0xE8) {
            DWORD oldProt2;
            VirtualProtect(call1, 5, PAGE_EXECUTE_READWRITE, &oldProt2);
            call1[0] = 0x31; call1[1] = 0xC0; // xor eax, eax
            call1[2] = 0x90; call1[3] = 0x90; call1[4] = 0x90; // nop nop nop
            VirtualProtect(call1, 5, oldProt2, &oldProt2);
            Log("NOP'd CALL at +130 (verification call 1)");
        }
        
        // CALL at +174 -> 0x612EBA0 (verification 2)
        BYTE* call2 = found2 + 174;
        if (call2[0] == 0xE8) {
            DWORD oldProt2;
            VirtualProtect(call2, 5, PAGE_EXECUTE_READWRITE, &oldProt2);
            call2[0] = 0x31; call2[1] = 0xC0;
            call2[2] = 0x90; call2[3] = 0x90; call2[4] = 0x90;
            VirtualProtect(call2, 5, oldProt2, &oldProt2);
            Log("NOP'd CALL at +174 (verification call 2)");
        }
        
        // CALL at +195 -> 0x612E770 (verification 3)
        BYTE* call3 = found2 + 195;
        if (call3[0] == 0xE8) {
            DWORD oldProt2;
            VirtualProtect(call3, 5, PAGE_EXECUTE_READWRITE, &oldProt2);
            call3[0] = 0x31; call3[1] = 0xC0;
            call3[2] = 0x90; call3[3] = 0x90; call3[4] = 0x90;
            VirtualProtect(call3, 5, oldProt2, &oldProt2);
            Log("NOP'd CALL at +195 (verification call 3)");
        }
    } // close if (found2)
        
    // The REAL cert processing is in STATE 3 at +0x61262DC, not state 6!
    // Search for state 3 pattern directly
    BYTE pattern3[] = { 0x83, 0xBB, 0x8C, 0x00, 0x00, 0x00, 0x03 };
    char mask3[] = "xxxxxxx";
    BYTE* state3Match = FindPattern(baseAddr, moduleSize, pattern3, mask3, 7);
    
    if (state3Match) {
        Log("Found state 3 check at +0x%llX", (unsigned long long)(state3Match - baseAddr));
        
        // State 3 handler is between this check and the state 4 check
        // State 4 is at +0x612634D (from our scan)
        // Scan forward from state3Match for CALL instructions
        BYTE* scanStart = state3Match + 7; // skip the cmp instruction
        SIZE_T scanSize = 128; // scan next 128 bytes
        
        Log("Scanning state 3 handler for CALL instructions:");
        for (SIZE_T i = 0; i < scanSize; i++) {
            if (scanStart[i] == 0xE8) {
                int32_t offset = *(int32_t*)(scanStart + i + 1);
                BYTE* target = scanStart + i + 5 + offset;
                if (target >= baseAddr && target < baseAddr + moduleSize) {
                    Log("  CALL at state3+%llu -> +0x%llX", (unsigned long long)(i + 7), (unsigned long long)(target - baseAddr));
                    
                    // Only patch the VERIFICATION call, let others run normally
                    // Call 3 at state3+53 -> +0x6124140 is likely _VerifyCertificate
                    DWORD oldProt3;
                    if (i + 7 == 53) { // This is the verification call
                        VirtualProtect(scanStart + i, 5, PAGE_EXECUTE_READWRITE, &oldProt3);
                        scanStart[i] = 0xB8; scanStart[i+1] = 0x01;
                        scanStart[i+2] = 0x00; scanStart[i+3] = 0x00; scanStart[i+4] = 0x00;
                        VirtualProtect(scanStart + i, 5, oldProt3, &oldProt3);
                        Log("  -> Patched VERIFICATION call to return 1");
                    } else {
                        Log("  -> Keeping this call intact (network I/O)");
                    }
                }
            }
        }
        
        // Also dump raw bytes for analysis
        Log("State 3 raw bytes (first 128):");
        for (SIZE_T i = 0; i < 128 && i < scanSize + 7; i += 16) {
            char hex[128] = {0};
            for (SIZE_T j = 0; j < 16; j++) {
                sprintf(hex + j * 3, "%02X ", state3Match[i + j]);
            }
            Log("  +%04llX: %s", (unsigned long long)i, hex);
        }
    } else {
        Log("State 3 pattern NOT FOUND!");
    }
    
    Log("All patches applied!");
    
    // Scan for ALL state machine checks to understand the full state flow
    Log("Scanning for ALL SSL state checks (cmp [rbx+0x8C], N)...");
    BYTE statePattern[] = { 0x83, 0xBB, 0x8C, 0x00, 0x00, 0x00 };
    char stateMask[] = "xxxxxx";
    BYTE* stateSearch = baseAddr;
    SIZE_T stateRemaining = moduleSize;
    int stateCount = 0;
    while (stateRemaining > 7) {
        BYTE* match = FindPattern(stateSearch, stateRemaining, statePattern, stateMask, 6);
        if (!match) break;
        BYTE stateNum = match[6];
        Log("  State %d check at +0x%llX", stateNum, (unsigned long long)(match - baseAddr));
        stateCount++;
        SIZE_T advance = (match - stateSearch) + 7;
        stateSearch = match + 7;
        stateRemaining -= advance;
        if (stateCount > 50) break;
    }
    Log("Found %d state checks total", stateCount);
}

// ============================================================
// DLL Entry Point
// ============================================================

static DWORD WINAPI PatchThread(LPVOID) {
    Sleep(5000);
    PatchSSL();
    
    // Also hook recv to monitor what the game reads
    HMODULE ws2 = GetModuleHandleA("WS2_32.dll");
    if (ws2) {
        typedef int (WINAPI *recv_t)(UINT_PTR, char*, int, int);
        static recv_t real_recv = (recv_t)GetProcAddress(ws2, "recv");
        // We can't easily hook recv from here without a hooking library
        // Just log that we're done
        Log("WS2_32.dll found, recv monitoring would go here");
    }
    
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        LoadRealDinput8();
        // Start the patch thread - we need to wait for Denuvo
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_realDinput8) FreeLibrary(g_realDinput8);
        if (g_logFile) fclose(g_logFile);
    }
    return TRUE;
}
