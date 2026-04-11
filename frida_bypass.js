console.log("[*] v17 - patch error handler + state machine");
var base = Process.getModuleByName("FIFA17.exe").base;

// From stack trace:
// exe+0x6126453 - SSL state machine (cert failure point)
// exe+0x612E7C5 - error handler (return addr, so call was at ~0x612E7C0)
// exe+0x612D730 - disconnect caller

// Strategy: Look at the state machine code at exe+0x6126440.
// From v15 dump:
// +6126440: 75 21 40 38 bb 20 0c 00 00 75 18 48 8b 0b e8 1d
// +6126450: 83 00 00 66 c7 83 1f 0c 00 00 00 01 40 88 bb 21
// +6126460: 0c 00 00 83 bb 8c 00 00 00 06 0f 85 cb 00 00 00
//
// At +0x6126440: 75 21 = JNE +0x21 (jump if not equal, skip 33 bytes)
// This is likely: if (cert_verify_failed) { jump to error }
// If we change 75 (JNE) to EB (JMP), it always jumps = always skips the error
// OR change 75 to 90 90 (NOP NOP) = never jumps = always falls through
//
// Actually, 75 21 means "jump over 33 bytes if ZF=0"
// We need to understand what the jump skips.
// Let's look more carefully:
//
// 6126440: 75 21          JNE +0x21 (to 0x6126463)
// 6126442: 40 38 bb 20 0c 00 00  CMP [rbx+0xC20], dil
// 6126449: 75 18          JNE +0x18 (to 0x6126463)  
// 612644B: 48 8b 0b       MOV rcx, [rbx]
// 612644E: E8 1D 83 00 00 CALL exe+0x612E770
// 6126453: 66 c7 83 1f 0c 00 00 00 01  MOV WORD [rbx+0xC1F], 0x0100
// 612645C: 40 88 bb 21 0c 00 00  MOV [rbx+0xC21], dil
// 6126463: 83 bb 8c 00 00 00 06  CMP DWORD [rbx+0x8C], 6
//
// So the flow is:
// if (something != 0) goto 0x6126463 (skip error handling)
// if ([rbx+0xC20] != dil) goto 0x6126463 (skip error handling)
// CALL exe+0x612E770 (this is the error handler!)
// set some state bytes
// 0x6126463: check if state == 6
//
// The CALL at 0x612644E calls 0x612E770 which is the error handler.
// The return address would be 0x6126453 - matches our stack trace!
//
// To bypass: NOP the CALL at 0x612644E (5 bytes: E8 1D 83 00 00)

var callAddr = base.add(0x612644E);
var b = callAddr.readU8();
console.log("[*] Byte at exe+0x612644E: 0x" + b.toString(16));

if (b === 0xE8) {
    var disp = callAddr.add(1).readS32();
    var target = callAddr.add(5).add(disp);
    console.log("[*] CALL target: exe+" + target.sub(base));
    
    Memory.protect(callAddr, 5, 'rwx');
    callAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd CALL at exe+0x612644E!");
    
    // Also NOP the state-setting after it to be safe
    // 6126453: 66 c7 83 1f 0c 00 00 00 01 = MOV WORD [rbx+0xC1F], 0x0100
    // This sets an error state. NOP it too (9 bytes)
    var stateAddr = base.add(0x6126453);
    Memory.protect(stateAddr, 9, 'rwx');
    stateAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd error state write at exe+0x6126453!");
    
    // And NOP the byte write after that
    // 612645C: 40 88 bb 21 0c 00 00 = MOV [rbx+0xC21], dil
    var byteAddr = base.add(0x612645C);
    Memory.protect(byteAddr, 7, 'rwx');
    byteAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd flag write at exe+0x612645C!");
} else {
    console.log("[-] Expected E8, got 0x" + b.toString(16));
}

console.log("[*] Trigger connection now.");
