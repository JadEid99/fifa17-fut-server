/*
 * Frida v45: Dump FUN_146e15070 bytes to find the CreateAccount command (0x0A)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v45: Dump FUN_146e15070 ===');

// Dump first 200 bytes of FUN_146e15070
var fn = addr(0x6e15070);
var bytes = new Uint8Array(fn.readByteArray(200));
console.log('[DUMP] FUN_146e15070 first 200 bytes:');
for (var row = 0; row < 200; row += 16) {
    var hex = '';
    var ascii = '';
    for (var col = 0; col < 16 && row + col < 200; col++) {
        hex += ('0' + bytes[row + col].toString(16)).slice(-2) + ' ';
        ascii += (bytes[row + col] >= 32 && bytes[row + col] < 127) ? String.fromCharCode(bytes[row + col]) : '.';
    }
    console.log('  +' + ('0' + row.toString(16)).slice(-2) + ': ' + hex + ' ' + ascii);
}

// Search for value 0x0A in various instruction encodings
console.log('\n[SEARCH] Looking for value 10 (0x0A) in instructions:');
for (var i = 0; i < 190; i++) {
    // MOV R8D, imm32: 41 B8 0A 00 00 00
    if (bytes[i] === 0x41 && bytes[i+1] === 0xB8 && bytes[i+2] === 0x0A) {
        console.log('  +' + i.toString(16) + ': MOV R8D, 0x0A (41 B8 0A ...)');
    }
    // MOV R8D, imm8 via different encoding
    if (bytes[i] === 0x41 && bytes[i+1] === 0xB0 && bytes[i+2] === 0x0A) {
        console.log('  +' + i.toString(16) + ': MOV R8B, 0x0A (41 B0 0A)');
    }
    // PUSH 0x0A / MOV ECX,0x0A etc
    if (bytes[i] === 0x6A && bytes[i+1] === 0x0A) {
        console.log('  +' + i.toString(16) + ': PUSH 0x0A (6A 0A)');
    }
    // MOV reg, 0x0A (various)
    if (bytes[i+1] === 0x0A && bytes[i+2] === 0x00 && bytes[i+3] === 0x00 && bytes[i+4] === 0x00) {
        console.log('  +' + i.toString(16) + ': possible imm32=0x0A: ' + 
            ('0'+bytes[i].toString(16)).slice(-2) + ' 0A 00 00 00');
    }
}

console.log('=== Done ===');
