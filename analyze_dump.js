/**
 * Analyze the dump to understand state transitions and find why
 * the handshake hangs after bAllowAnyCert bypass.
 * Run on Windows: node analyze_dump.js
 */
const fs = require('fs');
const dump = fs.readFileSync('D:\\Games\\FIFA 17\\FIFA17_dumped.bin');
console.log('Dump size:', dump.length);

// Find all iState assignments (C7 83 8C 00 00 00 XX 00 00 00)
const statePattern = Buffer.from([0xC7, 0x83, 0x8C, 0x00, 0x00, 0x00]);
let pos = 0;
console.log('\n=== All iState assignments ===');
while (true) {
    pos = dump.indexOf(statePattern, pos);
    if (pos === -1) break;
    const val = dump.readUInt32LE(pos + 6);
    if (val <= 20) { // reasonable state values
        console.log('  iState = ' + val + ' at +0x' + pos.toString(16));
    }
    pos++;
}

// Dump 64 bytes around the State 3->4 transition at +0x612631C
console.log('\n=== Code around State 3->4 transition (+0x6126310) ===');
for (let i = 0; i < 64; i += 16) {
    const off = 0x6126310 + i;
    const bytes = [];
    for (let j = 0; j < 16; j++) bytes.push(dump[off+j].toString(16).padStart(2,'0'));
    console.log('  +' + off.toString(16) + ': ' + bytes.join(' '));
}

// Dump the code between State 3 cert check and State 4
// This is where the cert is parsed and the key is extracted
console.log('\n=== State 3 handler (+0x61262DC to +0x6126350) ===');
for (let i = 0; i < 0x74; i += 16) {
    const off = 0x61262DC + i;
    const bytes = [];
    for (let j = 0; j < 16; j++) bytes.push(dump[off+j].toString(16).padStart(2,'0'));
    console.log('  +' + off.toString(16) + ': ' + bytes.join(' '));
}

// Find all CALL instructions in the State 3 handler
console.log('\n=== CALLs in State 3 handler ===');
for (let i = 0; i < 0x100; i++) {
    const off = 0x61262DC + i;
    if (dump[off] === 0xE8) {
        const disp = dump.readInt32LE(off + 1);
        const target = off + 5 + disp;
        console.log('  CALL at +0x' + off.toString(16) + ' -> +0x' + target.toString(16));
    }
}

// Check: what does the code at +0x6126334 do? (cert_finalize call)
console.log('\n=== cert_finalize call area (+0x6126330) ===');
for (let i = 0; i < 32; i += 16) {
    const off = 0x6126330 + i;
    const bytes = [];
    for (let j = 0; j < 16; j++) bytes.push(dump[off+j].toString(16).padStart(2,'0'));
    console.log('  +' + off.toString(16) + ': ' + bytes.join(' '));
}

console.log('\nDone.');
