/**
 * Deep analysis of cert_process (+0x6127020) from the memory dump.
 * Find all CALL instructions, conditional jumps, and return values.
 * Run on Windows: node analyze_cert_process.js
 */
const fs = require('fs');
const dump = fs.readFileSync('D:\\Games\\FIFA 17\\FIFA17_dumped.bin');

const BASE = 0x6127020;
const SIZE = 0x300; // analyze 768 bytes

console.log('=== cert_process analysis (+0x' + BASE.toString(16) + ') ===\n');

// Dump raw bytes
for (let i = 0; i < SIZE; i += 16) {
    const off = BASE + i;
    const bytes = [];
    const ascii = [];
    for (let j = 0; j < 16 && i+j < SIZE; j++) {
        bytes.push(dump[off+j].toString(16).padStart(2, '0'));
        ascii.push(dump[off+j] >= 32 && dump[off+j] < 127 ? String.fromCharCode(dump[off+j]) : '.');
    }
    console.log('+' + off.toString(16) + ': ' + bytes.join(' ') + '  ' + ascii.join(''));
}

// Find all CALL instructions
console.log('\n=== CALL instructions ===');
for (let i = 0; i < SIZE; i++) {
    if (dump[BASE + i] === 0xE8) {
        const disp = dump.readInt32LE(BASE + i + 1);
        const target = BASE + i + 5 + disp;
        console.log('  +' + (BASE+i).toString(16) + ': CALL +' + target.toString(16));
    }
    // Also indirect calls: FF 15 (call [rip+disp])
    if (dump[BASE + i] === 0xFF && dump[BASE + i + 1] === 0x15) {
        const disp = dump.readInt32LE(BASE + i + 2);
        console.log('  +' + (BASE+i).toString(16) + ': CALL [rip+' + disp.toString(16) + '] (indirect)');
    }
}

// Find all conditional jumps (7x xx or 0F 8x xx xx xx xx)
console.log('\n=== Conditional jumps ===');
for (let i = 0; i < SIZE; i++) {
    const b = dump[BASE + i];
    // Short conditional jumps: 70-7F
    if (b >= 0x70 && b <= 0x7F) {
        const offset = dump.readInt8(BASE + i + 1);
        const target = BASE + i + 2 + offset;
        const names = ['JO','JNO','JB','JNB','JE','JNE','JBE','JA','JS','JNS','JP','JNP','JL','JGE','JLE','JG'];
        console.log('  +' + (BASE+i).toString(16) + ': ' + names[b-0x70] + ' +' + target.toString(16));
    }
    // Near conditional jumps: 0F 80-8F
    if (b === 0x0F && dump[BASE+i+1] >= 0x80 && dump[BASE+i+1] <= 0x8F) {
        const disp = dump.readInt32LE(BASE + i + 2);
        const target = BASE + i + 6 + disp;
        const names = ['JO','JNO','JB','JNB','JE','JNE','JBE','JA','JS','JNS','JP','JNP','JL','JGE','JLE','JG'];
        console.log('  +' + (BASE+i).toString(16) + ': ' + names[dump[BASE+i+1]-0x80] + ' +' + target.toString(16) + ' (near)');
    }
}

// Find RET instructions
console.log('\n=== RET instructions ===');
for (let i = 0; i < SIZE; i++) {
    if (dump[BASE + i] === 0xC3) {
        // Check what's before the RET (the return value setup)
        const prev = [];
        for (let j = Math.max(0, i-8); j < i; j++) {
            prev.push(dump[BASE+j].toString(16).padStart(2,'0'));
        }
        console.log('  +' + (BASE+i).toString(16) + ': RET (preceded by: ' + prev.join(' ') + ')');
    }
}

// Find TEST eax, eax patterns (85 C0)
console.log('\n=== TEST eax,eax patterns ===');
for (let i = 0; i < SIZE; i++) {
    if (dump[BASE+i] === 0x85 && dump[BASE+i+1] === 0xC0) {
        const next = dump[BASE+i+2];
        const names = {0x7E:'JLE',0x7F:'JG',0x74:'JE',0x75:'JNE',0x78:'JS',0x79:'JNS'};
        console.log('  +' + (BASE+i).toString(16) + ': TEST eax,eax -> ' + (names[next]||'0x'+next.toString(16)));
    }
}

console.log('\nDone.');
