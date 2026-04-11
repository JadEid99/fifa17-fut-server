/**
 * Search the dumped exe for SSL code patterns.
 * If found, we can create a patched version.
 * Run: node search_dump.js
 */
const fs = require('fs');

const dumpPath = 'D:\\Games\\FIFA 17\\FIFA17_dumped.bin';
console.log('Reading dump...');
const dump = fs.readFileSync(dumpPath);
console.log('Size: ' + dump.length + ' bytes (' + (dump.length/1024/1024).toFixed(1) + ' MB)');

const patterns = [
    { name: "cert_receive error CALL", bytes: Buffer.from([0xE8, 0x3D, 0x6B, 0x00, 0x00]), patchTo: Buffer.from([0x90,0x90,0x90,0x90,0x90]) },
    { name: "State 5 error CALL", bytes: Buffer.from([0xE8, 0x1D, 0x83, 0x00, 0x00]), patchTo: Buffer.from([0x90,0x90,0x90,0x90,0x90]) },
    { name: "bAllowAnyCert CMP+JNE", bytes: Buffer.from([0x80, 0xBB, 0x20, 0x0C, 0x00, 0x00, 0x00, 0x75, 0x18]), patchTo: null },
    { name: "State 3 cert check", bytes: Buffer.from([0x83, 0xBB, 0x8C, 0x00, 0x00, 0x00, 0x03, 0x75, 0x68]), patchTo: null },
    { name: "installed CA cert", bytes: Buffer.from("installed CA cert"), patchTo: null },
    { name: "SetCACert string", bytes: Buffer.from("DirtySdkHttpProtoImpl::SetCACert"), patchTo: null },
    { name: "cert_process prologue", bytes: Buffer.from([0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCB, 0xBF]), patchTo: null },
];

for (const p of patterns) {
    let pos = 0;
    const matches = [];
    while (matches.length < 10) {
        pos = dump.indexOf(p.bytes, pos);
        if (pos === -1) break;
        matches.push(pos);
        pos++;
    }
    
    if (matches.length > 0) {
        console.log(`\nFOUND: ${p.name} (${matches.length} match${matches.length>1?'es':''})`);
        for (const m of matches.slice(0, 3)) {
            console.log(`  Offset 0x${m.toString(16)} (memory: exe+0x${m.toString(16)})`);
        }
    } else {
        console.log(`NOT FOUND: ${p.name}`);
    }
}

console.log('\nDone.');
