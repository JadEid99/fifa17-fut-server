/**
 * Search FIFA17.exe on disk for known byte patterns from the SSL code.
 * If found, we can patch the exe directly instead of using Frida.
 * 
 * Run: node find_patch_offset.js
 */
const fs = require('fs');

const exePath = 'D:\\Games\\FIFA 17\\FIFA17.exe';
console.log('Reading ' + exePath + '...');
const exe = fs.readFileSync(exePath);
console.log('Size: ' + exe.length + ' bytes (' + (exe.length/1024/1024).toFixed(1) + ' MB)');

// Known patterns from Frida analysis (runtime code):
const patterns = [
    {
        name: "cert_receive error CALL (E8 3D 6B 00 00)",
        bytes: Buffer.from([0xE8, 0x3D, 0x6B, 0x00, 0x00]),
        context: "at +0x6127C2E in memory"
    },
    {
        name: "State 5 error CALL (E8 1D 83 00 00)",
        bytes: Buffer.from([0xE8, 0x1D, 0x83, 0x00, 0x00]),
        context: "at +0x612644E in memory"
    },
    {
        name: "bAllowAnyCert check (80 BB 20 0C 00 00 00 75)",
        bytes: Buffer.from([0x80, 0xBB, 0x20, 0x0C, 0x00, 0x00, 0x00, 0x75]),
        context: "at +0x6127C22 in memory"
    },
    {
        name: "State 3 cert check (83 BB 8C 00 00 00 03 75 68)",
        bytes: Buffer.from([0x83, 0xBB, 0x8C, 0x00, 0x00, 0x00, 0x03, 0x75, 0x68]),
        context: "at +0x61262DC in memory"
    },
    {
        name: "installed CA cert string",
        bytes: Buffer.from("installed CA cert"),
        context: "at +0x39316B1 in memory"
    },
    {
        name: "DirtySdkHttpProtoImpl::SetCACert",
        bytes: Buffer.from("DirtySdkHttpProtoImpl::SetCACert"),
        context: "at +0x3931690 area in memory"
    }
];

for (const p of patterns) {
    let pos = 0;
    const matches = [];
    while (true) {
        pos = exe.indexOf(p.bytes, pos);
        if (pos === -1) break;
        matches.push(pos);
        pos++;
        if (matches.length >= 5) break;
    }
    
    if (matches.length > 0) {
        console.log(`\nFOUND: ${p.name}`);
        console.log(`  ${matches.length} match(es) at file offsets: ${matches.map(m => '0x' + m.toString(16)).join(', ')}`);
        console.log(`  Memory context: ${p.context}`);
        // Show surrounding bytes
        for (const m of matches.slice(0, 2)) {
            const before = exe.subarray(Math.max(0, m - 8), m);
            const after = exe.subarray(m, Math.min(exe.length, m + p.bytes.length + 8));
            console.log(`  At 0x${m.toString(16)}: ...${Array.from(before).map(b=>b.toString(16).padStart(2,'0')).join(' ')} [${Array.from(after).map(b=>b.toString(16).padStart(2,'0')).join(' ')}]...`);
        }
    } else {
        console.log(`NOT FOUND: ${p.name} (${p.context})`);
    }
}

console.log('\nDone.');
