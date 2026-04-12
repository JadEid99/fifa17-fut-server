/**
 * Extract the SSL code region from the dump for analysis.
 * This creates a smaller file with just the ProtoSSL functions.
 * Run: node extract_ssl_code.js
 */
const fs = require('fs');
const dump = fs.readFileSync('D:\\Games\\FIFA 17\\FIFA17_dumped.bin');

// Extract the SSL state machine + cert functions region
// From +0x6120000 to +0x6140000 (128KB)
const sslStart = 0x6120000;
const sslEnd = 0x6140000;
const sslCode = dump.subarray(sslStart, sslEnd);
fs.writeFileSync('D:\\Games\\FIFA 17\\ssl_code_region.bin', sslCode);
console.log('Extracted SSL code: ' + sslCode.length + ' bytes');
console.log('  From +0x' + sslStart.toString(16) + ' to +0x' + sslEnd.toString(16));

// Also extract as hex dump for text analysis
let hexDump = '';
// Focus on the key functions:
const regions = [
    { name: 'cert_process', start: 0x6127020, size: 0x200 },
    { name: 'cert_receive', start: 0x6127B40, size: 0x100 },
    { name: 'cert_finalize', start: 0x61279F0, size: 0x100 },
    { name: 'state3_handler', start: 0x61262DC, size: 0x100 },
    { name: 'state5_handler', start: 0x6126416, size: 0x80 },
    { name: 'cert_parser_6138680', start: 0x6138680, size: 0x200 },
    { name: 'fn_612E810', start: 0x612E810, size: 0x100 },
    { name: 'fn_612E770_error', start: 0x612E770, size: 0x80 },
    { name: 'fn_6123EA0', start: 0x6123EA0, size: 0x100 },
    { name: 'fn_612BB40', start: 0x612BB40, size: 0x100 },
];

for (const r of regions) {
    hexDump += `\n=== ${r.name} (+0x${r.start.toString(16)}) ===\n`;
    for (let i = 0; i < r.size; i += 16) {
        const off = r.start + i;
        const bytes = [];
        for (let j = 0; j < 16 && i+j < r.size; j++) {
            bytes.push(dump[off+j].toString(16).padStart(2, '0'));
        }
        hexDump += `+${off.toString(16)}: ${bytes.join(' ')}\n`;
    }
}

fs.writeFileSync('C:\\Users\\Jad\\fifa17-fut-server\\ssl_hex_dump.txt', hexDump);
console.log('Hex dump written to ssl_hex_dump.txt');
console.log('Push this file to git so it can be analyzed');
