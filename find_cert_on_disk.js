// Search for the EA CA cert in all game files
// Run on the Windows PC: node find_cert_on_disk.js
const fs = require('fs');
const path = require('path');

const gameDir = 'D:\\Games\\FIFA 17';
// Search for "Online Technology Group" which is in the EA CA cert
const searchBytes = Buffer.from('Online Technology Group');
// Also search for the DER cert header pattern with CA:TRUE
const caTrue = Buffer.from([0x30, 0x03, 0x01, 0x01, 0xFF]);

function searchFile(filePath) {
    try {
        const stat = fs.statSync(filePath);
        if (stat.size > 500 * 1024 * 1024) return; // skip files > 500MB
        if (stat.size < 100) return;
        
        const data = fs.readFileSync(filePath);
        let pos = 0;
        while (true) {
            pos = data.indexOf(searchBytes, pos);
            if (pos === -1) break;
            // Check if there's a cert structure nearby
            const start = Math.max(0, pos - 500);
            const region = data.subarray(start, pos + 500);
            const hasCaTrue = region.indexOf(caTrue) !== -1;
            console.log(`FOUND in ${filePath} at offset 0x${pos.toString(16)} (CA:TRUE nearby: ${hasCaTrue})`);
            pos++;
        }
    } catch (e) {
        // skip unreadable files
    }
}

function walkDir(dir) {
    try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walkDir(fullPath);
            } else {
                searchFile(fullPath);
            }
        }
    } catch (e) {}
}

console.log('Searching for EA CA cert in game files...');
walkDir(gameDir);
console.log('Done.');
