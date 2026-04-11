/**
 * Search ALL game files for the EA CA certificate.
 * 
 * The EA CA cert is a DER-encoded X.509 certificate that:
 * - Starts with 0x30 0x82 (DER SEQUENCE)
 * - Contains "Online Technology Group" 
 * - Contains "OTG3 Certificate Authority"
 * - Contains "Electronic Arts"
 * - Is approximately 764 bytes (from our memory analysis)
 * 
 * We also search for the raw string "OTG3 Certificate Authority" 
 * which might appear in config files or data files.
 * 
 * Run: node find_ca_on_disk.js
 */
const fs = require('fs');
const path = require('path');

const gameDir = 'D:\\Games\\FIFA 17';
const otgBytes = Buffer.from('Online Technology Group');
const otg3Bytes = Buffer.from('OTG3 Certificate Authority');
const eaBytes = Buffer.from('Electronic Arts');

let totalFiles = 0;
let totalMatches = 0;

function searchFile(filePath) {
    try {
        const stat = fs.statSync(filePath);
        if (stat.size > 2 * 1024 * 1024 * 1024) return; // skip > 2GB
        if (stat.size < 100) return;
        totalFiles++;
        
        const data = fs.readFileSync(filePath);
        const relPath = path.relative(gameDir, filePath);
        
        // Search for "Online Technology Group"
        let pos = 0;
        while (true) {
            pos = data.indexOf(otgBytes, pos);
            if (pos === -1) break;
            totalMatches++;
            
            // Look backwards for DER cert start (0x30 0x82)
            let certStart = -1;
            let certLen = 0;
            for (let back = 4; back < 300 && pos >= back; back++) {
                if (data[pos - back] === 0x30 && data[pos - back + 1] === 0x82) {
                    const len = (data[pos - back + 2] << 8) | data[pos - back + 3];
                    if (len >= 200 && len <= 2000) {
                        certStart = pos - back;
                        certLen = len + 4;
                        break;
                    }
                }
            }
            
            // Check for CA:TRUE nearby
            const regionStart = Math.max(0, pos - 500);
            const regionEnd = Math.min(data.length, pos + 500);
            const region = data.subarray(regionStart, regionEnd);
            const hasCaTrue = region.indexOf(Buffer.from([0x30, 0x03, 0x01, 0x01, 0xFF])) !== -1;
            const hasOTG3 = region.indexOf(otg3Bytes) !== -1;
            
            console.log(`[OTG] ${relPath} offset=0x${pos.toString(16)} DER=${certStart >= 0 ? '0x' + certStart.toString(16) + ' (' + certLen + 'b)' : 'none'} CA:TRUE=${hasCaTrue} OTG3=${hasOTG3}`);
            
            // If we found a DER cert, dump its first 32 bytes
            if (certStart >= 0) {
                const header = data.subarray(certStart, certStart + Math.min(32, certLen));
                console.log(`  Header: ${Array.from(header).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
            }
            
            pos++;
        }
        
        // Also search for "OTG3 Certificate Authority" separately
        pos = 0;
        while (true) {
            pos = data.indexOf(otg3Bytes, pos);
            if (pos === -1) break;
            // Only log if not already found via OTG search
            const nearbyOTG = data.indexOf(otgBytes, Math.max(0, pos - 200));
            if (nearbyOTG === -1 || nearbyOTG > pos + 200) {
                console.log(`[OTG3] ${relPath} offset=0x${pos.toString(16)} (standalone)`);
            }
            pos++;
        }
    } catch (e) {
        // skip
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

console.log(`Searching for EA CA cert in ${gameDir}...`);
console.log('This may take a while for large game directories.\n');
walkDir(gameDir);
console.log(`\nDone. Scanned ${totalFiles} files, found ${totalMatches} OTG matches.`);
