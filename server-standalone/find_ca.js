const fs = require('fs');
const fd = fs.openSync('C:/Users/Jad/fifa17_dump.dmp', 'r');
const stat = fs.fstatSync(fd);
const chunkSize = 64 * 1024 * 1024;
const overlap = 4000;
console.log('Searching ' + stat.size + ' bytes...');

// Search for ALL DER certificate structures, not just ones with EA strings
// The ProtoSSL CA cert might not have readable ASCII strings
let found = 0;
const certs = [];

for (let off = 0; off < stat.size; off += chunkSize - overlap) {
  const sz = Math.min(chunkSize, stat.size - off);
  const buf = Buffer.alloc(sz);
  fs.readSync(fd, buf, 0, sz, off);
  
  for (let i = 0; i < sz - 10; i++) {
    if (buf[i] === 0x30 && buf[i+1] === 0x82) {
      const outerLen = buf.readUInt16BE(i+2);
      // CA certs are typically 500-1000 bytes
      if (outerLen >= 300 && outerLen <= 900 && i+4 < sz && buf[i+4] === 0x30 && buf[i+5] === 0x82) {
        const innerLen = buf.readUInt16BE(i+6);
        if (innerLen < outerLen && innerLen > 100 && i+8 < sz) {
          // Check for version tag (0xA0 0x03 0x02 0x01 = v3 cert) or serial (0x02)
          if (buf[i+8] === 0xA0 || buf[i+8] === 0x02) {
            const certEnd = i + outerLen + 4;
            if (certEnd <= sz) {
              const cert = buf.subarray(i, certEnd);
              const hex = cert.toString('hex');
              
              // Check for RSA OID (2a 86 48 86 f7 0d 01 01) which all RSA certs have
              if (hex.includes('2a864886f70d0101')) {
                const globalOff = off + i;
                // Deduplicate by first 32 bytes
                const sig = hex.substring(0, 64);
                if (!certs.find(c => c.sig === sig)) {
                  const ascii = cert.toString('ascii').replace(/[^\x20-\x7e]/g, '.');
                  // Extract readable strings
                  const strings = [];
                  let current = '';
                  for (let j = 0; j < cert.length; j++) {
                    const c = cert[j];
                    if (c >= 0x20 && c < 0x7f) current += String.fromCharCode(c);
                    else { if (current.length >= 4) strings.push(current); current = ''; }
                  }
                  if (current.length >= 4) strings.push(current);
                  
                  certs.push({ sig, off: globalOff, len: cert.length, strings: strings.join(' | '), b64: cert.toString('base64') });
                  found++;
                  console.log('#' + found + ' at 0x' + globalOff.toString(16) + ' len=' + cert.length);
                  console.log('  strings: ' + strings.join(' | ').substring(0, 300));
                }
              }
            }
          }
        }
      }
    }
  }
  if (off % (256*1024*1024) === 0) process.stderr.write('Scanned ' + Math.round(off/1024/1024) + 'MB...\r\n');
}
fs.closeSync(fd);
console.log('\nTotal unique certs: ' + found);

// Write all found certs to a file for analysis
fs.writeFileSync('C:/Users/Jad/Desktop/fifa17_all_certs.txt', 
  certs.map((c, i) => '#' + (i+1) + ' offset=0x' + c.off.toString(16) + ' len=' + c.len + '\nstrings: ' + c.strings + '\nbase64: ' + c.b64 + '\n').join('\n---\n')
);
console.log('Saved to fifa17_all_certs.txt');
