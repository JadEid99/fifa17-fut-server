const fs = require('fs');
const fd = fs.openSync('C:/Users/Jad/fifa17_dump.dmp', 'r');
const stat = fs.fstatSync(fd);
const chunkSize = 64 * 1024 * 1024;
const overlap = 2000;
console.log('Searching ' + stat.size + ' bytes for DER certs...');
let found = 0;
for (let off = 0; off < stat.size; off += chunkSize - overlap) {
  const sz = Math.min(chunkSize, stat.size - off);
  const buf = Buffer.alloc(sz);
  fs.readSync(fd, buf, 0, sz, off);
  for (let i = 0; i < sz - 10; i++) {
    if (buf[i] === 0x30 && buf[i+1] === 0x82) {
      const outerLen = buf.readUInt16BE(i+2);
      if (outerLen > 200 && outerLen < 1500 && i+4 < sz && buf[i+4] === 0x30 && buf[i+5] === 0x82) {
        const innerLen = buf.readUInt16BE(i+6);
        if (innerLen < outerLen && innerLen > 100 && i+8 < sz && (buf[i+8] === 0xA0 || buf[i+8] === 0x02)) {
          const certEnd = i + outerLen + 4;
          if (certEnd <= sz) {
            const cert = buf.subarray(i, certEnd);
            const ascii = cert.toString('ascii').replace(/[^\x20-\x7e]/g, '');
            const lc = ascii.toLowerCase();
            if (lc.includes('ea.com') || lc.includes('electronic art') || lc.includes('gosred') || lc.includes('otg') || lc.includes('certificate auth') || lc.includes('online technology') || lc.includes('global online')) {
              console.log('CERT at dump+0x' + (off+i).toString(16) + ' len=' + cert.length);
              console.log('  strings: ' + ascii.substring(0, 300));
              console.log('  b64: ' + cert.toString('base64').substring(0, 120) + '...');
              found++;
              if (found >= 10) { fs.closeSync(fd); process.exit(0); }
            }
          }
        }
      }
    }
  }
  if (off % (256*1024*1024) === 0) process.stderr.write('Scanned ' + Math.round(off/1024/1024) + 'MB...\r\n');
}
fs.closeSync(fd);
console.log('Total: ' + found);
