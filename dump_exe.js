// Dump the decrypted FIFA17.exe from memory to disk.
// This creates a file with all code sections decrypted by Denuvo.
// Run: frida -n FIFA17.exe -l dump_exe.js
// Output: D:\Games\FIFA 17\FIFA17_dumped.bin

console.log("[*] FIFA 17 Memory Dumper");

var mod = Process.getModuleByName("FIFA17.exe");
console.log("[*] Module: " + mod.name);
console.log("[*] Base: " + mod.base);
console.log("[*] Size: " + mod.size + " (" + (mod.size/1024/1024).toFixed(1) + " MB)");

var outPath = "D:\\Games\\FIFA 17\\FIFA17_dumped.bin";

// Dump in 1MB chunks to avoid memory issues
var chunkSize = 1024 * 1024;
var totalChunks = Math.ceil(mod.size / chunkSize);

console.log("[*] Dumping " + totalChunks + " chunks to " + outPath);

// Open file for writing
var f = new File(outPath, "wb");

for (var i = 0; i < totalChunks; i++) {
    var offset = i * chunkSize;
    var size = Math.min(chunkSize, mod.size - offset);
    
    try {
        var data = mod.base.add(offset).readByteArray(size);
        f.write(data);
    } catch(e) {
        // If a page is not readable, write zeros
        console.log("[!] Chunk " + i + " at offset 0x" + offset.toString(16) + " not readable, writing zeros");
        var zeros = new ArrayBuffer(size);
        f.write(zeros);
    }
    
    if (i % 50 === 0) {
        console.log("[*] Progress: " + i + "/" + totalChunks + " (" + Math.round(i/totalChunks*100) + "%)");
    }
}

f.close();
console.log("[+] Done! Dumped to " + outPath);
console.log("[+] Size: " + mod.size + " bytes");
console.log("[*] You can now analyze this in Ghidra or x64dbg");
console.log("[*] Load at base address " + mod.base);
