// Quick test: make +0x6138680 return 0 (this is called from cert_process)
// This might be the RSA signature verification function
console.log("[*] Patching +0x6138680 to return 0");
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x6138680);
var orig = [];
for (var i = 0; i < 6; i++) orig.push(a.add(i).readU8());
console.log("[*] Original: " + orig.map(function(x){return ("0"+x.toString(16)).slice(-2)}).join(" "));
Memory.protect(a, 6, 'rwx');
a.writeByteArray([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]); // mov eax, 0; ret
console.log("[+] Patched!");
