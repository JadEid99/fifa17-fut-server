console.log("[*] v21 - make cert_process return 1 (success)");
var base = Process.getModuleByName("FIFA17.exe").base;

// cert_process at +0x6127020 is called from State 3.
// If it returns > 0, the cert is accepted and state advances to 4.
// If it returns <= 0, the cert is rejected.
// Patch it to: mov eax, 1; ret (B8 01 00 00 00 C3)

var addr = base.add(0x6127020);
var orig = [];
for (var i = 0; i < 6; i++) orig.push(addr.add(i).readU8());
console.log("[*] cert_process original: " + orig.map(function(b){return ("0"+b.toString(16)).slice(-2)}).join(" "));

Memory.protect(addr, 6, 'rwx');
addr.writeByteArray([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax, 1; ret
console.log("[+] Patched cert_process to return 1!");
console.log("[*] Trigger connection now.");
