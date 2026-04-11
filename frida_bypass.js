/**
 * Frida v7 - Patch cert_verify AND cert_process to return 0.
 * Also hook to log when they're called.
 * 
 * Run with server already running:
 *   1. Start server: node server-standalone\server.mjs
 *   2. Launch FIFA 17, wait 20s
 *   3. frida -n FIFA17.exe -l frida_bypass.js
 *   4. Trigger connection in game
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v7");

var base = Process.enumerateModules()[0].base;
var certVerify = base.add(0x6124140);

// Read original bytes first
var origBytes = [];
for (var i = 0; i < 16; i++) origBytes.push(certVerify.add(i).readU8());
console.log("[*] cert_verify at " + certVerify);
console.log("[*] Original: " + origBytes.map(function(b){return b.toString(16).padStart(2,'0')}).join(' '));

// Instead of patching the function start, use Interceptor to hook it
// This is safer - Frida manages the hook properly
try {
    Interceptor.attach(certVerify, {
        onEnter: function(args) {
            console.log("[!] cert_verify called! args: " + args[0] + ", " + args[1] + ", " + args[2]);
        },
        onLeave: function(retval) {
            console.log("[!] cert_verify returning: " + retval + " -> forcing 0");
            retval.replace(ptr(0));
        }
    });
    console.log("[+] Hooked cert_verify - will force return 0");
} catch(e) {
    console.log("[-] Hook failed: " + e.message);
    console.log("[*] Falling back to direct patch...");
    Memory.protect(certVerify, 16, 'rwx');
    certVerify.writeU8(0x31);
    certVerify.add(1).writeU8(0xC0);
    certVerify.add(2).writeU8(0xC3);
    console.log("[+] Direct patch applied");
}

console.log("[*] Ready. Trigger a connection in the game now.");
