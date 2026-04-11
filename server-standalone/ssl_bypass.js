/**
 * Frida script to bypass ProtoSSL certificate verification in FIFA 17.
 */

console.log("[*] FIFA 17 SSL Bypass - Frida Script");

var mainModule = Process.findModuleByName("FIFA17.exe");
console.log("[*] Main module: " + mainModule.name + " base=" + mainModule.base + " size=" + mainModule.size);

var memcmpAddr = Module.load("ntdll.dll").getExportByName("memcmp");
console.log("[*] memcmp at: " + memcmpAddr);

var mainBase = mainModule.base;
var mainEnd = mainBase.add(mainModule.size);
var bypassCount = 0;

Interceptor.attach(memcmpAddr, {
    onEnter: function(args) {
        this.shouldBypass = false;
        var size = args[2].toInt32();
        if (size === 16 || size === 20 || size === 32) {
            var retAddr = this.returnAddress;
            if (retAddr.compare(mainBase) >= 0 && retAddr.compare(mainEnd) < 0) {
                this.shouldBypass = true;
                this.size = size;
                this.retAddr = retAddr;
            }
        }
    },
    onLeave: function(retval) {
        if (this.shouldBypass) {
            var origRet = retval.toInt32();
            if (origRet !== 0) {
                retval.replace(0);
                bypassCount++;
                console.log("[+] BYPASS #" + bypassCount + ": memcmp(size=" + this.size + ") " + origRet + "->0 (caller: " + this.retAddr.sub(mainBase) + ")");
            }
        }
    }
});

console.log("[*] Hook installed! Now start the SSL proxy + Node server, then trigger connection in FIFA 17.");
