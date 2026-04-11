/**
 * Frida v9 - Hook send() to catch SSL alert + stack trace.
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */
console.log("[*] FIFA 17 ProtoSSL v9 - trace SSL alert");

var sendAddr = Module.getExportByName("ws2_32.dll", "send");
var connectAddr = Module.getExportByName("ws2_32.dll", "connect");

console.log("[+] send() at " + sendAddr);
console.log("[+] connect() at " + connectAddr);

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
        
        if (this.len >= 7) {
            var b0 = this.buf.readU8();
            if (b0 === 0x15) {
                var bytes = [];
                for (var i = 0; i < Math.min(this.len, 16); i++) {
                    bytes.push(this.buf.add(i).readU8().toString(16).padStart(2, '0'));
                }
                console.log("\n[!] SSL ALERT: " + bytes.join(' '));
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
        }
    }
});

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        var sa = args[1];
        if (sa.readU16() === 2) {
            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." + sa.add(6).readU8() + "." + sa.add(7).readU8();
            console.log("[connect] " + ip + ":" + port);
        }
    }
});

console.log("[*] Ready. Trigger connection now.");
