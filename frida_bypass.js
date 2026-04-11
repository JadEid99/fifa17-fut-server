console.log("[*] v12");
var ws2 = Process.getModuleByName("ws2_32.dll");
var sendFn = ws2.getExportByName("send");
var connectFn = ws2.getExportByName("connect");
console.log("[+] send=" + sendFn + " connect=" + connectFn);

Interceptor.attach(sendFn, {
    onEnter: function(args) {
        var buf = args[1];
        var len = args[2].toInt32();
        if (len >= 7 && buf.readU8() === 0x15) {
            var hex = "";
            for (var i = 0; i < Math.min(len, 16); i++)
                hex += ("0" + buf.add(i).readU8().toString(16)).slice(-2) + " ";
            console.log("\n[!] SSL ALERT: " + hex);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        }
    }
});

Interceptor.attach(connectFn, {
    onEnter: function(args) {
        var sa = args[1];
        if (sa.readU16() === 2) {
            var p = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            console.log("[connect] " + sa.add(4).readU8()+"."+sa.add(5).readU8()+"."+sa.add(6).readU8()+"."+sa.add(7).readU8()+":"+p);
        }
    }
});
console.log("[*] Ready.");
