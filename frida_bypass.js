console.log("[*] v13 - hook closesocket for stack trace");
var ws2 = Process.getModuleByName("ws2_32.dll");
var sendFn = ws2.getExportByName("send");
var connectFn = ws2.getExportByName("connect");
var closeFn = ws2.getExportByName("closesocket");
var base = Process.getModuleByName("FIFA17.exe").base;

console.log("[+] send=" + sendFn + " connect=" + connectFn + " close=" + closeFn);
console.log("[+] exe base=" + base);

// Track sockets that connect to port 42230
var trackedSockets = {};

Interceptor.attach(connectFn, {
    onEnter: function(args) {
        this.sock = args[0];
        var sa = args[1];
        if (sa.readU16() === 2) {
            var p = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            var ip = sa.add(4).readU8()+"."+sa.add(5).readU8()+"."+sa.add(6).readU8()+"."+sa.add(7).readU8();
            console.log("[connect] " + ip + ":" + p + " sock=" + this.sock);
            if (p === 42230) {
                trackedSockets[this.sock.toString()] = true;
                console.log("[+] Tracking socket " + this.sock + " (port 42230)");
            }
        }
    }
});

Interceptor.attach(closeFn, {
    onEnter: function(args) {
        var sock = args[0];
        if (trackedSockets[sock.toString()]) {
            console.log("\n[!] closesocket() on tracked socket " + sock + " (port 42230)");
            console.log("[!] STACK TRACE:");
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            for (var i = 0; i < bt.length; i++) {
                var addr = bt[i];
                var offset = addr.sub(base);
                console.log("  " + addr + " (exe+" + offset + ")");
            }
            delete trackedSockets[sock.toString()];
        }
    }
});

// Also hook send to catch any SSL alerts
Interceptor.attach(sendFn, {
    onEnter: function(args) {
        var buf = args[1];
        var len = args[2].toInt32();
        if (len >= 5 && buf.readU8() === 0x15) {
            var hex = "";
            for (var i = 0; i < Math.min(len, 16); i++)
                hex += ("0" + buf.add(i).readU8().toString(16)).slice(-2) + " ";
            console.log("\n[!] SSL ALERT: " + hex);
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            for (var i = 0; i < bt.length; i++)
                console.log("  " + bt[i] + " (exe+" + bt[i].sub(base) + ")");
        }
    }
});

console.log("[*] Ready. Trigger connection.");
