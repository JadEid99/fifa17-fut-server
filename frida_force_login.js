/*
 * Frida v21: Check if CreateAccount TDF body is now parsed with byte13=0x00
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v21 ===');

Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[CA] param3=0x' + (p3>>>0).toString(16) + (p3===0?' SUCCESS':' ERROR'));
        if (p3 === 0 && !p2.isNull()) {
            console.log('[CA] +0x10 userId=' + p2.add(0x10).readU32());
            console.log('[CA] +0x13 byte=' + p2.add(0x13).readU8());
            try {
                var pnam = p2.add(0x18).readPointer();
                console.log('[CA] +0x18 pnam_ptr=' + pnam);
                if (!pnam.isNull() && pnam.toInt32() > 0x1000) {
                    console.log('[CA] pnam="' + pnam.readUtf8String(32) + '"');
                }
            } catch(e) {}
        }
    }
});

console.log('=== Ready ===');
