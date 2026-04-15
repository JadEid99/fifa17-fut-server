/*
 * Frida v44: Dump the PreAuth response object after decoding to see
 * which fields are populated and which are empty.
 * Focus on offset +0xb8 (login type list) and nearby fields.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v44: PreAuth Response Object Dump ===');

// Hook the PreAuth handler to dump param_2 (decoded response)
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) {
        var param1 = args[0];
        var param2 = args[1]; // decoded PreAuth response
        var param3 = args[2];
        
        console.log('[PA-HANDLER] param1=' + param1 + ' param2=' + param2 + ' param3=' + param3);
        
        // Dump the decoded PreAuth response object
        // Focus on the fields the handler reads
        try {
            console.log('[PA-RESP] PreAuth response object dump:');
            for (var off = 0; off < 0x250; off += 8) {
                var val = param2.add(off).readPointer();
                if (!val.isNull() && !val.equals(ptr(0))) {
                    var label = '';
                    if (off === 0x00) label = ' (vtable)';
                    if (off === 0x10) label = ' (INST string?)';
                    if (off === 0x28) label = ' (NASP string?)';
                    if (off === 0x40) label = ' (PLAT string?)';
                    if (off === 0x58) label = ' (RSRC string?)';
                    if (off === 0x70) label = ' (QOSS struct?)';
                    if (off === 0xb8) label = ' *** LOGIN TYPE LIST ***';
                    if (off === 0x120) label = ' (param_2+0x120 passed to FUN_146e1c3f0)';
                    if (off === 0x1f0) label = ' (SVER string?)';
                    if (off === 0x1d8) label = ' (PTVR string?)';
                    if (off === 0x1c0) label = ' (PTAG string?)';
                    if (off === 0x220) label = ' (ANON?)';
                    if (off === 0x240) label = ' (used by FUN_146124610)';
                    
                    // Try to read as string
                    var str = '';
                    try {
                        var s = val.readUtf8String(30);
                        if (s && s.length > 1 && s.length < 30 && /^[\x20-\x7e]+$/.test(s)) {
                            str = ' "' + s + '"';
                        }
                    } catch(e) {}
                    
                    console.log('  +0x' + off.toString(16) + ' = ' + val + label + str);
                }
            }
            
            // Specifically dump the +0xb8 area (login type list)
            console.log('[PA-RESP] Login type list area (+0xb8):');
            var listObj = param2.add(0xb8);
            for (var off = 0; off < 0x40; off += 8) {
                var val = listObj.add(off).readPointer();
                console.log('  +0xb8+0x' + off.toString(16) + ' = ' + val);
            }
            
            // Dump +0x120 area (passed to FUN_146e1c3f0 as param_2)
            console.log('[PA-RESP] +0x120 area (login config):');
            var configObj = param2.add(0x120);
            for (var off = 0; off < 0x40; off += 8) {
                var val = configObj.add(off).readPointer();
                console.log('  +0x120+0x' + off.toString(16) + ' = ' + val);
            }
            
        } catch(e) {
            console.log('[PA-RESP] Error: ' + e);
        }
    }
});

console.log('=== Frida v44 Ready ===');
