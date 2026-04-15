/*
 * Frida v36: Trace web view URL loading and Nucleus HTTP requests.
 * The OSDK screen should load a web page from nucleusConnect URL.
 * We need to see what URLs the game tries to load.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v36: Web View + HTTP Trace ===');

// Hook the LoadURL function at 0x1472d5cf0 (referenced by s_LoadURL)
try {
    Interceptor.attach(addr(0x72d5cf0), {
        onEnter: function(args) {
            console.log('[LOAD-URL] FUN_1472d5cf0 called!');
            // Try to read string args
            for (var i = 0; i < 4; i++) {
                try {
                    var s = args[i].readUtf8String(200);
                    if (s && s.length > 3 && s.length < 200) {
                        console.log('[LOAD-URL]   arg' + i + ' = "' + s + '"');
                    }
                } catch(e) {}
                try {
                    var p = args[i].readPointer();
                    var s2 = p.readUtf8String(200);
                    if (s2 && s2.length > 3 && s2.length < 200) {
                        console.log('[LOAD-URL]   arg' + i + ' -> "' + s2 + '"');
                    }
                } catch(e) {}
            }
        }
    });
    console.log('Hooked LoadURL at 0x1472d5cf0');
} catch(e) {
    console.log('Could not hook LoadURL: ' + e);
}

// Hook FUN_147572550 (NetResourceAdaptor LoadURL wrapper)
try {
    Interceptor.attach(addr(0x7572550), {
        onEnter: function(args) {
            console.log('[NET-LOAD] FUN_147572550 called!');
            for (var i = 0; i < 6; i++) {
                try {
                    var s = args[i].readUtf8String(200);
                    if (s && s.length > 3 && s.length < 200) {
                        console.log('[NET-LOAD]   arg' + i + ' = "' + s + '"');
                    }
                } catch(e) {}
            }
        }
    });
    console.log('Hooked NetResourceAdaptor at 0x147572550');
} catch(e) {
    console.log('Could not hook NetResourceAdaptor: ' + e);
}

// Hook the nucleusConnect config reader at 0x147237850
// This function reads the nucleusConnect URL from the config
try {
    Interceptor.attach(addr(0x7237850), {
        onEnter: function(args) {
            console.log('[NUCLEUS-URL] FUN_147237850 called (nucleusConnect reader)');
        },
        onLeave: function(retval) {
            try {
                if (!retval.isNull()) {
                    var url = retval.readUtf8String(200);
                    console.log('[NUCLEUS-URL] Returned: "' + url + '"');
                } else {
                    console.log('[NUCLEUS-URL] Returned NULL');
                }
            } catch(e) {
                console.log('[NUCLEUS-URL] Return value: ' + retval);
            }
        }
    });
    console.log('Hooked nucleusConnect reader at 0x147237850');
} catch(e) {
    console.log('Could not hook nucleusConnect reader: ' + e);
}

// Hook FUN_146e00f40 — called during persona creation path
try {
    Interceptor.attach(addr(0x6e00f40), {
        onEnter: function(args) {
            console.log('[PERSONA-CREATE] FUN_146e00f40 called! param1=' + args[0] + ' param2=' + args[1] + ' param3=' + args[2]);
        }
    });
    console.log('Hooked FUN_146e00f40 (persona creation)');
} catch(e) {}

// Hook FUN_146e00d50 — called by FUN_146e00f40
try {
    Interceptor.attach(addr(0x6e00d50), {
        onEnter: function(args) {
            console.log('[PERSONA-D50] FUN_146e00d50 called! param1=' + args[0] + ' param2=' + args[1]);
        }
    });
} catch(e) {}

// Hook the TOS response handlers to see if they fire
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PA-HANDLER] PreAuth handler called R8=' + args[2]);
        }
    });
} catch(e) {}

try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[CA-HANDLER] CreateAccount handler called R8=' + args[2]);
        }
    });
} catch(e) {}

// Monitor all WinHTTP/WinInet calls for HTTP requests
try {
    var winhttp = Module.findExportByName('winhttp.dll', 'WinHttpOpenRequest');
    if (winhttp) {
        Interceptor.attach(winhttp, {
            onEnter: function(args) {
                try {
                    var verb = args[1].readUtf16String();
                    var path = args[2].readUtf16String();
                    console.log('[WINHTTP] OpenRequest: ' + verb + ' ' + path);
                } catch(e) {}
            }
        });
        console.log('Hooked WinHttpOpenRequest');
    }
} catch(e) {}

try {
    var winhttp2 = Module.findExportByName('winhttp.dll', 'WinHttpConnect');
    if (winhttp2) {
        Interceptor.attach(winhttp2, {
            onEnter: function(args) {
                try {
                    var server = args[1].readUtf16String();
                    var port = args[2].toInt32();
                    console.log('[WINHTTP] Connect: ' + server + ':' + port);
                } catch(e) {}
            }
        });
        console.log('Hooked WinHttpConnect');
    }
} catch(e) {}

// Also hook Winsock connect to catch any TCP connections
try {
    var wsConnect = Module.findExportByName('ws2_32.dll', 'connect');
    if (wsConnect) {
        Interceptor.attach(wsConnect, {
            onEnter: function(args) {
                try {
                    var addr_struct = args[1];
                    var family = addr_struct.readU16();
                    if (family === 2) { // AF_INET
                        var port = (addr_struct.add(2).readU8() << 8) | addr_struct.add(3).readU8();
                        var ip = addr_struct.add(4).readU8() + '.' + addr_struct.add(5).readU8() + '.' + addr_struct.add(6).readU8() + '.' + addr_struct.add(7).readU8();
                        console.log('[CONNECT] TCP connect to ' + ip + ':' + port);
                    }
                } catch(e) {}
            }
        });
        console.log('Hooked ws2_32.connect');
    }
} catch(e) {}

console.log('=== Frida v36 Ready ===');
console.log('Watching for: LoadURL, WinHTTP, TCP connect, nucleusConnect, persona creation');
