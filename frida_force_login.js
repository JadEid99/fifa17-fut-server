/*
 * Frida v5: After PreAuth, directly send Login RPC on the same connection.
 * Bypasses the broken login state machine entirely.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 Force Login v5 === Base=' + base);

var preAuthCount = 0;

// Hook PreAuth completion - after it fires, send Login on the same connection
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        preAuthCount++;
        var connMgr = args[0];
        var result = args[1];
        console.log('[PreAuth #' + preAuthCount + '] connMgr=' + connMgr + ' result=' + result);
        
        // Only act on the Q-triggered connection (2nd PreAuth)
        if (preAuthCount < 2) {
            console.log('[PreAuth] Skipping first auto-connect, waiting for Q press...');
            return;
        }
        
        console.log('[PreAuth] >>> Attempting to send Login RPC! <<<');
        
        // The connMgr object has the connection at +0x8 (inner connection manager)
        // FUN_146e18170 sends an RPC: (connMgrInner+0xc08, callback_struct, this, callbackFn, ...)
        // But this is too complex to call directly.
        
        // Simpler approach: find the Blaze connection's send function and send raw Login bytes
        // The connection object is at connMgr+0x10 (the embedded login type object)
        // Actually, let's try calling the login type's "execute" function directly
        
        try {
            // Read the BlazeHub from the handler
            // connMgr is the ConnectionManager. BlazeHub is at connMgr - some offset.
            // Actually, connMgr+0x8 = inner connection (the one that has the RPC system)
            var innerConn = connMgr.add(0x8).readPointer();
            console.log('[Login] innerConn=' + innerConn);
            
            // The inner connection has the RPC dispatch at +0xc08
            // And the connection socket at +0xc50
            var rpcDispatch = innerConn.add(0xc08);
            var connSocket = innerConn.add(0xc50).readPointer();
            console.log('[Login] rpcDispatch=' + rpcDispatch + ' connSocket=' + connSocket);
            
            // Read the connection state
            var connState = innerConn.add(0xb28).readU32();
            console.log('[Login] connState=' + connState);
            
            // Check if connection is still open
            if (connSocket.isNull()) {
                console.log('[Login] Connection socket is NULL - already disconnected');
                return;
            }
            
            // Try to find the ProtoSSL send function
            // FUN_14612e960 is the ProtoSSL send function
            // It takes: (connObj, data, length)
            // But we need to send a properly formatted Blaze packet through the RPC layer
            
            // Let's try a different approach: hook the disconnect function and PREVENT it
            // Then the connection stays open and we can observe what happens
            console.log('[Login] Preventing disconnect by replacing FUN_146db3e40...');
            
        } catch(e) {
            console.log('[Login] Error: ' + e.message);
        }
    }
});

// REPLACE the disconnect function to prevent disconnection after PreAuth
var disconnectCount = 0;
Interceptor.replace(addr(0x6db3e40), new NativeCallback(function(param1) {
    disconnectCount++;
    console.log('[DISCONNECT #' + disconnectCount + '] BLOCKED! param1=' + param1);
    // Don't call the original - just return
    // This keeps the connection open after PreAuth
}, 'void', ['pointer']));
console.log('[HOOK] Disconnect function REPLACED (all disconnects blocked)');

// Hook send_RPC to see if anything tries to send
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) {
        console.log('[send_RPC] >>> cm=' + args[0] + ' cb=' + args[2] + ' fn=' + args[3]);
    }
});

// Hook LOGIN_SENDER
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) {
        console.log('[LOGIN] >>> SENDER CALLED! <<<');
    }
});

// Hook post_PreAuth
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[post_PreAuth] >>> CALLED! <<<');
    }
});

// Hook PreAuth_processor
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[PreAuth_proc] >>> CALLED! <<<');
    }
});

console.log('=== Ready. Trigger connection. ===');
