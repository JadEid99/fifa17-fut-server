/*
 * Frida script to trace FIFA 17 login flow.
 * Hooks 16 key functions with CORRECT offsets (base 0x140000000).
 * Run via: frida -p <PID> -l frida_login_trace.js
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
function hk(off, name, onE, onL) {
    try {
        Interceptor.attach(addr(off), {
            onEnter: onE || function(a) { console.log('[>] ' + name); },
            onLeave: onL || function(r) { console.log('[<] ' + name + ' -> ' + r); }
        });
        console.log('[OK] ' + name + ' @ ' + addr(off));
    } catch(e) { console.log('[!!] ' + name + ': ' + e.message); }
}
console.log('=== FIFA 17 Login Tracer === Base=' + base);

hk(0x71a5da0, 'SDK_gate');
hk(0x71995b0, 'get_SDK_mgr', null, function(r) { console.log('[<] get_SDK_mgr -> ' + r + (r.isNull()?' NULL!':'')); });
hk(0x6e19a00, 'PreAuth_complete', function(a) { console.log('[>] PreAuth_complete p1=' + a[0] + ' p2=' + a[1] + ' p3=' + a[2]); });
hk(0x6db3e40, 'DISCONNECT', function(a) { console.log('[>] DISCONNECT p1=' + a[0]); });
hk(0x6db6af0, 'LoginSM_setup', function(a) { console.log('[>] LoginSM_setup p1=' + a[0]); }, function(r) { console.log('[<] LoginSM_setup -> ' + r + (r.isNull()?' FAILED!':'')); });
hk(0x6e19680, 'ConnMgr_create', null, function(r) { console.log('[<] ConnMgr_create -> ' + r + (r.isNull()?' NULL!':'')); });
hk(0x6e18170, 'send_RPC', function(a) { console.log('[>] send_RPC cm=' + a[0] + ' cb=' + a[2] + ' fn=' + a[3]); });
hk(0x6e1e460, 'post_PreAuth', function(a) { console.log('[>] post_PreAuth p1=' + a[0]); });
hk(0x6e1c3f0, 'PreAuth_processor', function(a) { console.log('[>] PreAuth_processor p1=' + a[0] + ' p2=' + a[1]); });
hk(0x6f2a270, 'LOGIN_SENDER', function(a) { console.log('[>] *** LOGIN_SENDER *** p1=' + a[0]); });
hk(0x6da9570, 'schedule_cb', function(a) { console.log('[>] schedule_cb obj=' + a[0] + ' cb=' + a[1] + ' p=' + a[2]); });
hk(0x6dad43c, 'cb_dispatch', function(a) {
    console.log('[>] cb_dispatch p1=' + a[0]);
    try { var v=a[0].readPointer(); var f=v.add(0x10).readPointer(); console.log('    vt=' + v + ' fn=' + f); } catch(e) {}
});
hk(0x6e156a0, 'login_type_check');
hk(0x6f199c0, 'auth_token_proc', function(a) { console.log('[>] auth_token_proc p1=' + a[0]); });
hk(0x70db3c0, 'AuthCodeSync', function(a) { console.log('[>] AuthCodeSync p1=' + a[0] + ' p2=' + a[1]); }, function(r) { console.log('[<] AuthCodeSync -> ' + r); });
hk(0x6124a40, 'DirtySDK_status', function(a) {
    var t=a[0].toInt32(); var s=String.fromCharCode((t>>24)&0xFF,(t>>16)&0xFF,(t>>8)&0xFF,t&0xFF);
    console.log('[>] DirtySDK "' + s + '" (0x' + t.toString(16) + ')');
}, function(r) { console.log('[<] DirtySDK -> ' + r); });

// 17. FUN_146db7490 - BlazeHub callback handler (called after PreAuth)
hk(0x6db7490, 'BlazeHub_handler', function(a) {
    console.log('[>] BlazeHub_handler p1=' + a[0] + ' p2=' + a[1]);
    // Dump the first 64 bytes of this function to understand what it does
    try {
        var funcBytes = addr(0x6db7490).readByteArray(64);
        console.log('[>] BlazeHub_handler bytes: ' + Array.from(new Uint8Array(funcBytes)).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' '));
    } catch(e) {}
    // Also read the object state
    try {
        var obj = a[0];
        // Read key offsets on the BlazeHub object
        var off750 = obj.add(0x750).readPointer();
        var off788 = obj.add(0x788).readPointer();
        var off53f = obj.add(0x53f).readU8();
        console.log('[>] BlazeHub state: +0x750=' + off750 + ' +0x788=' + off788 + ' +0x53f=' + off53f);
    } catch(e) { console.log('[>] BlazeHub state read error: ' + e.message); }
}, function(r) { console.log('[<] BlazeHub_handler -> ' + r); });

// 18. The parent function that contains the PreAuth response processing
// This is the function with param_3==0 (PreAuth) vs param_3!=0 (Login) paths
hk(0x6e1c5e0, 'PreAuth_response_handler', function(a) {
    console.log('[>] PreAuth_response_handler p1=' + a[0] + ' p2=' + a[1] + ' p3=' + a[2]);
});

console.log('=== Hooks ready. Trigger connection now. ===');
