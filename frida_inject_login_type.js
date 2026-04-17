/*
 * FIFA 17 — Login Type Injection v13 (minimal — matches test 11 that worked)
 *
 * Root cause: PreAuth response has no login types → LoginCheck returns 0 → Logout.
 * Fix: Replace LoginCheck (FUN_146e1dae0) to initialize arrays + call LoginSender.
 *
 * Test 11 proved this works (no crash, no freeze, LoginSender returns job handle).
 * Tests 12-13 crashed because additional diagnostic hooks corrupted the call stack.
 * This version strips all non-essential hooks.
 */

"use strict";
const base = Process.getModuleByName("FIFA17.exe").base;
const t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }
function addr(off) { return base.add(off); }

console.log("=== FIFA 17 Login Type Injector v13 (minimal) ===");

// NOP the OSDK screen loader
try {
  Memory.patchCode(addr(0x6e00f40), 4, function(code) {
    var w = new X86Writer(code, { pc: addr(0x6e00f40) });
    w.putRet();
    w.flush();
  });
  console.log(ts() + " Patched OSDK screen -> RET");
} catch(e) {}

let loginTypeInjected = false;

// Replace FUN_146e1dae0 (LoginCheck) — the core fix
try {
  Interceptor.replace(addr(0x6e1dae0), new NativeCallback(function(param_1) {
    if (loginTypeInjected) return ptr(0);
    loginTypeInjected = true;
    
    console.log(ts() + " LoginCheck REPLACED: init arrays + call LoginSender");
    
    try {
      const jobHandle = param_1.add(0x18).readPointer();
      if (jobHandle.isNull()) {
        console.log(ts() + "   jobHandle NULL — abort");
        return ptr(0);
      }
      
      // Initialize arrays (same as FUN_146e1c3f0 does before LoginCheck)
      const resizeFn = new NativeFunction(addr(0x6e192f0), 'void', ['pointer', 'uint32']);
      resizeFn(param_1.add(0x258), 1);
      const initFn = new NativeFunction(addr(0x6f8e7e0), 'void', ['pointer', 'uint32']);
      initFn(param_1.add(0x38), 1);
      param_1.add(0x1a0).writeU16(0);
      param_1.add(0x210).writeU8(param_1.add(0x210).readU8() | 1);
      
      // Build fake login entry
      const entry = Memory.alloc(0x40);
      const flagStr = Memory.allocUtf8String("1");
      entry.writePointer(flagStr);
      entry.add(0x10).writeU32(2);
      const config = entry.add(0x20);
      const authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
      config.add(0x10).writePointer(authToken);
      config.add(0x28).writeU16(0);
      entry.add(0x18).writePointer(config);
      
      // Call LoginSender
      const loginSenderFn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
      const result = loginSenderFn(param_1, entry, config, 1);
      console.log(ts() + " LoginSender returned: " + result);
      
      return ptr(1);
    } catch(e) {
      console.log(ts() + " ERROR: " + e.message);
      return ptr(0);
    }
  }, 'uint64', ['pointer']));
  console.log(ts() + " Replaced LoginCheck OK");
} catch(e) {
  console.log(ts() + " Replace failed: " + e.message);
}

// Minimal RPC monitor — only log component 1 (auth) commands
Interceptor.attach(addr(0x6df0e80), {
  onEnter: function(args) {
    try {
      var comp = this.context.r8.toInt32() & 0xFFFF;
      var cmd = this.context.r9.toInt32() & 0xFFFF;
    } catch(e) { return; }
    if (comp === 1) {
      const names = {0xa:"CreateAccount", 0x28:"Login", 0x32:"SilentLogin", 0x46:"Logout", 0x98:"OriginLogin"};
      console.log(ts() + " AUTH RPC: " + (names[cmd] || "0x"+cmd.toString(16)));
    } else if (comp === 9 && cmd === 7) {
      console.log(ts() + " RPC: PreAuth");
    } else if (comp === 9 && cmd === 8) {
      console.log(ts() + " RPC: PostAuth");
    }
  }
});

// Monitor PreAuth handler
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) { console.log(ts() + " PreAuthHandler(err=" + args[2].toInt32() + ")"); },
  onLeave: function(ret) { console.log(ts() + " PreAuthHandler done"); }
});

// Monitor LoginTypesProcessor
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    console.log(ts() + " LoginTypesProcessor(loginSM=" + args[0] + ")");
    try {
      const parent = args[0].add(0x08).readPointer();
      if (!parent.isNull()) {
        const flag = parent.add(0x53f).readU8();
        console.log(ts() + "   parent+0x53f = " + flag);
        if (flag === 0) { parent.add(0x53f).writeU8(1); console.log(ts() + "   FORCED to 1"); }
      }
    } catch(e) {}
  },
  onLeave: function(ret) { console.log(ts() + " LoginTypesProcessor done"); }
});

// Monitor state transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM_Transition(state=" + args[1].toInt32() + " reason=" + args[2].toInt32() + ")");
  }
});

console.log(ts() + " Ready. Waiting for PreAuth...");
