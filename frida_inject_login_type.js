/*
 * FIFA 17 — Login Type Injection v20
 *
 * Back to Approach B (replace LoginCheck, call LoginSender) but with
 * transport type = 1 instead of 0. The transport type at config+0x28
 * determines how the Login RPC is dispatched. Type 0 may mean "none".
 *
 * Also: no array init (crashes intermittently). Just call LoginSender.
 * If it crashes, retry on next call.
 */

"use strict";
var base = Process.getModuleByName("FIFA17.exe").base;
var t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }
function addr(off) { return base.add(off); }

console.log("=== FIFA 17 v20: LoginSender with transport=1 ===");

// NOP OSDK screen
try {
  Memory.patchCode(addr(0x6e00f40), 4, function(code) {
    var w = new X86Writer(code, { pc: addr(0x6e00f40) });
    w.putRet();
    w.flush();
  });
} catch(e) {}

// Ignore system exceptions (Denuvo)
Process.setExceptionHandler(function(details) {
  if (details.address.toString().indexOf("7ffd") === 2) return false;
  console.log(ts() + " !!! CRASH: " + details.type + " at " + details.address);
  return false;
});

var injected = false;

// Replace LoginCheck
try {
  Interceptor.replace(addr(0x6e1dae0), new NativeCallback(function(param_1) {
    if (injected) return ptr(0);
    injected = true;

    console.log(ts() + " LoginCheck: calling LoginSender (transport=1)");

    try {
      var jobHandle = param_1.add(0x18).readPointer();
      if (jobHandle.isNull()) { console.log(ts() + "   job NULL"); injected = false; return ptr(0); }
      console.log(ts() + "   job=" + jobHandle);

      // Block DLL race
      param_1.add(0x218).writePointer(ptr(1));
      param_1.add(0x220).writePointer(ptr(1));

      var entry = Memory.alloc(0x40);
      var flagStr = Memory.allocUtf8String("1");
      entry.writePointer(flagStr);
      entry.add(0x10).writeU32(2);
      var config = entry.add(0x20);
      var authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
      config.add(0x10).writePointer(authToken);
      config.add(0x28).writeU16(1);  // transport type 1 (was 0 in previous tests)
      entry.add(0x18).writePointer(config);

      var fn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
      var result = fn(param_1, entry, config, 1);
      console.log(ts() + "   LoginSender returned " + result);
      return ptr(1);
    } catch(e) {
      console.log(ts() + "   ERR: " + e);
      injected = false;
      return ptr(0);
    }
  }, 'uint64', ['pointer']));
  console.log(ts() + " Replaced LoginCheck OK");
} catch(e) {
  console.log(ts() + " Replace FAILED: " + e);
}

// Monitor auth RPCs
Interceptor.attach(addr(0x6df0e80), {
  onEnter: function(args) {
    try {
      var comp = this.context.r8.toInt32() & 0xFFFF;
      var cmd = this.context.r9.toInt32() & 0xFFFF;
    } catch(e) { return; }
    if (comp === 1) {
      var names = {0xa:"CreateAccount", 0x28:"Login", 0x32:"SilentLogin",
                   0x46:"Logout", 0x98:"OriginLogin"};
      var name = names[cmd] || "0x"+cmd.toString(16);
      if (cmd === 0x28 || cmd === 0x32 || cmd === 0x98) {
        console.log(ts() + " 🚀🚀🚀 " + name + " ON WIRE! 🚀🚀🚀");
      } else {
        console.log(ts() + " AUTH: " + name);
      }
    } else if (comp === 9 && cmd === 7) {
      console.log(ts() + " PreAuth");
    } else if (comp === 9 && cmd === 8) {
      console.log(ts() + " PostAuth");
    }
  }
});

// Monitor PreAuth + LoginTypesProcessor
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) { console.log(ts() + " PreAuthHandler(err=" + args[2].toInt32() + ")"); },
  onLeave: function(ret) { console.log(ts() + " PreAuthHandler done"); }
});
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    console.log(ts() + " LoginTypesProcessor");
    try {
      var p = args[0].add(0x08).readPointer();
      if (!p.isNull() && p.add(0x53f).readU8() === 0) {
        p.add(0x53f).writeU8(1);
        console.log(ts() + "   forced +0x53f=1");
      }
    } catch(e) {}
  },
  onLeave: function(ret) { console.log(ts() + " LoginTypesProcessor done"); }
});

// State transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM(" + args[1].toInt32() + "," + args[2].toInt32() + ")");
  }
});

console.log(ts() + " Ready.");
