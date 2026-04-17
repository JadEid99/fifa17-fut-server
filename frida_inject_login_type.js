/*
 * FIFA 17 — Login Type Injection v19
 *
 * NEW APPROACH: Instead of bypassing CreateAccount and trying to call
 * LoginSender directly (which queues but never dispatches), let the
 * natural CreateAccount flow happen and fix the broken TDF decoder
 * by writing the correct response values directly.
 *
 * The CreateAccount handler (FUN_146e151d0) reads resp[0x10..0x13].
 * The TDF decoder never populates these (confirmed). We write them
 * in the handler's onEnter so the handler sees:
 *   resp[0x10] = 1 (UID exists)
 *   resp[0x13] = 1 (persona creation flag → triggers SM_Transition(1,3))
 *
 * SM_Transition(1,3) → OSDK screen (NOP'd) → OSDK completion handler
 * calls SM_Transition(0,-1) → state 0 onEnter → Login flow.
 */

"use strict";
var base = Process.getModuleByName("FIFA17.exe").base;
var t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }
function addr(off) { return base.add(off); }

console.log("=== FIFA 17 v19: Fix CreateAccount response ===");

// NOP the OSDK screen loader (already done by DLL but belt-and-suspenders)
try {
  Memory.patchCode(addr(0x6e00f40), 4, function(code) {
    var w = new X86Writer(code, { pc: addr(0x6e00f40) });
    w.putRet();
    w.flush();
  });
  console.log(ts() + " Patched OSDK screen -> RET");
} catch(e) {}

// Exception handler
Process.setExceptionHandler(function(details) {
  if (details.address.toString().indexOf("7ffd") === 2) return false; // ignore system crashes
  console.log(ts() + " !!! CRASH: " + details.type + " at " + details.address);
  return false;
});

// Hook CreateAccount handler — write correct response values
Interceptor.attach(addr(0x6e151d0), {
  onEnter: function(args) {
    this._resp = args[1];
    this._err = args[2].toInt32();
    console.log(ts() + " CreateAccountHandler(err=" + this._err + " resp=" + this._resp + ")");

    if (this._err === 0) {
      try {
        var resp = this._resp;
        // Before: resp[0x10..0x13] = all zeros (broken TDF decoder)
        console.log(ts() + "   BEFORE: [0x10]=" + resp.add(0x10).readU8() +
                    " [0x11]=" + resp.add(0x11).readU8() +
                    " [0x12]=" + resp.add(0x12).readU8() +
                    " [0x13]=" + resp.add(0x13).readU8());

        resp.add(0x10).writeU8(1);  // UID byte = 1 (account exists)
        resp.add(0x11).writeU8(0);
        resp.add(0x12).writeU8(0);
        resp.add(0x13).writeU8(1);  // persona flag = 1 → triggers SM(1,3)

        console.log(ts() + "   AFTER:  [0x10]=1 [0x11]=0 [0x12]=0 [0x13]=1");
      } catch(e) {
        console.log(ts() + "   Write error: " + e);
      }
    }
  },
  onLeave: function(ret) {
    console.log(ts() + " CreateAccountHandler done");
  }
});
console.log(ts() + " Hooked CreateAccountHandler");

// Hook OSDK completion handler
try {
  Interceptor.attach(addr(0x6e15320), {
    onEnter: function(args) {
      console.log(ts() + " OSDKCompletionHandler fired!");
    }
  });
  console.log(ts() + " Hooked OSDKCompletionHandler");
} catch(e) {
  console.log(ts() + " OSDKCompletion hook failed: " + e);
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
                   0x46:"Logout", 0x98:"OriginLogin", 0x6e:"LoginPersona"};
      console.log(ts() + " AUTH RPC: " + (names[cmd] || "0x"+cmd.toString(16)));
    } else if (comp === 9 && (cmd === 7 || cmd === 8)) {
      console.log(ts() + " RPC: " + (cmd === 7 ? "PreAuth" : "PostAuth"));
    }
  }
});

// Monitor state transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM(" + args[1].toInt32() + "," + args[2].toInt32() + ")");
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
    console.log(ts() + " LoginTypesProcessor");
    try {
      var parent = args[0].add(0x08).readPointer();
      if (!parent.isNull()) {
        var flag = parent.add(0x53f).readU8();
        if (flag === 0) { parent.add(0x53f).writeU8(1); console.log(ts() + "   forced +0x53f=1"); }
      }
    } catch(e) {}
  },
  onLeave: function(ret) { console.log(ts() + " LoginTypesProcessor done"); }
});

console.log(ts() + " Ready. Waiting for CreateAccount...");
