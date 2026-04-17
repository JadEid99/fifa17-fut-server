/*
 * FIFA 17 — Login Type Injection (Frida)
 *
 * Root cause: PreAuth response doesn't contain login types.
 * FUN_146e1c3f0 (LoginTypesProcessor) runs after PreAuth, but the
 * login type array at loginSM+0x218/+0x220 stays empty.
 * FUN_146e1dae0 (LoginCheck) returns 0, LoginSender never fires,
 * and the game eventually sends Logout.
 *
 * Fix: Hook FUN_146e1dae0 (LoginCheck) and inject a fake login type
 * entry into the array BEFORE it iterates. This makes LoginCheck
 * call FUN_146e1eb70 (LoginSender) which sends the Login RPC.
 *
 * This runs ON THE GAME'S MAIN THREAD (inside the PreAuth handler
 * call chain), so the Login RPC will be sent on the correct thread
 * and the connection will still be alive.
 */

"use strict";
const base = Process.getModuleByName("FIFA17.exe").base;
function addr(off) { return base.add(off); }

const t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }

console.log("=== FIFA 17 Login Type Injector ===");

// NOP the OSDK screen loader (FUN_146e00f40) — prevents broken web view
try {
  Memory.patchCode(addr(0x6e00f40), 4, function(code) {
    var w = new X86Writer(code, { pc: addr(0x6e00f40) });
    w.putRet();
    w.flush();
  });
  console.log(ts() + " Patched FUN_146e00f40 (OSDK screen) -> RET");
} catch(e) { console.log(ts() + " OSDK patch failed: " + e.message); }

// Track state
let loginTypeInjected = false;
let loginSenderFired = false;

// Hook FUN_146e1c3f0 (LoginTypesProcessor) — inject login type entry
// at the START of this function, BEFORE it calls LoginCheck internally.
// This way the natural code path processes our entry without deadlocks.
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    const loginSM = args[0];
    console.log(ts() + " LoginTypesProcessor(loginSM=" + loginSM + ")");
    this._loginSM = loginSM;
    
    if (loginTypeInjected) return;
    
    try {
      // The function will read +0x218/+0x220 after doing the TDF copy.
      // We need to inject AFTER the TDF copy but BEFORE LoginCheck.
      // Since we can't hook between those two calls, we use a different
      // approach: we'll set a flag here and do the injection in a
      // setTimeout(0) which runs after this function returns but before
      // the next game tick processes the Logout timeout.
      //
      // Actually — the simplest approach: just populate +0x218/+0x220
      // right now. The TDF copy will overwrite +0x1b8 (a different field),
      // but +0x218/+0x220 is the PROCESSED array that LoginCheck reads.
      // If we write to +0x218/+0x220 now, the TDF copy won't touch it
      // (it writes to +0x1b8), and LoginCheck will see our entry.
      
      loginTypeInjected = true;
      console.log(ts() + " INJECTING login type entry into loginSM+0x218/+0x220");
      
      const entry = Memory.alloc(0x40);
      const flagStr = Memory.allocUtf8String("1");
      entry.writePointer(flagStr);
      entry.add(0x10).writeU32(2);
      
      const config = entry.add(0x20);
      const authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
      config.add(0x10).writePointer(authToken);
      config.add(0x28).writeU16(0);
      entry.add(0x18).writePointer(config);
      
      loginSM.add(0x218).writePointer(entry);
      loginSM.add(0x220).writePointer(entry.add(0x20));
      
      console.log(ts() + " Injected: entry=" + entry + " config=" + config);
      console.log(ts() + " loginSM+0x218=" + loginSM.add(0x218).readPointer());
      console.log(ts() + " loginSM+0x220=" + loginSM.add(0x220).readPointer());
      console.log(ts() + " Now letting the natural code path run (LoginCheck will see count=1)");
    } catch(e) {
      console.log(ts() + " Inject error: " + e.message);
    }
  },
  onLeave: function(retval) {
    if (!this._loginSM) return;
    try {
      const sm = this._loginSM;
      const start = sm.add(0x218).readPointer();
      const end = sm.add(0x220).readPointer();
      if (!start.isNull() && !end.isNull()) {
        const count = end.sub(start).toInt32() / 0x20;
        console.log(ts() + " LoginTypesProcessor done: array count=" + count);
      } else {
        console.log(ts() + " LoginTypesProcessor done: array still empty (injection may have been overwritten)");
      }
    } catch(e) {}
  }
});

// Monitor LoginSender (FUN_146e1eb70) — this is the goal
Interceptor.attach(addr(0x6e1eb70), {
  onEnter: function(args) {
    loginSenderFired = true;
    console.log(ts() + " 🎯 LoginSender FIRED! p0=" + args[0] + " p1=" + args[1] + " p2=" + args[2] + " p3=" + args[3]);
    try {
      const strPtr = args[1].readPointer();
      if (!strPtr.isNull()) {
        console.log(ts() + "   flag string: \"" + strPtr.readCString(32) + "\"");
      }
    } catch(e) {}
  },
  onLeave: function(retval) {
    console.log(ts() + " 🎯 LoginSender returned " + retval.toInt32());
  }
});

// Monitor RPC sends to see if Login actually goes on the wire
Interceptor.attach(addr(0x6df0e80), {
  onEnter: function(args) {
    var comp, cmd;
    try {
      comp = this.context.r8.toInt32() & 0xFFFF;
      cmd = this.context.r9.toInt32() & 0xFFFF;
    } catch(e) {
      return;
    }
    if (comp === 0 && cmd === 0) return;
    const names = {
      "1:0xa": "CreateAccount", "1:0x28": "Login", "1:0x32": "SilentLogin",
      "1:0x46": "Logout", "1:0x98": "OriginLogin",
      "9:0x7": "PreAuth", "9:0x8": "PostAuth", "9:0x1": "FetchClientConfig",
      "9:0x2": "Ping"
    };
    const key = comp + ":0x" + cmd.toString(16);
    const name = names[key] || key;
    
    if (comp === 1 && (cmd === 0x28 || cmd === 0x32 || cmd === 0x98)) {
      console.log(ts() + " 🚀🚀🚀 LOGIN RPC ON WIRE: " + name + " 🚀🚀🚀");
    } else if (comp === 1 && cmd === 0x46) {
      console.log(ts() + " ⚠️ Logout RPC sent");
    } else {
      console.log(ts() + " RPC: " + name);
    }
  }
});

// Monitor state transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM_Transition(newState=" + args[1].toInt32() + " reason=" + args[2].toInt32() + ")");
  }
});

// Monitor PreAuth handler
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) {
    console.log(ts() + " PreAuthHandler(err=" + args[2].toInt32() + ")");
  },
  onLeave: function(ret) {
    console.log(ts() + " PreAuthHandler done");
  }
});

// Monitor LoginTypesProcessor
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    console.log(ts() + " LoginTypesProcessor(loginSM=" + args[0] + ")");
  },
  onLeave: function(ret) {
    console.log(ts() + " LoginTypesProcessor done");
  }
});

console.log(ts() + " All hooks installed. Waiting for PreAuth...");
