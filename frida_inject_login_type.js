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

// Hook FUN_146e1c3f0 (LoginTypesProcessor) — this is called from the PreAuth
// handler and eventually calls FUN_146e1dae0 (LoginCheck) internally.
// We inject the login type entry at the START of this function, so when
// LoginCheck runs, the array will already have our entry.
//
// We can't hook FUN_146e1dae0 directly because Frida reports
// "unable to intercept function" (possibly due to DLL patches nearby).
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    const loginSM = args[0];
    console.log(ts() + " LoginTypesProcessor(loginSM=" + loginSM + ")");
    this._loginSM = loginSM;
  },
  onLeave: function(retval) {
    const loginSM = this._loginSM;
    if (!loginSM || loginTypeInjected) {
      console.log(ts() + " LoginTypesProcessor done (skip inject)");
      return;
    }
    
    try {
      const arrStart = loginSM.add(0x218).readPointer();
      const arrEnd = loginSM.add(0x220).readPointer();
      
      if (arrStart.isNull() && arrEnd.isNull()) {
        console.log(ts() + " LoginTypesProcessor: array STILL empty after processing — INJECTING");
        loginTypeInjected = true;
        
        // Allocate a fake login type entry (0x20 bytes per entry)
        const entry = Memory.alloc(0x40);
        
        // Entry layout (from FUN_146e1eb70 Ghidra analysis):
        //   +0x00: pointer to string (flag — *(char*)*param_2 != '\0')
        //   +0x10: u32 — used as (value >> 1) for string length param
        //   +0x18: pointer to config object
        // Config object layout:
        //   +0x10: pointer to auth token string (must be non-empty)
        //   +0x28: u16 transport type (0 = Login)
        
        // Write a non-empty flag string at entry+0x00
        const flagStr = Memory.allocUtf8String("1");
        entry.writePointer(flagStr);
        
        // entry+0x10: u32 used as string length hint (set to reasonable value)
        entry.add(0x10).writeU32(2);  // (2 >> 1) = 1, safe length
        
        // Write auth token at config+0x10
        const config = entry.add(0x20);  // use second half of allocation
        const authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
        config.add(0x10).writePointer(authToken);
        
        // Transport type = 0 (Login with auth token)
        config.add(0x28).writeU16(0);
        
        // Set entry+0x18 = config pointer
        entry.add(0x18).writePointer(config);
        
        // Set the array pointers: start = entry, end = entry + 0x20 (one entry)
        loginSM.add(0x218).writePointer(entry);
        loginSM.add(0x220).writePointer(entry.add(0x20));
        
        const newStart = loginSM.add(0x218).readPointer();
        const newEnd = loginSM.add(0x220).readPointer();
        const count = newEnd.sub(newStart).toInt32() / 0x20;
        
        console.log(ts() + " Injected: entry=" + entry + " config=" + config);
        console.log(ts() + " Array: start=" + newStart + " end=" + newEnd + " count=" + count);
        
        // Call FUN_146e1eb70 (LoginSender) directly instead of going through
        // FUN_146e1dae0 (LoginCheck) — avoids re-entrancy issues since we're
        // in the onLeave of FUN_146e1c3f0 which already called LoginCheck.
        console.log(ts() + " Calling FUN_146e1eb70 (LoginSender) directly...");
        try {
          const loginSenderFn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
          const result = loginSenderFn(loginSM, entry, config, 1);
          console.log(ts() + " 🎯 LoginSender returned: " + result);
        } catch(e) {
          console.log(ts() + " LoginSender CRASHED: " + e.message);
        }
      } else {
        const count = arrEnd.sub(arrStart).toInt32() / 0x20;
        console.log(ts() + " LoginTypesProcessor done: array has " + count + " entries");
      }
    } catch(e) {
      console.log(ts() + " LoginTypesProcessor inject error: " + e.message);
    }
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
