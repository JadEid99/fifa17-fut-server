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

// The problem: we can't inject into loginSM+0x218/+0x220 because those
// contain TDF objects with vtables that the code iterates and dereferences.
// We can't hook FUN_146e1dae0 (LoginCheck) with Interceptor.attach.
//
// Solution: Use Interceptor.replace on FUN_146e1dae0 to completely replace
// it with our own implementation that calls FUN_146e1eb70 (LoginSender)
// with our fake entry.
//
// FUN_146e1dae0 signature: uint64 FUN_146e1dae0(longlong param_1)
// It returns 0 (no login types) or 1 (login sent).

const origLoginCheck = new NativeFunction(addr(0x6e1dae0), 'uint64', ['pointer']);

try {
  Interceptor.replace(addr(0x6e1dae0), new NativeCallback(function(param_1) {
  // Strategy: Initialize the internal arrays that LoginSender needs,
  // then call LoginSender directly. This mirrors what FUN_146e1c3f0
  // does before calling LoginCheck.
  //
  // The crash in test 9 was because param_1+0x258 wasn't initialized.
  // FUN_146e1c3f0 calls these before LoginCheck:
  //   FUN_146e192f0(param_1 + 600, count)  — resize array at +0x258
  //   FUN_146f8e7e0(param_1 + 0x38, count) — init tracking array
  // We need to call these with count=1 before calling LoginSender.
  
  if (loginTypeInjected) {
    return ptr(0);
  }
  
  loginTypeInjected = true;
  console.log(ts() + " LoginCheck REPLACED: initializing arrays + calling LoginSender");
  
  try {
    const jobHandle = param_1.add(0x18).readPointer();
    if (jobHandle.isNull()) {
      console.log(ts() + "   jobHandle is NULL — can't send Login RPC");
      return ptr(0);
    }
    console.log(ts() + "   jobHandle = " + jobHandle);
    
    // Initialize the internal arrays with count=1
    // FUN_146e192f0(param_1 + 600, 1) — 600 decimal = 0x258
    const resizeFn = new NativeFunction(addr(0x6e192f0), 'void', ['pointer', 'uint32']);
    console.log(ts() + "   Calling FUN_146e192f0(param_1+0x258, 1) to resize array...");
    resizeFn(param_1.add(0x258), 1);
    
    // FUN_146f8e7e0(param_1 + 0x38, 1)
    const initFn = new NativeFunction(addr(0x6f8e7e0), 'void', ['pointer', 'uint32']);
    console.log(ts() + "   Calling FUN_146f8e7e0(param_1+0x38, 1) to init tracking...");
    initFn(param_1.add(0x38), 1);
    
    // Set the status fields that FUN_146e1c3f0 sets before LoginCheck
    param_1.add(0x1a0).writeU16(0);
    param_1.add(0x210).writeU8(param_1.add(0x210).readU8() | 1);
    
    console.log(ts() + "   Arrays initialized. Now calling LoginSender...");
    
    // Allocate our fake entry and config
    const entry = Memory.alloc(0x40);
    const flagStr = Memory.allocUtf8String("1");
    entry.writePointer(flagStr);
    entry.add(0x10).writeU32(2);
    
    const config = entry.add(0x20);
    const authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
    config.add(0x10).writePointer(authToken);
    config.add(0x28).writeU16(0);
    entry.add(0x18).writePointer(config);
    
    const loginSenderFn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
    const result = loginSenderFn(param_1, entry, config, 1);
    console.log(ts() + " 🎯 LoginSender returned: 0x" + result.toString(16));
    
    if (result.toInt32() !== 0) {
      console.log(ts() + " 🚀🚀🚀 LOGIN RPC QUEUED! 🚀🚀🚀");
      return ptr(1);
    }
    return ptr(0);
  } catch(e) {
    console.log(ts() + " EXCEPTION: " + e.message);
    return ptr(0);
  }
}, 'uint64', ['pointer']));
  console.log(ts() + " Successfully replaced FUN_146e1dae0 (LoginCheck)");
} catch(replaceErr) {
  console.log(ts() + " Interceptor.replace failed: " + replaceErr.message);
  console.log(ts() + " FALLBACK: Patching FUN_146e1dae0 with Memory.patchCode");
  
  // Fallback: use Memory.patchCode to write a JMP to our code cave
  // We'll write the function body directly using x86 assembly
  try {
    // Simpler fallback: hook FUN_146e1c3f0 at onLeave and call LoginSender
    // from a setTimeout(0) to avoid the deadlock (runs on next tick)
    Interceptor.attach(addr(0x6e1c3f0), {
      onLeave: function(retval) {
        if (loginTypeInjected) return;
        loginTypeInjected = true;
        
        const loginSM = this.context.rbx; // RBX typically holds param_1 in callee-saved
        console.log(ts() + " FALLBACK: LoginTypesProcessor done, scheduling LoginSender on next tick");
        console.log(ts() + "   loginSM candidate (rbx) = " + loginSM);
        
        // Use setTimeout to call LoginSender outside the PreAuth handler stack
        setTimeout(function() {
          console.log(ts() + " FALLBACK: setTimeout fired, calling LoginSender...");
          try {
            const entry = Memory.alloc(0x40);
            const flagStr = Memory.allocUtf8String("1");
            entry.writePointer(flagStr);
            entry.add(0x10).writeU32(2);
            
            const config = entry.add(0x20);
            const authToken = Memory.allocUtf8String("FAKEAUTHCODE1234567890");
            config.add(0x10).writePointer(authToken);
            config.add(0x28).writeU16(0);
            entry.add(0x18).writePointer(config);
            
            const loginSenderFn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
            const result = loginSenderFn(loginSM, entry, config, 1);
            console.log(ts() + " FALLBACK LoginSender returned: " + result);
          } catch(e) {
            console.log(ts() + " FALLBACK LoginSender error: " + e.message);
          }
        }, 0);
      }
    });
    console.log(ts() + " FALLBACK: Hooked LoginTypesProcessor onLeave with setTimeout");
  } catch(fallbackErr) {
    console.log(ts() + " FALLBACK also failed: " + fallbackErr.message);
  }
}

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

// Monitor LoginTypesProcessor for logging only
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    const loginSM = args[0];
    console.log(ts() + " LoginTypesProcessor(loginSM=" + loginSM + ")");
    // Check the +0x53f flag that gates the LoginCheck call
    try {
      const parent = loginSM.add(0x08).readPointer();
      if (!parent.isNull()) {
        const flag53f = parent.add(0x53f).readU8();
        console.log(ts() + "   loginSM+0x08 (parent) = " + parent);
        console.log(ts() + "   parent+0x53f = " + flag53f + (flag53f ? " (GOOD — LoginCheck will run)" : " (BAD — LoginCheck SKIPPED!)"));
        if (flag53f === 0) {
          console.log(ts() + "   FORCING parent+0x53f = 1");
          parent.add(0x53f).writeU8(1);
        }
      } else {
        console.log(ts() + "   loginSM+0x08 = NULL!");
      }
    } catch(e) {
      console.log(ts() + "   parent check error: " + e.message);
    }
  },
  onLeave: function(ret) {
    console.log(ts() + " LoginTypesProcessor done");
  }
});

console.log(ts() + " All hooks installed. Waiting for PreAuth...");
