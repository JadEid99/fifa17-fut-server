/*
 * FIFA 17 — v22: Passive observer (no injection)
 *
 * Major hypothesis change: our PreAuth response had wrong CIDS format
 * and other bugs. After fixing per Blaze3SDK schema, test what the game
 * does with a properly-formatted PreAuth. No injections or replacements.
 */

"use strict";
var base = Process.getModuleByName("FIFA17.exe").base;
var t0 = Date.now();
function ts() { return "[" + (Date.now() - t0).toString().padStart(7) + "]"; }
function addr(off) { return base.add(off); }

console.log("=== v22: Passive observer (no injection) ===");

// Ignore system exceptions
Process.setExceptionHandler(function(details) {
  if (details.address.toString().indexOf("7ffd") === 2) return false;
  console.log(ts() + " !!! CRASH: " + details.type + " at " + details.address);
  return false;
});

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
        console.log(ts() + " 🚀 " + name + " ON WIRE! 🚀");
      } else {
        console.log(ts() + " AUTH: " + name);
      }
    } else if (comp === 9 && (cmd === 7 || cmd === 8)) {
      console.log(ts() + " " + (cmd === 7 ? "PreAuth" : "PostAuth"));
    }
  }
});

// PreAuth handler
Interceptor.attach(addr(0x6e1cf10), {
  onEnter: function(args) { console.log(ts() + " PreAuthHandler(err=" + args[2].toInt32() + ")"); },
  onLeave: function(ret) { console.log(ts() + " PreAuthHandler done"); }
});

// LoginTypesProcessor — just observe state
Interceptor.attach(addr(0x6e1c3f0), {
  onEnter: function(args) {
    console.log(ts() + " LoginTypesProcessor");
    try {
      var p = args[0].add(0x08).readPointer();
      if (!p.isNull()) {
        console.log(ts() + "   parent+0x53f = " + p.add(0x53f).readU8());
      }
    } catch(e) {}
  },
  onLeave: function(ret) {
    try {
      var sm = this._sm = arguments.callee.caller; // hack
    } catch(e) {}
    console.log(ts() + " LoginTypesProcessor done");
  }
});

// LoginCheck — observe return value
Interceptor.attach(addr(0x6e1dae0), {
  onEnter: function(args) {
    try {
      var start = args[0].add(0x218).readPointer();
      var end = args[0].add(0x220).readPointer();
      var count = start.isNull() ? 0 : end.sub(start).toInt32() / 0x20;
      console.log(ts() + " LoginCheck: array count=" + count);
    } catch(e) { console.log(ts() + " LoginCheck: err " + e); }
  },
  onLeave: function(ret) {
    console.log(ts() + " LoginCheck returned " + ret);
  }
});

// LoginSender — the holy grail
Interceptor.attach(addr(0x6e1eb70), {
  onEnter: function(args) {
    console.log(ts() + " 🎯🎯🎯 LoginSender fired naturally! 🎯🎯🎯");
  },
  onLeave: function(ret) {
    console.log(ts() + " LoginSender returned " + ret);
  }
});

// LoginFallback (when no login types)
Interceptor.attach(addr(0x6e19b30), {
  onEnter: function(args) {
    console.log(ts() + " ⚠️ LoginFallback (no login types)");
  }
});

// State transitions
Interceptor.attach(addr(0x6e126b0), {
  onEnter: function(args) {
    console.log(ts() + " SM(" + args[1].toInt32() + "," + args[2].toInt32() + ")");
  }
});

// CreateAccount handler — do we receive it?
Interceptor.attach(addr(0x6e151d0), {
  onEnter: function(args) {
    console.log(ts() + " CreateAccountHandler(err=" + args[2].toInt32() + ")");
  }
});

console.log(ts() + " Ready. Testing fixed PreAuth response (Blaze3SDK schema)...");
