/*
 * FIFA 17 — Flow Trace (passive observation only)
 *
 * Purpose: Capture the complete call chain from PreAuth → Logout decision.
 * Does NOT patch anything. Just observes.
 *
 * Usage:
 *   frida -l frida_flow_trace.js -f FIFA17.exe --no-pause > trace.log
 *
 * Or if the game is already running:
 *   frida -l frida_flow_trace.js FIFA17.exe
 *
 * The log output should be captured and sent back for analysis.
 */

"use strict";

const base = Process.getModuleByName("FIFA17.exe").base;
const t0 = Date.now();
function ts() { return (Date.now() - t0).toString().padStart(7, ' '); }
function addr(off) { return base.add(off); }
function log(msg) { console.log("[" + ts() + "] " + msg); }

// Shorten long hex dumps
function shortHex(ptr, len) {
  try {
    const bytes = ptr.readByteArray(len);
    return Array.from(new Uint8Array(bytes))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) { return "<unreadable>"; }
}

function readStr(ptr, maxLen) {
  try {
    if (ptr.isNull()) return "<null>";
    const s = ptr.readCString(maxLen || 256);
    return s ? s.substring(0, 200) : "<empty>";
  } catch (e) { return "<err>"; }
}

function readU8(ptr, off) {
  try { return ptr.add(off).readU8(); } catch (e) { return -1; }
}
function readU32(ptr, off) {
  try { return ptr.add(off).readU32(); } catch (e) { return -1; }
}
function readU64(ptr, off) {
  try { return ptr.add(off).readU64().toString(16); } catch (e) { return "<err>"; }
}
function readPtr(ptr, off) {
  try { return ptr.add(off).readPointer(); } catch (e) { return ptr(0); }
}

// === Global state we want to watch ===
const DAT_OnlineManager    = addr(0x8a3b20);   // DAT_1448a3b20
const DAT_OriginSdkObject  = addr(0xb7c7a0);   // DAT_144b7c7a0 — watch out, 0x144xxx is one region
const DAT_SdkManager       = addr(0xb86bf8);   // DAT_144b86bf8
const DAT_OnlineModeFlag   = addr(0x8a3ac3);   // DAT_1448a3ac3

// Fix absolute addresses — these are in the .data section (0x144xxxxxx)
// Base is 0x140000000, so use absolute addresses directly.
const ABS = ptr => ptr;
const OM_PTR        = ptr("0x1448a3b20");
const SDK_OBJ_PTR   = ptr("0x144b7c7a0");
const SDK_MGR_PTR   = ptr("0x144b86bf8");
const ONLINE_FLAG   = ptr("0x1448a3ac3");

function dumpCheckpoint(label) {
  try {
    log("============ CHECKPOINT: " + label + " ============");

    const onlineMgr = OM_PTR.readPointer();
    const sdkObj    = SDK_OBJ_PTR.readPointer();
    const sdkMgr    = SDK_MGR_PTR.readPointer();
    const onFlag    = ONLINE_FLAG.readU8();

    log("  OnlineFlag       = " + onFlag);
    log("  OnlineManager    = " + onlineMgr);
    log("  OriginSdkObject  = " + sdkObj);
    log("  SdkManager       = " + sdkMgr);

    if (!onlineMgr.isNull()) {
      log("  OM +0x1c0 (connState?) = " + readU32(onlineMgr, 0x1c0));
      log("  OM +0x1f0 (gameMode?)  = " + readU32(onlineMgr, 0x1f0));
      log("  OM +0x13b8 (UI state)  = " + readU32(onlineMgr, 0x13b8));
      log("  OM +0x4e98 (auth0 ptr) = " + readPtr(onlineMgr, 0x4e98));
      log("  OM +0x4ea0 (auth1 ptr) = " + readPtr(onlineMgr, 0x4ea0));
      log("  OM +0x4ea8 (auth2 ptr) = " + readPtr(onlineMgr, 0x4ea8));
      log("  OM +0x4ece (authFail)  = " + readU8(onlineMgr, 0x4ece));
      log("  OM +0xb10 (connMgr)    = " + readPtr(onlineMgr, 0xb10));

      // BlazeHub via +0xb10 -> +0xf8
      const connMgr = readPtr(onlineMgr, 0xb10);
      if (!connMgr.isNull()) {
        const blazeHub = readPtr(connMgr, 0xf8);
        log("    BlazeHub             = " + blazeHub);
        if (!blazeHub.isNull()) {
          log("    BH +0x53f (flag)     = " + readU8(blazeHub, 0x53f));
        }
      }

      // Check auth request slots
      for (let slot = 0; slot < 3; slot++) {
        const p = readPtr(onlineMgr, 0x4e98 + slot * 8);
        if (!p.isNull()) {
          log("    auth slot " + slot + " obj  = " + p);
          log("      +0xd8 (auth code ptr) = " + readPtr(p, 0xd8));
          log("      +0xe8 (ready flag)    = " + readU8(p, 0xe8));
          const authPtr = readPtr(p, 0xd8);
          if (!authPtr.isNull()) {
            log("      auth code str = \"" + readStr(authPtr, 64) + "\"");
          }
        }
      }
    }

    if (!sdkObj.isNull()) {
      log("  SDK +0x3a0 (userId)  = " + readU64(sdkObj, 0x3a0));
      log("  SDK +0x35c (port)    = " + readU32(sdkObj, 0x35c));
    }

    log("============");
  } catch (e) {
    log("  CHECKPOINT ERR: " + e.message);
  }
}

// === Hook catalog ===

function hookFn(offset, name, onEnterFn, onLeaveFn) {
  try {
    const tgt = addr(offset);
    Interceptor.attach(tgt, {
      onEnter: function(args) {
        try {
          this._entry = Date.now() - t0;
          if (onEnterFn) onEnterFn.call(this, args, this.context);
        } catch (e) { log("ERR " + name + " onEnter: " + e.message); }
      },
      onLeave: function(retval) {
        try {
          if (onLeaveFn) onLeaveFn.call(this, retval, this.context);
        } catch (e) { log("ERR " + name + " onLeave: " + e.message); }
      }
    });
    log("HOOKED " + name + " @ " + tgt);
  } catch (e) {
    log("FAILED TO HOOK " + name + " @ 0x" + offset.toString(16) + ": " + e.message);
  }
}

// PreAuth response handler — param_3 is error code, param_2 is response TDF obj
hookFn(0x6e1cf10, "PreAuthHandler",
  function(args) {
    const errCode = args[2].toInt32();
    log("PreAuthHandler(this=" + args[0] + " resp=" + args[1] + " err=" + errCode + ")");
    this._param1 = args[0];
    this._param2 = args[1];
  },
  function(ret) {
    log("PreAuthHandler returned");
    // Dump the response TDF obj fields at +0x100..+0x200
    try {
      const resp = this._param2;
      if (!resp.isNull()) {
        log("  resp dump +0x100..+0x150:");
        for (let off = 0x100; off <= 0x150; off += 0x10) {
          log("    +" + off.toString(16) + ": " + shortHex(resp.add(off), 16));
        }
      }
    } catch (e) {}
    // CHECKPOINT after PreAuth
    dumpCheckpoint("PreAuth done");
  }
);

// Login types processor — this is where +0x218 array is populated
hookFn(0x6e1c3f0, "LoginTypesProcessor",
  function(args) {
    const loginSM = args[0];
    const preAuthResp = args[1];
    log("LoginTypesProcessor(loginSM=" + loginSM + " resp+0x120=" + preAuthResp + ")");
    this._loginSM = loginSM;
    // Dump the login types source in the PreAuth response
    try {
      log("  resp TDF bytes (first 64): " + shortHex(preAuthResp, 64));
    } catch (e) {}
  },
  function(ret) {
    try {
      const sm = this._loginSM;
      const start = readPtr(sm, 0x218);
      const end   = readPtr(sm, 0x220);
      const count = end.sub(start).toInt32() / 0x20;
      log("LoginTypesProcessor done. loginSM+0x218=" + start + " +0x220=" + end + " count=" + count);
      // Dump each entry
      for (let i = 0; i < count && i < 10; i++) {
        const entry = start.add(i * 0x20);
        log("  entry[" + i + "]: " + shortHex(entry, 0x20));
      }
    } catch (e) { log("  err: " + e.message); }
  }
);

// Login check — iterates +0x218 array
hookFn(0x6e1dae0, "LoginCheck",
  function(args) {
    const sm = args[0];
    try {
      const start = readPtr(sm, 0x218);
      const end   = readPtr(sm, 0x220);
      const count = end.sub(start).toInt32() / 0x20;
      log("LoginCheck(loginSM=" + sm + " count=" + count + ")");
    } catch (e) { log("LoginCheck ERR: " + e.message); }
  },
  function(ret) {
    log("LoginCheck returned " + ret.toInt32());
  }
);

// Login RPC sender — the holy grail. If this is called, the Login RPC is sent.
hookFn(0x6e1eb70, "LoginSender",
  function(args) {
    log("🎯 LoginSender(p0=" + args[0] + " p1=" + args[1] + " p2=" + args[2] + " p3=" + args[3] + ")");
    try {
      if (!args[1].isNull()) {
        log("  p1 bytes: " + shortHex(args[1], 0x20));
        const strPtr = readPtr(args[1], 0);
        if (!strPtr.isNull()) log("  p1[0] -> \"" + readStr(strPtr, 64) + "\"");
      }
    } catch (e) {}
  },
  function(ret) { log("🎯 LoginSender returned " + ret.toInt32()); }
);

// Login fallback — called when loginTypes array is empty
hookFn(0x6e19b30, "LoginFallback_NoTypes",
  function(args) { log("⚠️  LoginFallback_NoTypes called (login types array empty!)"); },
  function(ret) { log("LoginFallback_NoTypes done"); }
);

// Origin SDK auth code request (top-level — called by DLL cave target)
hookFn(0x70db3c0, "OriginRequestAuthCodeSync",
  function(args) {
    log("OriginRequestAuthCodeSync(userId=" + args[0] + " clientId=" + args[1] +
        " scope=" + args[2] + " outCode=" + args[3] + ")");
  },
  function(ret) { log("OriginRequestAuthCodeSync returned"); }
);

// Origin SDK LSX RequestAuthCode — sends GetAuthCode XML
hookFn(0x70e67f0, "Origin_RequestAuthCode_LSX",
  function(args) {
    log("Origin_RequestAuthCode_LSX(sdk=" + args[0] + " userId=" + args[1] +
        " clientId=" + args[2] + " scope=" + args[3] + ")");
  },
  function(ret) { log("Origin_RequestAuthCode_LSX returned 0x" + ret.toString(16)); }
);

// Is Origin SDK connected (DAT_144b7c7a0 != 0)
// NOTE: this is called VERY frequently (every tick). We log only on changes.
let lastIsConnected = null;
hookFn(0x70e2840, "IsOriginSDKConnected",
  function(args) {},
  function(ret) {
    try {
      const v = (ret.toInt32() & 0xFF);
      if (v !== lastIsConnected) {
        const sdkObj = SDK_OBJ_PTR.readPointer();
        log("IsOriginSDKConnected => " + v + "  (DAT_144b7c7a0 = " + sdkObj + ")");
        lastIsConnected = v;
      }
    } catch (e) {}
  }
);

// FirstPartyAuthTokenRequest processor — per-frame auth slot iterator
hookFn(0x6f199c0, "FirstPartyAuthTokenReq",
  function(args) {
    const base = args[0];
    try {
      const slot1 = readPtr(base, 8);
      const slot2 = readPtr(base, 16);
      if (!slot1.isNull() || !slot2.isNull()) {
        log("FirstPartyAuthTokenReq(base=" + base + ")");
        log("  slot1=" + slot1 + " slot2=" + slot2);
      }
    } catch (e) {}
  }
);

// Login event dispatcher (from Origin SDK XML)
hookFn(0x7102800, "LoginEventDispatcher",
  function(args) { log("LoginEventDispatcher(" + args[0] + ", " + args[1] + ")"); }
);

// RPC wire send — component, command, msgId
hookFn(0x6df0e80, "RpcSend",
  function(args, ctx) {
    // R8 = component, R9 = command per earlier docs
    const comp = ctx.r8.toInt32() & 0xFFFF;
    const cmd  = ctx.r9.toInt32() & 0xFFFF;
    if (comp === 0 && cmd === 0) return;   // skip pings
    const names = {
      "1:0x7": "PreAuth?", "1:0xa": "CreateAccount", "1:0x28": "Login",
      "1:0x32": "SilentLogin", "1:0x46": "Logout", "1:0x98": "OriginLogin",
      "9:0x7": "PreAuth", "9:0x8": "PostAuth", "9:0x1": "FetchClientConfig",
      "9:0x2": "Ping"
    };
    const key = comp + ":0x" + cmd.toString(16);
    const name = names[key] || key;
    const marker = (comp === 1 && cmd === 0x46) ? "🚨 LOGOUT SENT" : "RpcSend";
    log(marker + " [" + name + "]");
    if (comp === 1 && cmd === 0x46) {
      dumpCheckpoint("just before Logout RPC");
      // Print a stack trace to see WHO called this
      try {
        const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
          .slice(0, 15)
          .map(DebugSymbol.fromAddress)
          .map(String);
        log("  STACK:");
        bt.forEach(s => log("    " + s));
      } catch (e) { log("  stack err: " + e.message); }
    }
  }
);

// RPC builder — where component/command are set
hookFn(0x6dab760, "RpcBuilder",
  function(args, ctx) {
    const comp = ctx.r8.toInt32() & 0xFFFF;
    const cmd  = ctx.r9.toInt32() & 0xFFFF;
    if (comp === 0) return;
    log("RpcBuilder(comp=0x" + comp.toString(16) + " cmd=0x" + cmd.toString(16) + ")");
  }
);

// State transitions in LoginStateMachineImpl
// The vtable +0x08 transition function: args are (this, newState, leaveReason)
hookFn(0x6e126b0, "SM_Transition",
  function(args) {
    const sm = args[0];
    const newState = args[1].toInt32();
    const reason = args[2].toInt32();
    log("SM_Transition(sm=" + sm + " newState=" + newState + " reason=" + reason + ")");
  }
);

// Send XML via LSX
hookFn(0x70e6ee0, "LSX_SendXml",
  function(args) {
    try {
      // args[1] likely the XML buffer
      const xml = readStr(args[1], 300);
      log("LSX_SendXml: " + xml);
    } catch (e) {}
  }
);

// Watch online tick so we can observe state changes over time
// Only emit when any watched field CHANGES — way less noise.
let tickCount = 0;
let lastC1c0 = -999, lastC1f0 = -999, lastC13b8 = -999;
hookFn(0x6f7c7e0, "OnlineTick",
  function(args) {
    tickCount++;
    if (tickCount % 30 !== 0) return;
    try {
      const onlineMgr = OM_PTR.readPointer();
      if (onlineMgr.isNull()) return;
      const c1c0  = readU32(onlineMgr, 0x1c0);
      const c1f0  = readU32(onlineMgr, 0x1f0);
      const c13b8 = readU32(onlineMgr, 0x13b8);
      if (c1c0 !== lastC1c0 || c1f0 !== lastC1f0 || c13b8 !== lastC13b8) {
        log("STATE-CHANGE tick#" + tickCount + " OM(+0x1c0=" + lastC1c0 + "→" + c1c0 +
            " +0x1f0=" + lastC1f0 + "→" + c1f0 +
            " +0x13b8=" + lastC13b8 + "→" + c13b8 + ")");
        lastC1c0 = c1c0; lastC1f0 = c1f0; lastC13b8 = c13b8;
      }
    } catch (e) {}
  }
);

// === Initial checkpoint ===
log("=== Frida flow trace attached ===");
log("Base: " + base);

// Dump the PreAuthResponse TDF member info table (14 entries at 0x144874a90).
// Each entry in BlazeSDK's TdfMemberInfo is typically 32 bytes containing:
//   { tag (u32), offset (u32), type (u32), flags (u32), name ptr (u64), ... }
// We don't know the exact layout so we dump raw bytes for manual decode.
function dumpMemberInfoTable() {
  try {
    const tablePtr = ptr("0x144874a90").readPointer();
    log("=== PreAuthResponse member info table @ " + tablePtr + " ===");
    for (let i = 0; i < 14; i++) {
      const entry = tablePtr.add(i * 40);  // guess — might be 32 or 48
      log("  [" + i + "] " + shortHex(entry, 40));
      // Try to interpret first 12 bytes as common layouts
      try {
        const u0 = entry.readU32();
        const u4 = entry.add(4).readU32();
        const u8 = entry.add(8).readU32();
        // Tag is typically encoded with upper bit set in the hash
        log("       u32[0]=0x" + u0.toString(16) +
            " u32[1]=0x" + u4.toString(16) +
            " u32[2]=0x" + u8.toString(16));
      } catch (e) {}
    }
  } catch (e) { log("member table dump err: " + e.message); }
}

setTimeout(() => {
  dumpCheckpoint("initial (after DLL patches should be done)");
  dumpMemberInfoTable();
}, 2000);
setTimeout(() => dumpCheckpoint("5s mark"), 5000);
setTimeout(() => dumpCheckpoint("10s mark"), 10000);
