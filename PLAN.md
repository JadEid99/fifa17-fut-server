# FIFA 17 Diagnosis — The Master Plan

## Where We Are
Origin IPC works. Blaze PreAuth + FetchClientConfig work. But the game sends
**Logout** (cmd 0x46, empty body) as its first authentication action.
This is not the Blaze protocol level — this is the game's high-level
LoginAdaptor (UI layer) calling `FUN_1472d62a0` (`LoginAdaptor::Logout`).

## What We Learned Today

### 1. LoginStateMachineImpl Structure (from Ghidra)
`FUN_146e116a0` constructs a LoginStateMachineImpl. It contains THREE
sub-state-machines at offsets:
- `+0x07` — first SM (initialized from `FUN_146e116a0` recursive call)
- `+0xa2` — second SM (from `FUN_146e11610`)
- `+0xac` — third SM (from `FUN_146e11570`)

This confirms why attempting state transition (2,1) crashed earlier —
**there are only 3 sub-machines, at slot indices 1, 2, 4 of the outer struct**
(the array has 5 pointers: [0]=self, [1]=SM1, [2]=SM2, [3]=NULL, [4]=SM3).
Your earlier "SM[3] = 0x0" finding matches exactly.

### 2. Logout Has No TDF Body
Unlike Login/CreateAccount/OriginLogin, Logout is NOT registered in the
Blaze RPC TDF table. It's a bare command with cmd=0x46, empty body.
That's why your server sees `len=0`.

### 3. Logout Is Called from UI Layer
`FUN_1472d62a0` is `LoginAdaptor::Logout`. It calls
`DAT_144b8fee8->0x70->0x38()` which sends the Blaze RPC.
Something in the game's high-level login logic is deciding to call this.

### 4. PreAuthResponse TDF Has 14 Fields
TDF member info table at `PTR_DAT_144874a90` has 14 entries. The member
table itself is static data Ghidra can't decompile. We need Frida to
dump this at runtime.

### 5. BF4 Working PreAuth Structure (Reference)
BF4's working PreAuth response contains at minimum:
- ASRC (source), CIDS (component IDs list), CONF (config map),
  ESRC, INST (instance name), MINR, NASP (namespace), PLAT,
  QOSS (QoS struct), + more
- Decoded from BF4BlazeEmulator/Components_Client/Util.py

### 6. Login Types Populated from PreAuth TDF +0x120
`FUN_146e1c3f0` reads from `PreAuthResponse + 0x120` to populate
`loginSM+0x218..+0x220` (login type array). If the array is empty,
`FUN_146e1dae0` returns 0 and the fallback `FUN_146e19b30` runs.

## The Plan

### Phase A: Instrument (you run the Frida script)
File: `frida_flow_trace.js`

This passive script hooks every key function in the auth chain.
It does NOT patch anything. It just logs.

**You run:**
```
frida -l frida_flow_trace.js FIFA17.exe > trace.log 2>&1
```
(Game should already be launched with the DLL.)

Let the game get to the point where it sends Logout, then stop and
send me `trace.log`.

### Phase B: Analyze (I do this)
From the trace we will determine:

1. **Is `FUN_146e1c3f0` called?** (It should be, after PreAuth response.)
2. **What's the count of login types in `loginSM+0x218..+0x220`?**
   - If 0: **we need to add login types to the PreAuth response**.
3. **Does `FUN_146e1eb70` (Login sender) ever fire?**
   - If no: decision was made before Login was reached.
4. **Does `FUN_146e19b30` (fallback) fire?**
   - If yes: login types were empty, we know the fix.
5. **What's the stack trace at the moment Logout RPC is sent?**
   - This reveals the exact code path that chose Logout.

### Phase C: Fix (one of these paths)

**Path A: Login types missing from PreAuth.**
We add them to our PreAuth TDF response. I know approximately what
tag is used (based on offset +0x120 → ~9th field). We try standard
BlazeSDK tag names: `LGTY`, `LGDY`, `LOGT`, `ALGT`, etc.

**Path B: Login types present but Login still isn't sent.**
Something else is blocking — probably the `+0x53f` flag on BlazeHub
isn't set at the right moment. We fix the timing.

**Path C: UI layer calls Logout on a different trigger.**
A state-machine state's `onEnter` calls `LoginAdaptor::Logout` when
some condition fails. We'd identify the condition and fix it.

## What I Need From You

1. **Pull the latest changes** (I'll push when this plan is done).
2. **Run the Frida trace** while the game attempts to connect.
3. **Stop when you see "EA servers unavailable"** or similar.
4. **Send me `trace.log`** — even if 1MB+ that's fine, I'll parse it.

## Estimated Time to Solution
- Phase A (Frida run): 5 minutes (you run it)
- Phase B (my analysis): 1 back-and-forth
- Phase C (fix): 1-2 iterations

We should have a working auth in 2-3 more interactions if this plan
works as intended.
