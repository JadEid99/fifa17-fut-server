# FIFA 17 Private Server — Definitive Solution

## Root Cause (Confirmed)

The game's auth token request fires during startup (~100ms) and calls
`FUN_1470db3c0` → `FUN_1470e67f0` which sends `GetAuthCode` to the STP
emulator via LSX socket. STP doesn't handle auth → 15-second timeout → error.
The auth slot is cleared (one-shot). Our DLL patches apply at ~640ms — too late.

Without an auth token, the Blaze SDK does: PreAuth → disconnect.
With an auth token, it would do: PreAuth → Login/SilentLogin → PostAuth → online.

## Solution: Patch FUN_1470e1ed0 (the 15-second wait)

`FUN_1470e67f0` calls `FUN_1470e1ed0(request, 15000)` to send the GetAuthCode
request to STP and wait for a response. This function BLOCKS for up to 15 seconds.

Since the auth request fires at ~100ms and our patches apply at ~640ms, the
function is STILL BLOCKED inside `FUN_1470e1ed0` when our patches land. The
function hasn't returned yet.

If we patch `FUN_1470e1ed0` to return success immediately, the auth request
will complete instantly. But it will complete with whatever STP returned (nothing),
so the auth code will be empty.

Better approach: patch `FUN_1470e67f0` AFTER the `FUN_1470e1ed0` call returns.
The function checks the result and copies the auth code. We can patch the
success path to use our fake auth code.

## Better Solution: Patch the auth token CHECK, not the auth token REQUEST

The Blaze SDK's login state machine checks if an auth token is available before
sending the Login request. Instead of trying to provide a real auth token, we
can patch the CHECK to always say "yes, auth token is available" and provide
a hardcoded token string.

From the LoginStateMachineImpl (FUN_146e116a0), the login type 0 (Login with
auth token) reads the auth token from a data structure. If we can find where
this read happens and replace it with a hardcoded string, the Login request
will be sent with our fake token.

## Simplest Solution: Patch FUN_1470db3c0 to return INSTANTLY

The function `FUN_1470db3c0` is called at ~100ms. Our patch lands at ~640ms.
But the function is still executing (blocked in the 15s wait). 

What if we DON'T patch the function body, but instead patch the CALLER to
retry? The caller `FUN_146f199c0` clears the slot after one attempt. If we
NOP the slot-clearing code, the function will be called again on the next
frame tick — and THIS time our patched function body will be in place.

## Implementation: NOP the slot-clearing in FUN_146f199c0

In `FUN_146f199c0`:
```c
plVar2 = (longlong *)*param_1;
*param_1 = 0;           // ← NOP THIS (don't clear the slot)
if (plVar2 != NULL) {
    (**(code **)(*plVar2 + 8))();  // ← NOP THIS (don't destroy the object)
}
```

If we NOP the `*param_1 = 0` and the destructor call, the auth request will
remain in the slot. On the next frame tick, `FUN_146f199c0` will be called
again, and this time `FUN_1470db3c0` will hit our patched body (which returns
a fake auth code instantly).

The auth code will be stored at `[reqObj + 0xd8]` and the flag at `[reqObj + 0xe8]`
will be set to 1. The Blaze SDK will then have an auth token and proceed to
send the Login request.

After the auth code is successfully stored, we need the slot to eventually
be cleared (otherwise it will keep calling). We can handle this by having
our patched `FUN_1470db3c0` set a flag that tells the DLL to restore the
original slot-clearing code after one successful execution.
