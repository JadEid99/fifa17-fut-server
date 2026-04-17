# FIFA 17 — Pragmatic Next Steps

## Where We Are (after 23 tests)

- Origin IPC: ✅ works perfectly
- Blaze TLS + Redirector + PreAuth + FetchClientConfig: ✅ all work
- **Blocker: `loginSM+0x218/+0x220` array stays empty → no Login → Logout at 30s**

## What We Know

1. Our Node.js TDF encoder produces data the game DECODES (PreAuth handler runs with err=0, FetchClientConfig decodes correctly).
2. But ONE specific field (the one at `PreAuthResponse+0x120`) isn't being populated.
3. Ghidra says that field has element type `10` (not a standard Blaze3SDK type).
4. Even the Zamboni Blaze3SDK PreAuthResponse doesn't have a field with element type 10 — this is FIFA 17-specific.

## The Question We Need to Answer

**What TDF field at offset +0x120 in FIFA 17's PreAuthResponse is the game expecting?**

This is almost certainly an extension FIFA 17 added on top of the standard Blaze3SDK PreAuthResponse. The standard has 14 fields. FIFA 17's dumped metadata said 14 fields. But the field at offset +0x120 exists and takes an element-type-10 TDF list.

## Three Paths Forward

### Path A: Dump the ACTUAL TDF member info table at runtime (RECOMMENDED)

We tried this earlier but couldn't decode the entries. Let me try again with a smarter approach — hook the TDF decoder DURING PreAuth response processing and log every tag it looks up. This tells us the exact tag names the game's decoder expects.

Specifically, hook `FUN_1479ab1e0` (TDF type registration) which is called with the tag hash + field name during static initialization. The registrations for PreAuthResponse members will give us all 14 tag+offset mappings.

### Path B: Migrate to Zamboni's C# server (1-2 days of work)

Fork Zamboni14Legacy, adapt for FIFA 17 PC:
- Change PreAuth response identifiers to fifa-2017-pc
- Replace Ps3LoginAsync with SilentLoginAsync (PC uses tokens, not PS3 tickets)
- Port our Origin IPC server to .NET or run in parallel as Node.js
- Add CardHouseComponent (FUT) stub

Risk: Even with the proven BlazeSDK C# encoder, FIFA 17's extra field at +0x120 might still be an issue.

### Path C: Hook the game's internal TDF DECODER (nuclear option)

Use Frida to hook the game's TDF decoder at runtime. When it tries to decode the PreAuth response, log exactly what tags it looks for and writes where. This tells us the COMPLETE schema FIFA 17 expects, without guessing.

Functions to hook:
- `FUN_1479ab1e0` — TDF type registration (log all tag/offset pairs)
- `FUN_146df4ff0` — one of the TDF decode methods
- The PreAuthResponse decoder at `LAB_146df24e0`

## Recommendation

**Start with Path A.** It's a small, targeted Frida script that instruments the TDF type registration. This gives us authoritative info about FIFA 17's PreAuthResponse schema WITHOUT needing to guess.

Once we know what field at +0x120 is, we can either add it to our Node.js encoder OR migrate to Zamboni (if still needed).

## Immediate Action

Write `frida_dump_tdf_schema.js` that hooks `FUN_1479ab1e0` at module load and logs every registered TDF type with its member info table. Run once, get the complete schema.
