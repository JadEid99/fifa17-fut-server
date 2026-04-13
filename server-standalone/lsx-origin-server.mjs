/**
 * LSX Origin SDK Server for FIFA 17
 * 
 * Two modes:
 * 
 * STANDALONE (default): Replaces STP emulator entirely on port 4216.
 *   Handles the LSX Challenge handshake, sends Login event, handles GetAuthCode.
 *   For unknown requests (Denuvo), responds with ErrorSuccess.
 *   Usage: node lsx-origin-server.mjs
 *   NOTE: You must STOP the STP emulator first, or rename/remove stp-origin_emu.dll
 * 
 * PROXY: Sits between game and STP emulator (game→4216→us→4217→STP).
 *   Sniffs the Challenge handshake to derive the session key.
 *   Injects Login events and handles GetAuthCode.
 *   Forwards all other traffic to/from STP.
 *   Usage: node lsx-origin-server.mjs --proxy
 *   NOTE: You must change STP to listen on port 4217 first.
 * 
 * Protocol (from origin-sdk Rust crate):
 *   1. Server→Client: Challenge event (plaintext XML\0)
 *   2. Client→Server: ChallengeResponse request (plaintext XML\0)
 *   3. Server→Client: ChallengeAccepted response (plaintext XML\0)
 *   4. All subsequent: hex-encoded AES-128-ECB encrypted XML\0
 *   5. Server→Client: Login event (IsLoggedIn=true) — tells game "Origin is logged in"
 */

import net from 'net';
import crypto from 'crypto';

const LISTEN_PORT = 4216;
const STP_PORT = 4217;
const PROXY_MODE = process.argv.includes('--proxy');

// ============================================================
// Crypto (matches origin-sdk/src/crypto.rs + random.rs exactly)
// ============================================================

const RAND_MAX = 32767;
const MULTIPLIER = 214013;
const INCREMENT = 2531011;
const DEFAULT_SEED = 7;

class Random {
  constructor(seed) { this.seed = seed >>> 0; }
  next() {
    this.seed = ((this.seed * MULTIPLIER) + INCREMENT) >>> 0;
    return (this.seed >>> 16) & RAND_MAX;
  }
  setSeed(seed) { this.seed = seed >>> 0; }
}

function generateKey(seed) {
  const key = Buffer.alloc(16);
  if (seed === 0) {
    for (let i = 0; i < 16; i++) key[i] = i;
  } else {
    const rng = new Random(DEFAULT_SEED);
    const newSeed = (rng.next() + seed) >>> 0;
    rng.setSeed(newSeed);
    for (let i = 0; i < 16; i++) key[i] = rng.next() & 0xFF;
  }
  return key;
}

function aesEncrypt(key, plaintext) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
}

function aesDecrypt(key, ciphertext) {
  const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
}

// ============================================================
// Logging
// ============================================================

function log(msg) {
  const ts = new Date().toISOString().substring(11, 23);
  console.log(`[${ts}] [LSX] ${msg}`);
}

// ============================================================
// XML Response Builders
// ============================================================

function buildChallengeEvent(key) {
  return `<LSX><Event sender="EALS"><Challenge key="${key}" version="3" build="10.6.1.8"/></Event></LSX>`;
}

function buildChallengeAccepted(id, response) {
  return `<LSX><Response id="${id}" sender="EALS"><ChallengeAccepted response="${response}"/></Response></LSX>`;
}

function buildLoginEvent() {
  return `<LSX><Event sender="EbisuSDK"><Login IsLoggedIn="true" UserIndex="0" LoginReasonCode="ALREADY_ONLINE"/></Event></LSX>`;
}

function buildOnlineStatusEvent() {
  return `<LSX><Event sender="EbisuSDK"><OnlineStatusEvent IsOnline="true"/></Event></LSX>`;
}

function buildAuthCodeResponse(id, code) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><AuthCode value="${code}"/></Response></LSX>`;
}

function buildAuthTokenResponse(id, token) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><AuthToken value="${token}"/></Response></LSX>`;
}

function buildErrorSuccess(id) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><ErrorSuccess/></Response></LSX>`;
}

function buildProfileResponse(id) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><GetProfileResponse UserId="33068179" PersonaId="33068179" DisplayName="Player" EAID="player@fut.local" DateOfBirth="1990-01-01" Country="US" Language="en" Locale="en_US"/></Response></LSX>`;
}

function buildInternetConnected(id) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><InternetConnectedState IsConnected="true"/></Response></LSX>`;
}

function buildUtcTime(id) {
  return `<LSX><Response id="${id}" sender="EbisuSDK"><GetUtcTimeResponse UtcTimeSecs="${Math.floor(Date.now()/1000)}"/></Response></LSX>`;
}

// ============================================================
// Message sending helpers
// ============================================================

function sendRaw(socket, xml) {
  socket.write(Buffer.concat([Buffer.from(xml, 'utf-8'), Buffer.from([0x00])]));
  log(`SENT raw: ${xml.substring(0, 150)}`);
}

function sendEncrypted(socket, xml, key) {
  const enc = aesEncrypt(key, xml);
  socket.write(Buffer.concat([Buffer.from(enc.toString('hex'), 'utf-8'), Buffer.from([0x00])]));
  log(`SENT enc: ${xml.substring(0, 150)}`);
}

// ============================================================
// STANDALONE MODE: Full LSX server replacing STP
// ============================================================

function handleStandaloneConnection(socket) {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  log(`Client connected: ${addr}`);

  let state = 'CHALLENGE_SENT';
  let challengeKey = crypto.randomBytes(8).toString('hex');
  let initialKey = generateKey(0); // seed=0 → [0,1,2,...,15]
  let sessionKey = null;
  let msgBuf = Buffer.alloc(0);
  let loginSent = false;

  // Send Challenge immediately
  sendRaw(socket, buildChallengeEvent(challengeKey));

  socket.on('data', (data) => {
    msgBuf = Buffer.concat([msgBuf, data]);
    processMessages();
  });

  function processMessages() {
    let idx;
    while ((idx = msgBuf.indexOf(0x00)) !== -1) {
      const raw = msgBuf.subarray(0, idx);
      msgBuf = msgBuf.subarray(idx + 1);
      if (raw.length === 0) continue;

      const str = raw.toString('utf-8');

      if (state === 'CHALLENGE_SENT') {
        log(`RECV raw: ${str.substring(0, 200)}`);
        processChallengeResponse(str);
      } else if (state === 'ESTABLISHED') {
        try {
          const cipherBytes = Buffer.from(str, 'hex');
          const xml = aesDecrypt(sessionKey, cipherBytes);
          log(`RECV enc: ${xml.substring(0, 200)}`);
          processRequest(xml);
        } catch (e) {
          log(`Decrypt error: ${e.message} (raw: ${str.substring(0, 60)})`);
        }
      }
    }
  }

  function processChallengeResponse(xml) {
    const idMatch = xml.match(/id="([^"]+)"/);
    const respMatch = xml.match(/response="([^"]+)"/);
    const keyMatch = xml.match(/ key="([^"]+)"/);
    const contentMatch = xml.match(/<ContentId>([^<]*)<\/ContentId>/);
    const titleMatch = xml.match(/<Title>([^<]*)<\/Title>/);
    const verMatch = xml.match(/<Version>([^<]*)<\/Version>/);

    const id = idMatch?.[1] || '0';
    const clientResp = respMatch?.[1] || '';
    const clientKey = keyMatch?.[1] || '';
    log(`ChallengeResponse: id=${id} key=${clientKey} content=${contentMatch?.[1]} title=${titleMatch?.[1]} ver=${verMatch?.[1]}`);

    // Compute our response (encrypt challengeKey with initial key)
    const encrypted = aesEncrypt(initialKey, challengeKey);
    const ourResponse = encrypted.toString('hex');

    // Derive session key from the response string
    // Both sides use the same algorithm, so they should match
    if (clientResp === ourResponse) {
      log('Challenge responses match');
      const seed = (ourResponse.charCodeAt(0) << 8) | ourResponse.charCodeAt(1);
      sessionKey = generateKey(seed);
    } else {
      log(`Responses differ — using client's response to derive key`);
      log(`  Ours:   ${ourResponse.substring(0, 32)}`);
      log(`  Client: ${clientResp.substring(0, 32)}`);
      // Use client's response to derive key (they encrypted with the same initial key)
      const seed = (clientResp.charCodeAt(0) << 8) | clientResp.charCodeAt(1);
      sessionKey = generateKey(seed);
    }
    log(`Session key: ${sessionKey.toString('hex')}`);

    // Send ChallengeAccepted
    sendRaw(socket, buildChallengeAccepted(id, ourResponse));
    state = 'ESTABLISHED';
    log('=== Handshake complete ===');

    // Send Login event after a short delay
    setTimeout(() => {
      if (!loginSent) {
        sendEncrypted(socket, buildLoginEvent(), sessionKey);
        loginSent = true;
        log('>>> Login event sent (IsLoggedIn=true) <<<');
      }
      // Also send online status
      setTimeout(() => {
        sendEncrypted(socket, buildOnlineStatusEvent(), sessionKey);
      }, 100);
    }, 300);
  }

  function processRequest(xml) {
    const reqMatch = xml.match(/<Request\s+id="(\d+)"/);
    if (!reqMatch) {
      log(`Non-request: ${xml.substring(0, 80)}`);
      return;
    }
    const id = reqMatch[1];

    // Determine request type and respond
    let resp = null;

    if (xml.includes('<GetAuthCode')) {
      const uid = xml.match(/UserId="(\d+)"/)?.[1];
      const cid = xml.match(/ClientId="([^"]+)"/)?.[1];
      const scope = xml.match(/Scope="([^"]+)"/)?.[1];
      log(`>>> GetAuthCode: userId=${uid} clientId=${cid} scope=${scope} <<<`);
      const code = `QUOxNjoxNjpGSUZBMTdfUEM6${crypto.randomBytes(32).toString('base64url')}`;
      resp = buildAuthCodeResponse(id, code);
    }
    else if (xml.includes('<GetAuthToken'))  { log('GetAuthToken'); resp = buildAuthTokenResponse(id, `Bearer ${crypto.randomBytes(48).toString('base64url')}`); }
    else if (xml.includes('<GetConfig'))     { log('GetConfig'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetConfigResponse/></Response></LSX>`; }
    else if (xml.includes('<GetInternetConnectedState')) { log('GetInternetConnectedState'); resp = buildInternetConnected(id); }
    else if (xml.includes('<GetProfile'))    { log('GetProfile'); resp = buildProfileResponse(id); }
    else if (xml.includes('<GoOnline'))      { log('GoOnline'); resp = buildErrorSuccess(id); }
    else if (xml.includes('<GetUtcTime'))    { log('GetUtcTime'); resp = buildUtcTime(id); }
    else if (xml.includes('<SetPresence'))   { log('SetPresence'); resp = buildErrorSuccess(id); }
    else if (xml.includes('<SubscribePresence')) { log('SubscribePresence'); resp = buildErrorSuccess(id); }
    else if (xml.includes('<GetPresence'))   { log('GetPresence'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetPresenceResponse/></Response></LSX>`; }
    else if (xml.includes('<QueryEntitlements')) { log('QueryEntitlements'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><QueryEntitlementsResponse/></Response></LSX>`; }
    else if (xml.includes('<QueryFriends'))  { log('QueryFriends'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><QueryFriendsResponse/></Response></LSX>`; }
    else if (xml.includes('<GetAllGameInfo') || xml.includes('<GetGameInfo')) { log('GetGameInfo'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetAllGameInfoResponse/></Response></LSX>`; }
    else if (xml.includes('<Logout'))        { log('Logout'); resp = buildErrorSuccess(id); }
    else if (xml.includes('<GetBlockList'))   { log('GetBlockList'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetBlockListResponse/></Response></LSX>`; }
    else if (xml.includes('<GetPresenceVisibility')) { log('GetPresenceVisibility'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetPresenceVisibilityResponse/></Response></LSX>`; }
    else if (xml.includes('<RequestLicense')) { log('RequestLicense'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><RequestLicenseResponse Granted="true"/></Response></LSX>`; }
    else if (xml.includes('<GetSetting'))    { log('GetSetting'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetSettingResponse/></Response></LSX>`; }
    else if (xml.includes('<GetSettings'))   { log('GetSettings'); resp = `<LSX><Response id="${id}" sender="EbisuSDK"><GetSettingsResponse/></Response></LSX>`; }
    else {
      const typeMatch = xml.match(/<Request[^>]*><(\w+)/);
      log(`Unknown request: ${typeMatch?.[1] || 'unknown'}`);
      resp = buildErrorSuccess(id);
    }

    if (resp) sendEncrypted(socket, resp, sessionKey);
  }

  socket.on('close', () => log(`Disconnected: ${addr}`));
  socket.on('error', (e) => log(`Error: ${e.message}`));
}

// ============================================================
// PROXY MODE: Sit between game and STP, inject auth
// ============================================================

function handleProxyConnection(gameSocket) {
  const addr = `${gameSocket.remoteAddress}:${gameSocket.remotePort}`;
  log(`[PROXY] Game connected: ${addr}`);

  let state = 'HANDSHAKE';
  let challengeKey = null;
  let sessionKey = null;
  let loginSent = false;
  let gameBuf = Buffer.alloc(0);
  let stpBuf = Buffer.alloc(0);

  // Connect to real STP emulator
  const stpSocket = net.createConnection(STP_PORT, '127.0.0.1', () => {
    log('[PROXY] Connected to STP emulator');
  });

  stpSocket.on('error', (e) => {
    log(`[PROXY] STP error: ${e.message}`);
    gameSocket.destroy();
  });

  // STP → Game: intercept to sniff handshake
  stpSocket.on('data', (data) => {
    stpBuf = Buffer.concat([stpBuf, data]);

    if (state === 'HANDSHAKE') {
      // During handshake, sniff the Challenge from STP
      let idx;
      while ((idx = stpBuf.indexOf(0x00)) !== -1) {
        const msg = stpBuf.subarray(0, idx).toString('utf-8');
        stpBuf = stpBuf.subarray(idx + 1);

        log(`[PROXY] STP→Game: ${msg.substring(0, 150)}`);

        // Sniff Challenge key
        const keyMatch = msg.match(/<Challenge\s+key="([^"]+)"/);
        if (keyMatch) {
          challengeKey = keyMatch[1];
          log(`[PROXY] Captured challenge key: ${challengeKey}`);
        }

        // Sniff ChallengeAccepted
        if (msg.includes('<ChallengeAccepted')) {
          state = 'ESTABLISHED';
          log('[PROXY] Handshake complete, now intercepting encrypted traffic');

          // After handshake, inject Login event
          setTimeout(() => {
            if (sessionKey && !loginSent) {
              sendEncrypted(gameSocket, buildLoginEvent(), sessionKey);
              loginSent = true;
              log('[PROXY] >>> Injected Login event <<<');
              setTimeout(() => {
                sendEncrypted(gameSocket, buildOnlineStatusEvent(), sessionKey);
              }, 100);
            }
          }, 500);
        }

        // Forward to game
        gameSocket.write(Buffer.concat([Buffer.from(msg, 'utf-8'), Buffer.from([0x00])]));
      }
    } else {
      // Post-handshake: forward encrypted data, but also try to decode it
      let idx;
      while ((idx = stpBuf.indexOf(0x00)) !== -1) {
        const msg = stpBuf.subarray(0, idx);
        stpBuf = stpBuf.subarray(idx + 1);

        if (sessionKey && msg.length > 0) {
          try {
            const xml = aesDecrypt(sessionKey, Buffer.from(msg.toString('utf-8'), 'hex'));
            log(`[PROXY] STP→Game (dec): ${xml.substring(0, 150)}`);
          } catch (e) { /* ignore decode errors */ }
        }

        // Forward to game
        gameSocket.write(Buffer.concat([msg, Buffer.from([0x00])]));
      }
    }
  });

  // Game → STP: intercept to sniff handshake and handle auth requests
  gameSocket.on('data', (data) => {
    gameBuf = Buffer.concat([gameBuf, data]);

    if (state === 'HANDSHAKE') {
      let idx;
      while ((idx = gameBuf.indexOf(0x00)) !== -1) {
        const msg = gameBuf.subarray(0, idx).toString('utf-8');
        gameBuf = gameBuf.subarray(idx + 1);

        log(`[PROXY] Game→STP: ${msg.substring(0, 150)}`);

        // Sniff ChallengeResponse to derive session key
        const respMatch = msg.match(/response="([^"]+)"/);
        if (respMatch && challengeKey) {
          const clientResp = respMatch[1];
          const seed = (clientResp.charCodeAt(0) << 8) | clientResp.charCodeAt(1);
          sessionKey = generateKey(seed);
          log(`[PROXY] Derived session key: ${sessionKey.toString('hex')}`);
        }

        // Forward to STP
        stpSocket.write(Buffer.concat([Buffer.from(msg, 'utf-8'), Buffer.from([0x00])]));
      }
    } else {
      // Post-handshake: decode, check if it's an auth request we should handle
      let idx;
      while ((idx = gameBuf.indexOf(0x00)) !== -1) {
        const rawMsg = gameBuf.subarray(0, idx);
        gameBuf = gameBuf.subarray(idx + 1);

        if (rawMsg.length === 0) continue;

        let handled = false;
        if (sessionKey) {
          try {
            const xml = aesDecrypt(sessionKey, Buffer.from(rawMsg.toString('utf-8'), 'hex'));
            log(`[PROXY] Game→STP (dec): ${xml.substring(0, 150)}`);

            // Intercept auth-related requests
            if (xml.includes('<GetAuthCode') || xml.includes('<GetAuthToken') ||
                xml.includes('<GoOnline') || xml.includes('<GetProfile') ||
                xml.includes('<GetInternetConnectedState')) {
              log('[PROXY] Intercepting auth request');
              handleProxyRequest(gameSocket, xml);
              handled = true;
            }
          } catch (e) { /* not decodable, forward as-is */ }
        }

        if (!handled) {
          // Forward to STP
          stpSocket.write(Buffer.concat([rawMsg, Buffer.from([0x00])]));
        }
      }
    }
  });

  function handleProxyRequest(sock, xml) {
    const reqMatch = xml.match(/<Request\s+id="(\d+)"/);
    if (!reqMatch) return;
    const id = reqMatch[1];

    let resp = null;
    if (xml.includes('<GetAuthCode')) {
      const code = `QUOxNjoxNjpGSUZBMTdfUEM6${crypto.randomBytes(32).toString('base64url')}`;
      resp = buildAuthCodeResponse(id, code);
      log(`[PROXY] >>> Responding to GetAuthCode <<<`);
    }
    else if (xml.includes('<GetAuthToken')) {
      resp = buildAuthTokenResponse(id, `Bearer ${crypto.randomBytes(48).toString('base64url')}`);
    }
    else if (xml.includes('<GoOnline'))     { resp = buildErrorSuccess(id); }
    else if (xml.includes('<GetProfile'))   { resp = buildProfileResponse(id); }
    else if (xml.includes('<GetInternetConnectedState')) { resp = buildInternetConnected(id); }

    if (resp) sendEncrypted(sock, resp, sessionKey);
  }

  gameSocket.on('close', () => { log(`[PROXY] Game disconnected`); stpSocket.destroy(); });
  gameSocket.on('error', (e) => { log(`[PROXY] Game error: ${e.message}`); stpSocket.destroy(); });
  stpSocket.on('close', () => { log(`[PROXY] STP disconnected`); gameSocket.destroy(); });
}

// ============================================================
// Server startup
// ============================================================

const server = net.createServer(PROXY_MODE ? handleProxyConnection : handleStandaloneConnection);

server.listen(LISTEN_PORT, '127.0.0.1', () => {
  log(`=== LSX Origin SDK Server ===`);
  log(`Mode: ${PROXY_MODE ? 'PROXY (game→4216→us→4217→STP)' : 'STANDALONE (replacing STP)'}`);
  log(`Listening on port ${LISTEN_PORT}`);
  if (PROXY_MODE) {
    log(`Forwarding to STP on port ${STP_PORT}`);
  }
  log('Waiting for game connection...');
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    log(`ERROR: Port ${LISTEN_PORT} in use!`);
    if (!PROXY_MODE) {
      log('The STP emulator is probably running. Options:');
      log('  1. Stop/rename stp-origin_emu.dll and restart the game');
      log('  2. Use --proxy mode: change STP to port 4217, then run with --proxy');
    }
    process.exit(1);
  }
  log(`Server error: ${e.message}`);
});
