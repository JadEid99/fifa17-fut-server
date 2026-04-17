/**
 * Fake Origin IPC Server v5 — GROUND TRUTH from Wireshark capture
 *
 * Confirmed protocol via known-plaintext attack on captured encrypted traffic:
 *   Session key seed = ASCII charCodes of first 2 chars of ChallengeAccepted response
 *   (NOT from ChallengeResponse as origin-sdk v10.6 does)
 *   Session key then derived via: rng(7), newSeed = rng.next() + seed, then 16 rng bytes
 *
 * Verified working decryption of every message in origin_capture.pcapng.
 *
 * Response formats are EXACT copies from the captured ground truth.
 */

import net from 'net';
import crypto from 'crypto';

const PORT = 3216;
const DEFAULT_KEY = Buffer.from([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);

// Fake persona — FIFA 17 uses PersonaId / UserId to proceed past login
// Using values from a real Origin account (from Wireshark capture) — the game may
// validate these against certain ranges/formats.
const FAKE_PERSONA_ID = '33068179';
const FAKE_USER_ID = '33068179';
const FAKE_PERSONA_NAME = 'Player';
const FAKE_AUTH_CODE = 'QVV0aEZha2VBdXRoQ29kZUZvckZJRkExN1NlcnZlcg==';

function createRng(seed) {
  let s = seed >>> 0;
  return {
    next() { s = ((s * 214013) + 2531011) >>> 0; return (s >>> 16) & 32767; },
    setSeed(ns) { s = ns >>> 0; }
  };
}

function deriveKey(seed) {
  const key = Buffer.alloc(16);
  if (seed === 0) {
    for (let i = 0; i < 16; i++) key[i] = i;
    return key;
  }
  const rng = createRng(7);
  const newSeed = (rng.next() + seed) >>> 0;
  rng.setSeed(newSeed);
  for (let i = 0; i < 16; i++) key[i] = rng.next() & 0xFF;
  return key;
}

function aesEncrypt(plaintext, key) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  c.setAutoPadding(true);
  return Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
}

function aesDecrypt(ciphertext, key) {
  const d = crypto.createDecipheriv('aes-128-ecb', key, null);
  d.setAutoPadding(true);
  return Buffer.concat([d.update(ciphertext), d.final()]).toString('utf8');
}

function handle(socket) {
  const addr = socket.remoteAddress + ':' + socket.remotePort;
  console.log('[Origin] ' + addr + ' connected');

  let buffer = Buffer.alloc(0);
  let sessionKey = null;
  let msgCount = 0;

  // Server always sends Challenge first (matches Wireshark ground truth exactly)
  const challengeKey = crypto.randomBytes(16).toString('hex');
  const challengeXml = '<LSX><Event sender="EALS"><Challenge key="' + challengeKey + '" build="release" version="10,4,13,6637"/></Event></LSX>';
  socket.write(challengeXml + '\0');
  console.log('[Origin] -> Challenge (key=' + challengeKey + ')');

  socket.on('data', (data) => {
    buffer = Buffer.concat([buffer, data]);
    while (true) {
      const nullIdx = buffer.indexOf(0);
      if (nullIdx === -1) break;
      const msg = buffer.slice(0, nullIdx).toString('utf8').trim();
      buffer = buffer.slice(nullIdx + 1);
      if (!msg) continue;
      msgCount++;
      handleMessage(socket, msg);
    }
  });

  function handleMessage(sock, msg) {
    // Plain XML (ChallengeResponse) or hex-encoded ciphertext?
    if (msg.startsWith('<LSX>')) {
      if (msg.includes('ChallengeResponse')) {
        return handleChallengeResponse(sock, msg);
      }
      console.log('[Origin] #' + msgCount + ' unexpected plain: ' + msg.substring(0, 120));
      return;
    }
    if (!sessionKey) {
      console.log('[Origin] #' + msgCount + ' encrypted-but-no-session-key, dropping');
      return;
    }
    if (!/^[0-9a-fA-F]+$/.test(msg) || msg.length % 32 !== 0) {
      console.log('[Origin] #' + msgCount + ' bad hex, len=' + msg.length);
      return;
    }
    try {
      const plain = aesDecrypt(Buffer.from(msg, 'hex'), sessionKey);
      handleRequest(sock, plain);
    } catch (e) {
      console.log('[Origin] decrypt failed: ' + e.message);
    }
  }

  function handleChallengeResponse(sock, xml) {
    const idMatch = xml.match(/id="([^"]+)"/);
    const keyMatch = xml.match(/ChallengeResponse[^>]*key="([^"]+)"/);
    if (!keyMatch) {
      console.log('[Origin] missing key in ChallengeResponse');
      return;
    }
    const id = idMatch ? idMatch[1] : '1';
    const clientKey = keyMatch[1];

    // Encrypt client's key with default key → that's our ChallengeAccepted response field
    const enc = crypto.createCipheriv('aes-128-ecb', DEFAULT_KEY, null);
    enc.setAutoPadding(true);
    const accepted = Buffer.concat([enc.update(clientKey, 'utf8'), enc.final()]).toString('hex');

    // Session key: seed = ASCII bytes of first 2 chars of `accepted`
    const seed = (accepted.charCodeAt(0) << 8) | accepted.charCodeAt(1);
    sessionKey = deriveKey(seed);
    console.log('[Origin] session seed=' + seed + ' key=' + sessionKey.toString('hex'));

    const xmlOut = '<LSX><Response id="' + id + '" sender="EALS"><ChallengeAccepted response="' + accepted + '"/></Response></LSX>';
    sock.write(xmlOut + '\0');
    console.log('[Origin] -> ChallengeAccepted (session ready)');
    
    // CRITICAL: FIFA 17 waits for a server-pushed <Login IsLoggedIn="true"/> event.
    // Without it, the IsLoggedIn internal flag stays false and the game sends Logout
    // to the Blaze server instead of attempting to authenticate.
    // Found via ghidra: FUN_147102800 dispatches on <Login> tag with sender="EALS"
    // and calls thunk_FUN_147138640 which sets IsLoggedIn=true on the Origin SDK object.
    //
    // Delay slightly so the client processes ChallengeAccepted first and has the session key.
    setTimeout(() => {
      if (sock.destroyed) return;
      const loginEvent = '<LSX><Event sender="EALS"><Login IsLoggedIn="true"/></Event></LSX>';
      send(sock, loginEvent);
      console.log('[Origin] -> pushed Login event (IsLoggedIn=true)');
    }, 50);
  }

  function send(sock, xml) {
    const cipher = aesEncrypt(xml, sessionKey);
    sock.write(cipher.toString('hex') + '\0');
    console.log('[Origin] -> ENC: ' + xml.substring(0, 140));
  }

  function handleRequest(sock, xml) {
    console.log('[Origin] <- DEC: ' + xml.substring(0, 200));
    const idMatch = xml.match(/id="(\d+)"/);
    const id = idMatch ? idMatch[1] : '0';
    let out = null;

    if (xml.includes('GetAuthCode')) {
      // Return real-looking auth code — FIFA 17 will forward this to Blaze
      out = '<LSX><Response id="' + id + '" sender="EbisuSDK"><AuthCode Code="' + FAKE_AUTH_CODE + '" Type="0"/></Response></LSX>';
    }
    else if (xml.includes('GetConfig')) {
      out = '<LSX><Response id="' + id + '" sender="EbisuSDK"><GetConfigResponse Config="false"/></Response></LSX>';
    }
    else if (xml.includes('GetProfile')) {
      out = '<LSX><Response id="' + id + '" sender="EbisuSDK"><GetProfileResponse IsSubscriber="true" PersonaId="' + FAKE_PERSONA_ID + '" AvatarId="" Country="US" CommerceCountry="US" GeoCountry="US" UserId="' + FAKE_USER_ID + '" Persona="' + FAKE_PERSONA_NAME + '" IsUnderAge="false" CommerceCurrency="USD"/></Response></LSX>';
    }
    else if (xml.includes('GetSetting')) {
      const m = xml.match(/SettingId="([^"]+)"/);
      const sid = m ? m[1] : '';
      const vals = {
        'ENVIRONMENT': 'production',
        'IS_IGO_ENABLED': 'false',
        'IS_IGO_AVAILABLE': 'false',
        'LANGUAGE': 'en_US'
      };
      const value = vals[sid] || '';
      out = '<LSX><Response id="' + id + '" sender=""><GetSettingResponse Setting="' + value + '"/></Response></LSX>';
    }
    else if (xml.includes('GetGameInfo')) {
      const m = xml.match(/GameInfoId="([^"]+)"/);
      const gid = m ? m[1] : '';
      const vals = {
        'FREETRIAL': 'false',
        'LANGUAGES': 'ar_SA,cs_CZ,da_DK,de_DE,en_US,es_ES,es_MX,fr_FR,it_IT,nl_NL,no_NO,pl_PL,pt_BR,pt_PT,ru_RU,sv_SE,tr_TR,zh_TW',
        'FULLGAME_PURCHASED': 'true',
        'FULLGAME_RELEASED': 'true',
        'UP_TO_DATE': 'true'
      };
      const value = vals[gid] !== undefined ? vals[gid] : 'true';
      out = '<LSX><Response id="' + id + '" sender=""><GetGameInfoResponse GameInfo="' + value + '"/></Response></LSX>';
    }
    else if (xml.includes('GetInternetConnectedState')) {
      // "1" = connected (wireshark showed 0 but game was offline there)
      out = '<LSX><Response id="' + id + '" sender=""><InternetConnectedState connected="1"/></Response></LSX>';
    }
    else if (xml.includes('IsProgressiveInstallationAvailable')) {
      out = '<LSX><Response id="' + id + '" sender=""><IsProgressiveInstallationAvailableResponse ItemId="" Available="false"/></Response></LSX>';
    }
    else if (xml.includes('SetDownloaderUtilization') || xml.includes('SetPresence')) {
      out = '<LSX><Response id="' + id + '" sender=""><ErrorSuccess Code="0" Description=""/></Response></LSX>';
    }
    else if (xml.includes('QueryImage')) {
      out = '<LSX><Response id="' + id + '" sender=""><QueryImageResponse ImageUrl=""/></Response></LSX>';
    }
    else {
      console.log('[Origin] UNKNOWN request -> ErrorSuccess');
      out = '<LSX><Response id="' + id + '" sender=""><ErrorSuccess Code="0" Description=""/></Response></LSX>';
    }
    send(sock, out);
  }

  socket.on('close', () => console.log('[Origin] ' + addr + ' closed (' + msgCount + ' msgs)'));
  socket.on('error', (e) => console.log('[Origin] ' + addr + ' err: ' + e.message));
}

const server = net.createServer(handle);
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.log('[Origin] Port ' + PORT + ' in use, retry in 2s');
    setTimeout(() => { server.close(); server.listen(PORT, '127.0.0.1'); }, 2000);
  } else {
    console.log('[Origin] server err: ' + e.message);
  }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log('[Origin] IPC server listening on 127.0.0.1:' + PORT);
  console.log('[Origin] session key algorithm: seed = ASCII(accepted[0..1]), key = deriveKey(seed)');
});
