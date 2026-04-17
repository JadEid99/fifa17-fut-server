/**
 * Fake Origin IPC Server v4 — Correct LSX Protocol
 * 
 * Based on github.com/ploxxxy/origin-sdk protocol specification.
 * 
 * Protocol:
 * 1. Server sends Challenge as EVENT: <LSX><Event><Challenge key="hex"/></Event></LSX>\0
 * 2. Client encrypts key with AES-128-ECB (default key), sends ChallengeResponse
 * 3. Server sends ChallengeAccepted
 * 4. All subsequent messages are AES-128-ECB encrypted + hex-encoded
 * 5. Client sends GetAuthCode, server responds with AuthCode
 */

import net from 'net';
import crypto from 'crypto';

const PORT = 3216;

// AES-128-ECB crypto (matches Origin SDK exactly)
const DEFAULT_KEY = Buffer.from([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);

// Custom PRNG matching Origin SDK's Random class
function createRng(seed) {
  let s = seed >>> 0;
  return {
    next: function() {
      s = ((s * 214013) + 2531011) >>> 0;
      return (s >>> 16) & 32767;
    },
    setSeed: function(newSeed) { s = newSeed >>> 0; }
  };
}

function deriveKey(seed) {
  var key = Buffer.alloc(16);
  if (seed === 0) {
    for (var i = 0; i < 16; i++) key[i] = i;
  } else {
    var rng = createRng(7);
    var newSeed = (rng.next() + seed) >>> 0;
    rng.setSeed(newSeed);
    for (var i = 0; i < 16; i++) key[i] = rng.next() & 0xFF;
  }
  return key;
}

function aesEncrypt(plaintext, key) {
  // AES-128-ECB with PKCS7 padding
  var cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}

function aesDecrypt(ciphertext, key) {
  var decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function createHandler(socket) {
  var addr = socket.remoteAddress + ':' + socket.remotePort;
  console.log('[Origin] Connected: ' + addr);
  
  var buffer = '';
  var msgCount = 0;
  var challengeKey = crypto.randomBytes(16).toString('hex');
  var sessionKey = null;
  
  // Step 1: Send Challenge as EVENT with sender="EALS"
  var challengeXml = '<LSX><Event sender="EALS"><Challenge key="' + challengeKey + '" version="3"/></Event></LSX>';
  console.log('[Origin] Sending Challenge: ' + challengeXml);
  socket.write(challengeXml + '\0');
  
  socket.on('data', function(data) {
    buffer += data.toString('utf8');
    
    // Split on null bytes
    var parts = buffer.split('\0');
    buffer = parts.pop(); // last part is incomplete
    
    for (var i = 0; i < parts.length; i++) {
      var msg = parts[i].trim();
      if (msg.length === 0) continue;
      msgCount++;
      
      console.log('[Origin] #' + msgCount + ' raw: ' + msg.substring(0, 200));
      
      // Check if this is the ChallengeResponse (plaintext XML)
      if (msg.indexOf('<LSX>') === 0 && msg.indexOf('ChallengeResponse') !== -1) {
        handleChallengeResponse(socket, msg);
      }
      // Otherwise it's encrypted (hex-encoded)
      else if (sessionKey && /^[0-9a-f]+$/i.test(msg)) {
        try {
          var cipherBytes = Buffer.from(msg, 'hex');
          var xml = aesDecrypt(cipherBytes, sessionKey);
          console.log('[Origin] Decrypted: ' + xml.substring(0, 300));
          handleDecryptedMessage(socket, xml);
        } catch(e) {
          console.log('[Origin] Decrypt error: ' + e.message);
        }
      }
      else {
        console.log('[Origin] Unrecognized message format');
      }
    }
  });
  
  function handleChallengeResponse(sock, xml) {
    console.log('[Origin] *** CHALLENGE RESPONSE RECEIVED ***');
    
    // Extract the response (encrypted challenge key, hex-encoded)
    var respMatch = xml.match(/response="([^"]+)"/);
    var keyMatch = xml.match(/key="([^"]+)"/);
    
    if (respMatch) {
      var responseHex = respMatch[1];
      console.log('[Origin] Response hex: ' + responseHex.substring(0, 64));
      
      // Derive session key from the response
      // First 2 bytes of hex string as ASCII → u16 seed
      var byte0 = responseHex.charCodeAt(0);
      var byte1 = responseHex.charCodeAt(1);
      var seed = (byte0 << 8) | byte1;
      sessionKey = deriveKey(seed);
      console.log('[Origin] Session seed: ' + seed + ', key: ' + sessionKey.toString('hex'));
    }
    
    // Send ChallengeAccepted
    var accepted = '<LSX><Response id="0"><ChallengeAccepted><response>' + (respMatch ? respMatch[1] : '') + '</response></ChallengeAccepted></Response></LSX>';
    console.log('[Origin] Sending ChallengeAccepted');
    sock.write(accepted + '\0');
  }
  
  function handleDecryptedMessage(sock, xml) {
    // Extract request type and id
    var idMatch = xml.match(/id="(\d+)"/);
    var id = idMatch ? idMatch[1] : '0';
    
    var response = null;
    
    if (xml.indexOf('GetAuthCode') !== -1) {
      console.log('[Origin] *** AUTH CODE REQUEST ***');
      response = '<LSX><Response id="' + id + '"><AuthCode Code="FAKEAUTHCODE1234567890" Type="0"/></Response></LSX>';
    }
    else if (xml.indexOf('GetConfig') !== -1) {
      response = '<LSX><Response id="' + id + '"><GetConfigResponse/></Response></LSX>';
    }
    else if (xml.indexOf('GetProfile') !== -1) {
      response = '<LSX><Response id="' + id + '"><GetProfileResponse PersonaId="1000000001" UserId="2000000001" DisplayName="Player1" DateOfBirth="1990-01-01" Country="US" Language="en_US" index="0"/></Response></LSX>';
    }
    else if (xml.indexOf('GetSetting') !== -1) {
      var m = xml.match(/SettingId="([^"]+)"/);
      var sid = m ? m[1] : '';
      var vals = {'ENVIRONMENT':'prod','IS_IGO_ENABLED':'0','LANGUAGE':'en_US'};
      response = '<LSX><Response id="' + id + '"><GetSettingResponse SettingId="' + sid + '" Value="' + (vals[sid]||'') + '"/></Response></LSX>';
    }
    else if (xml.indexOf('GetGameInfo') !== -1 || xml.indexOf('GetAllGameInfo') !== -1) {
      response = '<LSX><Response id="' + id + '"><GetAllGameInfoResponse UpToDate="true" Languages="en_US" FreeTrial="false" FullGamePurchased="true" FullGameReleased="true" InstalledLanguage="en_US"/></Response></LSX>';
    }
    else if (xml.indexOf('SetPresence') !== -1 || xml.indexOf('SetDownloaderUtilization') !== -1) {
      response = '<LSX><Response id="' + id + '"><ErrorSuccess/></Response></LSX>';
    }
    else if (xml.indexOf('GetAuthToken') !== -1) {
      response = '<LSX><Response id="' + id + '"><AuthToken Token="FAKETOKEN123" ExpiresIn="3600"/></Response></LSX>';
    }
    else {
      console.log('[Origin] Unknown request, sending ErrorSuccess');
      response = '<LSX><Response id="' + id + '"><ErrorSuccess/></Response></LSX>';
    }
    
    if (response) {
      // Encrypt response with session key
      var encrypted = aesEncrypt(response, sessionKey);
      var hexEncoded = encrypted.toString('hex');
      console.log('[Origin] Sending encrypted response (' + response.substring(0, 100) + ')');
      sock.write(hexEncoded + '\0');
    }
  }
  
  socket.on('close', function() { console.log('[Origin] Disconnected: ' + addr + ' (' + msgCount + ' msgs)'); });
  socket.on('error', function(e) { console.log('[Origin] Error: ' + e.message); });
}

var server = net.createServer(createHandler);
server.on('error', function(e) {
  if (e.code === 'EADDRINUSE') {
    console.log('[Origin] Port ' + PORT + ' in use, retrying...');
    setTimeout(function() { server.close(); server.listen(PORT, '127.0.0.1'); }, 2000);
  }
});
server.listen(PORT, '127.0.0.1', function() {
  console.log('[Origin] Listening on 127.0.0.1:' + PORT);
});
