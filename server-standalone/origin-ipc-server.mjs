/**
 * Fake Origin IPC Server v3
 * 
 * KEY INSIGHT: Origin sends a Challenge FIRST when the game connects.
 * The game then responds with ChallengeResponse. We were waiting for
 * the game to send first, but the game was waiting for US to send first.
 * 
 * Flow: Game connects → Origin sends Challenge → Game sends ChallengeResponse
 *       → Origin sends ChallengeAccepted → Game sends GetConfig, GetProfile, etc.
 */

import net from 'net';
import crypto from 'crypto';

const PORT = 3216;

function createHandler(socket) {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[Origin] Connected: ${addr}`);
  
  let buffer = '';
  let msgCount = 0;
  
  // Send Challenge — Origin sends this first, game responds with ChallengeResponse
  // Previous attempts froze because we didn't have null terminator. Now we do.
  var challengeKey = crypto.randomBytes(16).toString('hex');
  var challenge = '<LSX><Challenge key="' + challengeKey + '" version="3"/></LSX>';
  console.log('[Origin] Sending: ' + challenge);
  socket.write(challenge + '\0');
  
  socket.on('data', (data) => {
    // Protocol uses null-terminated strings
    buffer += data.toString('utf-8');
    
    // Log raw hex for debugging
    const hexDump = Array.from(data.subarray(0, Math.min(64, data.length)))
      .map(b => b.toString(16).padStart(2, '0')).join(' ');
    console.log(`[Origin] Recv ${data.length}b: ${hexDump}`);
    
    // Split on null bytes (protocol delimiter)
    let parts = buffer.split('\0');
    // Last part is incomplete (no null terminator yet)
    buffer = parts.pop();
    
    for (const msg of parts) {
      if (msg.trim().length === 0) continue;
      msgCount++;
      console.log(`[Origin] Msg: ${msg.substring(0, 300)}`);
      handleMessage(socket, msg, msgCount);
    }
  });
  
  socket.on('close', function() { console.log('[Origin] Disconnected: ' + addr + ' (' + msgCount + ' msgs)'); });
  socket.on('error', function(e) { console.log('[Origin] Error: ' + e.message); });
}

function handleMessage(socket, xml, msgNum) {
  const idMatch = xml.match(/id="(\d+)"/);
  const id = idMatch ? idMatch[1] : '0';
  const typeMatch = xml.match(/<Request[^>]*>\s*<(\w+)/);
  const requestType = typeMatch ? typeMatch[1] : 'Unknown';
  
  // Also check for non-Request wrapped messages
  const bareTypeMatch = xml.match(/<LSX>\s*<(\w+)/);
  const bareType = bareTypeMatch ? bareTypeMatch[1] : '';
  const effectiveType = requestType !== 'Unknown' ? requestType : bareType;
  
  console.log(`[Origin] #${msgNum} type=${effectiveType} id=${id}`);
  
  let response = null;
  
  switch (effectiveType) {
    case 'ChallengeResponse':
      console.log(`[Origin] *** CHALLENGE ACCEPTED ***`);
      response = `<LSX><ChallengeAccepted version="3"/></LSX>`;
      break;
      
    case 'GetConfig':
      response = `<LSX><Response id="${id}"><Config version="3"/></Response></LSX>`;
      break;
      
    case 'GetProfile':
      response = `<LSX><Response id="${id}"><Profile PersonaId="1000000001" UserId="2000000001" DisplayName="Player1" Email="player@local.com" DateOfBirth="19900101" Country="US" Language="en" index="0" version="3"/></Response></LSX>`;
      break;
      
    case 'GetSetting': {
      const m = xml.match(/SettingId="([^"]+)"/);
      const sid = m ? m[1] : '';
      const vals = { 'ENVIRONMENT': 'prod', 'IS_IGO_ENABLED': '0', 'LANGUAGE': 'en_US' };
      response = `<LSX><Response id="${id}"><Setting SettingId="${sid}" Value="${vals[sid] || ''}" version="3"/></Response></LSX>`;
      break;
    }
      
    case 'GetGameInfo':
      response = `<LSX><Response id="${id}"><GameInfo GameInfoId="FREETRIAL" Value="0" version="3"/></Response></LSX>`;
      break;
      
    case 'SetDownloaderUtilization':
    case 'SetPresence':
      response = `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`;
      break;
      
    case 'RequestAuthCode':
    case 'QueryAuthCode':
      console.log(`[Origin] *** AUTH CODE REQUEST ***`);
      response = `<LSX><Response id="${id}"><AuthCode Code="FAKEAUTHCODE1234567890" Type="0" version="3"/></Response></LSX>`;
      break;
      
    default:
      if (xml.includes('AuthCode') || xml.includes('auth')) {
        console.log(`[Origin] *** Possible auth in unknown format ***`);
        response = `<LSX><Response id="${id}"><AuthCode Code="FAKEAUTHCODE1234567890" Type="0" version="3"/></Response></LSX>`;
      } else {
        console.log(`[Origin] Unknown: ${effectiveType}`);
        response = `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`;
      }
  }
  
  if (response) {
    console.log(`[Origin] Send: ${response.substring(0, 200)}`);
    socket.write(response + '\0');
  }
}

const server = net.createServer(createHandler);
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.log(`[Origin] Port ${PORT} in use, retrying in 2s...`);
    setTimeout(() => { server.close(); server.listen(PORT, '127.0.0.1'); }, 2000);
  }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Origin] Listening on 127.0.0.1:${PORT}`);
});
