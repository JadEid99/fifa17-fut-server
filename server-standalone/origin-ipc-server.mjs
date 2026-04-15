/**
 * Fake Origin IPC Server
 * 
 * FIFA 17's Origin SDK communicates via TCP on localhost using EA's LSX XML format.
 * This server mimics Origin's responses to:
 * 1. GetSetting (ENVIRONMENT) — returns "prod" 
 * 2. RequestAuthCode — returns a fake auth code
 * 3. Any other requests — returns empty success responses
 *
 * The game connects to this on the port stored at originSDK+0x35c.
 * The DLL must set this port to match our server's port.
 *
 * LSX format: <LSX><Request/Response recipient="" id="N">...</Request/Response></LSX>
 */

import net from 'net';

const PORT = 4216; // The Origin SDK always connects here

const server = net.createServer((socket) => {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[Origin-IPC] Client connected: ${addr}`);
  
  let buffer = '';
  
  socket.on('data', (data) => {
    buffer += data.toString('utf-8');
    console.log(`[Origin-IPC] Received: ${data.toString('utf-8').substring(0, 500)}`);
    
    // Process complete LSX messages
    // LSX messages are delimited by </LSX>
    while (buffer.includes('</LSX>')) {
      const endIdx = buffer.indexOf('</LSX>') + 6;
      const msg = buffer.substring(0, endIdx);
      buffer = buffer.substring(endIdx);
      
      handleLSXMessage(socket, msg);
    }
  });
  
  socket.on('close', () => console.log(`[Origin-IPC] Disconnected: ${addr}`));
  socket.on('error', (e) => console.log(`[Origin-IPC] Error: ${e.message}`));
});

function handleLSXMessage(socket, xml) {
  console.log(`[Origin-IPC] Processing: ${xml.substring(0, 200)}`);
  
  // Extract the request ID
  const idMatch = xml.match(/id="(\d+)"/);
  const id = idMatch ? idMatch[1] : '0';
  
  // Extract the request type (first element inside <Request>)
  const typeMatch = xml.match(/<Request[^>]*>[\s]*<(\w+)/);
  const requestType = typeMatch ? typeMatch[1] : 'Unknown';
  
  console.log(`[Origin-IPC] Request type: ${requestType}, id: ${id}`);
  
  let response = '';
  
  if (requestType === 'QueryAuthCode' || requestType === 'RequestAuthCode' || 
      requestType === 'AuthCode' || xml.includes('AuthCode') || xml.includes('authcode')) {
    // Auth code request — return a fake auth code
    console.log('[Origin-IPC] *** AUTH CODE REQUEST — sending fake auth code ***');
    response = `<LSX><Response id="${id}"><AuthCode Code="FAKEAUTHCODE1234567890" Type="0" CreatedTimestamp="${Math.floor(Date.now()/1000)}"/></Response></LSX>`;
  }
  else if (requestType === 'ChallengeResponse') {
    // Crypto challenge from the game — respond with ChallengeAccepted
    // The game checks for "ChallengeAccepted" element (from Ghidra: s_ChallengeAccepted_143937b18)
    console.log('[Origin-IPC] *** CHALLENGE RESPONSE — sending ChallengeAccepted ***');
    response = `<LSX><Response id="${id}"><ChallengeAccepted version="3"/></Response></LSX>`;
  }
  else if (requestType === 'GetConfig') {
    console.log('[Origin-IPC] GetConfig request');
    response = `<LSX><Response id="${id}"><Config version="3"/></Response></LSX>`;
  }
  else if (requestType === 'GetSetting') {
    // Setting request — check which setting
    const settingMatch = xml.match(/SettingId="([^"]+)"/);
    const settingId = settingMatch ? settingMatch[1] : '';
    console.log(`[Origin-IPC] GetSetting: ${settingId}`);
    
    if (settingId === 'ENVIRONMENT') {
      response = `<LSX><Response id="${id}"><Setting SettingId="ENVIRONMENT" Value="prod" version="3"/></Response></LSX>`;
    } else {
      response = `<LSX><Response id="${id}"><Setting SettingId="${settingId}" Value="" version="3"/></Response></LSX>`;
    }
  }
  else if (requestType === 'QueryGameInfo' || requestType === 'GetGameInfo') {
    response = `<LSX><Response id="${id}"><GameInfo GameVersion="1.0.0.0" GamePlatform="pc"/></Response></LSX>`;
  }
  else if (requestType === 'CheckOnline') {
    response = `<LSX><Response id="${id}"><Online Status="1"/></Response></LSX>`;
  }
  else if (requestType === 'GetProfile') {
    response = `<LSX><Response id="${id}"><Profile PersonaId="1000000001" UserId="2000000001" DisplayName="Player1" Email="player@local.com" index="0" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'SetDownloaderUtilization') {
    response = `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'Initialize') {
    response = `<LSX><Response id="${id}"><Initialized Status="1"/></Response></LSX>`;
  }
  else {
    // Generic success response
    console.log(`[Origin-IPC] Unknown request type: ${requestType} — sending generic OK`);
    response = `<LSX><Response id="${id}"><Result Status="0"/></Response></LSX>`;
  }
  
  console.log(`[Origin-IPC] Sending: ${response.substring(0, 200)}`);
  socket.write(response);
}

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Origin-IPC] Fake Origin server listening on 127.0.0.1:${PORT}`);
});
