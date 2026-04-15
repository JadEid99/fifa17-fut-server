/**
 * Fake Origin IPC Server — Multi-format test
 * 
 * Listens on port 4216. Tests different ChallengeResponse formats.
 * Set CHALLENGE_FORMAT env var to select format (0-5).
 */

import net from 'net';

const PORT = 4216;
const FORMAT = parseInt(process.env.CHALLENGE_FORMAT || '0');

const CHALLENGE_FORMATS = [
  // 0: LSX > Response > ChallengeAccepted
  (id) => `<LSX><Response id="${id}"><ChallengeAccepted version="3"/></Response></LSX>`,
  // 1: LSX > ChallengeAccepted (no Response wrapper)
  (id) => `<LSX><ChallengeAccepted id="${id}" version="3"/></LSX>`,
  // 2: No response (silent)
  (id) => null,
  // 3: With sender attribute
  (id) => `<LSX><Response id="${id}" sender="EALS"><ChallengeAccepted version="3"/></Response></LSX>`,
  // 4: Empty response
  (id) => `<LSX><Response id="${id}"/></LSX>`,
  // 5: Response with result=0 (generic success)
  (id) => `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`,
];

console.log(`[Origin-IPC] Challenge format: ${FORMAT} (set CHALLENGE_FORMAT=N to change)`);
console.log(`[Origin-IPC] Format preview: ${CHALLENGE_FORMATS[FORMAT]('1') || '(silent)'}`);

function createHandler(socket) {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[Origin] Connected: ${addr}`);
  
  let buffer = '';
  let msgCount = 0;
  
  socket.on('data', (data) => {
    buffer += data.toString('utf-8');
    console.log(`[Origin] Recv: ${data.toString('utf-8').substring(0, 300)}`);
    
    while (buffer.includes('</LSX>')) {
      const endIdx = buffer.indexOf('</LSX>') + 6;
      const msg = buffer.substring(0, endIdx);
      buffer = buffer.substring(endIdx);
      msgCount++;
      handleMessage(socket, msg, msgCount);
    }
  });
  
  socket.on('close', () => console.log(`[Origin] Disconnected: ${addr} (${msgCount} msgs)`));
  socket.on('error', (e) => console.log(`[Origin] Error: ${e.message}`));
}

function handleMessage(socket, xml, msgNum) {
  const idMatch = xml.match(/id="(\d+)"/);
  const id = idMatch ? idMatch[1] : '0';
  const typeMatch = xml.match(/<Request[^>]*>\s*<(\w+)/);
  const requestType = typeMatch ? typeMatch[1] : 'Unknown';
  
  console.log(`[Origin] #${msgNum} ${requestType} id=${id}`);
  
  let response = null;
  
  if (requestType === 'ChallengeResponse') {
    const fn = CHALLENGE_FORMATS[FORMAT] || CHALLENGE_FORMATS[0];
    response = fn(id);
    console.log(`[Origin] Challenge format ${FORMAT}: ${response || '(silent)'}`);
  }
  else if (requestType === 'GetConfig') {
    response = `<LSX><Response id="${id}"><Config version="3"/></Response></LSX>`;
  }
  else if (requestType === 'GetProfile') {
    response = `<LSX><Response id="${id}"><Profile PersonaId="1000000001" UserId="2000000001" DisplayName="Player1" Email="player@local.com" DateOfBirth="19900101" Country="US" Language="en" index="0" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'GetSetting') {
    const m = xml.match(/SettingId="([^"]+)"/);
    const sid = m ? m[1] : '';
    const vals = { 'ENVIRONMENT': 'prod', 'IS_IGO_ENABLED': '0', 'LANGUAGE': 'en_US' };
    response = `<LSX><Response id="${id}"><Setting SettingId="${sid}" Value="${vals[sid] || ''}" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'GetGameInfo') {
    response = `<LSX><Response id="${id}"><GameInfo GameInfoId="FREETRIAL" Value="0" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'SetDownloaderUtilization' || requestType === 'SetPresence') {
    response = `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`;
  }
  else if (requestType === 'RequestAuthCode' || requestType === 'QueryAuthCode' || xml.includes('AuthCode')) {
    console.log(`[Origin] *** AUTH CODE REQUEST ***`);
    response = `<LSX><Response id="${id}"><AuthCode Code="FAKEAUTHCODE1234567890" Type="0" version="3"/></Response></LSX>`;
  }
  else {
    response = `<LSX><Response id="${id}"><Result Status="0" version="3"/></Response></LSX>`;
  }
  
  if (response) {
    console.log(`[Origin] Send: ${response.substring(0, 200)}`);
    socket.write(response);
  } else {
    console.log(`[Origin] (no response — silent)`);
  }
}

const server = net.createServer(createHandler);
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.log(`[Origin-IPC] Port ${PORT} in use, retrying...`);
    setTimeout(() => { server.close(); server.listen(PORT, '127.0.0.1'); }, 2000);
  } else {
    console.log(`[Origin-IPC] Server error: ${e.message}`);
  }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Origin-IPC] Listening on 127.0.0.1:${PORT}`);
});
