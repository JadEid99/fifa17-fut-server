/**
 * Blaze Main Server
 * 
 * After the redirector tells FIFA 17 where to connect, the game
 * connects here for authentication, matchmaking, and game services.
 * 
 * For Phase 1, we just need to handle:
 * - PreAuth (UTIL component)
 * - PostAuth (UTIL component)  
 * - Login/OriginLogin (AUTH component)
 * - Ping (UTIL component)
 * - FetchClientConfig (UTIL component)
 * - GetTelemetryServer (UTIL component)
 */

import * as net from 'net';
import {
  BlazeComponent,
  BlazePacket,
  MessageType,
  AuthCommand,
  UtilCommand,
} from './types.js';
import { buildReply, readPacket, buildPacket } from './codec.js';
import { TdfEncoder, TdfType } from './tdf.js';

const MAIN_PORT = 10041;

interface Session {
  id: number;
  socket: net.Socket;
  personaId: number;
  nucleusId: number;
  displayName: string;
  authenticated: boolean;
}

let nextSessionId = 1;
const sessions = new Map<number, Session>();

/**
 * Handle PreAuth request - game sends this first to get server config
 */
function handlePreAuth(packet: BlazePacket): Buffer {
  console.log('[Main] Handling PreAuth');
  const encoder = new TdfEncoder();

  // CIDS - list of component IDs the server supports
  encoder.writeIntList('CIDS', [
    0x0001, // Authentication
    0x0004, // Game Manager
    0x0005, // Redirector
    0x0007, // Stats
    0x0009, // Util
    0x000F, // Messaging
    0x0019, // Association Lists
    0x001C, // Game Reporting
    0x7802, // User Sessions
  ]);

  // CONF struct - server configuration
  encoder.writeStructStart('CONF');
  encoder.writeString('CONF', '{}');
  encoder.writeStructEnd();

  // INST - server instance name
  encoder.writeString('INST', 'fifa17-fut-server');

  // NASP - namespace
  encoder.writeString('NASP', 'cem_ea_id');

  // PILD - platform ID
  encoder.writeString('PILD', '');

  // PLAT - platform
  encoder.writeString('PLAT', 'pc');

  // QOSS struct - QoS server info
  encoder.writeStructStart('QOSS');
  encoder.writeStructStart('BWPS');
  encoder.writeString('PSA ', '127.0.0.1');
  encoder.writeInteger('PSP ', 17502);
  encoder.writeString('SNA ', 'prod-sjc');
  encoder.writeStructEnd();
  encoder.writeInteger('LNP ', 10);
  encoder.writeStructStart('LTPS');
  // Empty QoS server list for now
  encoder.writeStructEnd();
  encoder.writeInteger('SVID', 0x45410805);
  encoder.writeStructEnd();

  // RSRC - resource string
  encoder.writeString('RSRC', 'fifa17-2016');

  // SVER - server version
  encoder.writeString('SVER', 'Blaze 3.15.08.0 (CL# 1060080 / Jul 11 2016)');

  return buildReply(packet, encoder.build());
}

/**
 * Handle PostAuth request - game sends this after successful login
 */
function handlePostAuth(session: Session, packet: BlazePacket): Buffer {
  console.log('[Main] Handling PostAuth');
  const encoder = new TdfEncoder();

  // PSS struct - post-auth server settings
  encoder.writeStructStart('PSS ');
  encoder.writeString('ADRS', '');
  encoder.writeBlob('CSIG', Buffer.alloc(0));
  encoder.writeString('PJID', '123071');
  encoder.writeInteger('PORT', 443);
  encoder.writeInteger('RPRT', 15);
  encoder.writeInteger('TIID', 0);
  encoder.writeStructEnd();

  // TELE struct - telemetry config
  encoder.writeStructStart('TELE');
  encoder.writeString('ADRS', '127.0.0.1');
  encoder.writeInteger('ANON', 0);
  encoder.writeString('DPTS', 'ut/bf/fifa17');
  encoder.writeInteger('LOCA', 1701729619); // 'enUS'
  encoder.writeString('NOOK', '');
  encoder.writeInteger('PORT', 9988);
  encoder.writeInteger('SDLY', 15000);
  encoder.writeString('SESS', 'JMhnT9dXSED');
  encoder.writeString('SKEY', 'some_telemetry_key');
  encoder.writeInteger('SPCT', 75);
  encoder.writeString('STIM', '');
  encoder.writeStructEnd();

  // TICK struct - ticker settings
  encoder.writeStructStart('TICK');
  encoder.writeString('ADRS', '');
  encoder.writeInteger('PORT', 0);
  encoder.writeString('SKEY', '');
  encoder.writeStructEnd();

  // UROP struct - user options
  encoder.writeStructStart('UROP');
  encoder.writeInteger('TMOP', 1);
  encoder.writeInteger('UID ', session.nucleusId);
  encoder.writeStructEnd();

  return buildReply(packet, encoder.build());
}

/**
 * Handle Login/OriginLogin - authenticate the user
 */
function handleLogin(session: Session, packet: BlazePacket): Buffer {
  console.log('[Main] Handling Login');

  // For now, accept any login and assign a persona
  session.authenticated = true;
  session.personaId = 1000000000 + session.id;
  session.nucleusId = 2000000000 + session.id;
  session.displayName = `Player${session.id}`;

  const encoder = new TdfEncoder();

  // NTOS - needs TOS acceptance (0 = no)
  encoder.writeInteger('NTOS', 0);

  // PCTK - PC ticket
  encoder.writeString('PCTK', '');

  // PRIV - privacy policy version
  encoder.writeString('PRIV', '');

  // SESS struct - session info
  encoder.writeStructStart('SESS');
  encoder.writeInteger('BUID', session.nucleusId);
  encoder.writeInteger('FRST', 0);
  encoder.writeString('KEY ', `session_key_${session.id}`);
  encoder.writeInteger('LLOG', 0);
  encoder.writeString('MAIL', `player${session.id}@fut.local`);

  // PDTL struct - persona details
  encoder.writeStructStart('PDTL');
  encoder.writeString('DSNM', session.displayName);
  encoder.writeInteger('LAST', 0);
  encoder.writeInteger('PID ', session.personaId);
  encoder.writeInteger('STAS', 0);
  encoder.writeInteger('XREF', 0);
  encoder.writeInteger('XTYP', 0);
  encoder.writeStructEnd();

  encoder.writeInteger('UID ', session.nucleusId);
  encoder.writeStructEnd();

  // SPAM - spam flag
  encoder.writeInteger('SPAM', 0);

  // THST - TOS host
  encoder.writeString('THST', '');

  // TSUI - TOS URI
  encoder.writeString('TSUI', '');

  // TURI - TOS URI
  encoder.writeString('TURI', '');

  return buildReply(packet, encoder.build());
}

/**
 * Handle Ping
 */
function handlePing(packet: BlazePacket): Buffer {
  console.log('[Main] Handling Ping');
  const encoder = new TdfEncoder();
  encoder.writeInteger('STIM', BigInt(Date.now()));
  return buildReply(packet, encoder.build());
}

/**
 * Handle FetchClientConfig
 */
function handleFetchClientConfig(packet: BlazePacket): Buffer {
  console.log('[Main] Handling FetchClientConfig');
  const encoder = new TdfEncoder();
  // Return empty config map
  return buildReply(packet, encoder.build());
}

/**
 * Handle GetTelemetryServer
 */
function handleGetTelemetryServer(packet: BlazePacket): Buffer {
  console.log('[Main] Handling GetTelemetryServer');
  const encoder = new TdfEncoder();
  encoder.writeString('ADRS', '127.0.0.1');
  encoder.writeInteger('ANON', 0);
  encoder.writeString('DPTS', 'ut/bf/fifa17');
  encoder.writeInteger('LOCA', 1701729619);
  encoder.writeString('NOOK', '');
  encoder.writeInteger('PORT', 9988);
  encoder.writeInteger('SDLY', 15000);
  encoder.writeString('SESS', '');
  encoder.writeString('SKEY', '');
  encoder.writeInteger('SPCT', 75);
  encoder.writeString('STIM', '');
  return buildReply(packet, encoder.build());
}

/**
 * Handle UserSettingsLoadAll
 */
function handleUserSettingsLoadAll(packet: BlazePacket): Buffer {
  console.log('[Main] Handling UserSettingsLoadAll');
  const encoder = new TdfEncoder();
  encoder.writeString('SVAL', '');
  return buildReply(packet, encoder.build());
}

/**
 * Route a packet to the appropriate handler
 */
function handlePacket(session: Session, packet: BlazePacket): void {
  const { component, command, msgType } = packet.header;
  let response: Buffer | null = null;

  console.log(`[Main] Packet from session ${session.id}: component=0x${component.toString(16).padStart(4, '0')} command=0x${command.toString(16).padStart(4, '0')} type=0x${msgType.toString(16)}`);

  switch (component) {
    case BlazeComponent.UTIL:
      switch (command) {
        case UtilCommand.PRE_AUTH:
          response = handlePreAuth(packet);
          break;
        case UtilCommand.POST_AUTH:
          response = handlePostAuth(session, packet);
          break;
        case UtilCommand.PING:
          response = handlePing(packet);
          break;
        case UtilCommand.FETCH_CLIENT_CONFIG:
          response = handleFetchClientConfig(packet);
          break;
        case UtilCommand.GET_TELEMETRY_SERVER:
          response = handleGetTelemetryServer(packet);
          break;
        case UtilCommand.USER_SETTINGS_LOAD_ALL:
          response = handleUserSettingsLoadAll(packet);
          break;
        case UtilCommand.SET_CLIENT_METRICS:
          // Just acknowledge
          response = buildReply(packet, Buffer.alloc(0));
          break;
        case UtilCommand.USER_SETTINGS_SAVE:
          response = buildReply(packet, Buffer.alloc(0));
          break;
        default:
          console.log(`[Main] Unhandled UTIL command: 0x${command.toString(16)}`);
          response = buildReply(packet, Buffer.alloc(0));
      }
      break;

    case BlazeComponent.AUTHENTICATION:
      switch (command) {
        case AuthCommand.LOGIN:
        case AuthCommand.ORIGIN_LOGIN:
        case AuthCommand.SILENT_LOGIN:
        case AuthCommand.EXPRESS_LOGIN:
          response = handleLogin(session, packet);
          break;
        case AuthCommand.LIST_USER_ENTITLEMENTS_2:
          // Return empty entitlements list
          response = buildReply(packet, new TdfEncoder().build());
          break;
        case AuthCommand.GET_AUTH_TOKEN:
          response = buildReply(packet, new TdfEncoder().writeString('AUTH', `auth_token_${session.id}`).build());
          break;
        case AuthCommand.LIST_PERSONA:
          // Return a single persona
          const personaEncoder = new TdfEncoder();
          personaEncoder.writeList('PLST', TdfType.STRUCT, 1, (enc) => {
            enc.writeString('DSNM', session.displayName);
            enc.writeInteger('LAST', 0);
            enc.writeInteger('PID ', session.personaId);
            enc.writeInteger('STAS', 0);
            enc.writeInteger('XREF', 0);
            enc.writeInteger('XTYP', 0);
          });
          response = buildReply(packet, personaEncoder.build());
          break;
        case AuthCommand.GET_TOS_INFO:
          response = buildReply(packet, new TdfEncoder().writeInteger('TOSI', 0).build());
          break;
        case AuthCommand.LOGOUT:
          session.authenticated = false;
          response = buildReply(packet, Buffer.alloc(0));
          break;
        default:
          console.log(`[Main] Unhandled AUTH command: 0x${command.toString(16)}`);
          response = buildReply(packet, Buffer.alloc(0));
      }
      break;

    case BlazeComponent.USER_SESSIONS:
      // Stub all user session commands
      console.log(`[Main] UserSessions command: 0x${command.toString(16)}`);
      response = buildReply(packet, Buffer.alloc(0));
      break;

    default:
      console.log(`[Main] Unhandled component: 0x${component.toString(16)} command: 0x${command.toString(16)}`);
      // Send empty reply to prevent the game from hanging
      response = buildReply(packet, Buffer.alloc(0));
  }

  if (response) {
    session.socket.write(response);
  }
}

/**
 * Handle a client connection to the main server
 */
function handleConnection(socket: net.Socket): void {
  const sessionId = nextSessionId++;
  const session: Session = {
    id: sessionId,
    socket,
    personaId: 0,
    nucleusId: 0,
    displayName: '',
    authenticated: false,
  };
  sessions.set(sessionId, session);

  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[Main] Client connected: ${addr} (session ${sessionId})`);

  let buffer: Buffer = Buffer.alloc(0);

  socket.on('data', (data) => {
    buffer = Buffer.concat([buffer, data]) as Buffer;
    console.log(`[Main] Received ${data.length} bytes from session ${sessionId}`);

    let result = readPacket(buffer);
    while (result) {
      const { packet, remaining } = result;
      buffer = remaining as Buffer;
      handlePacket(session, packet);
      result = readPacket(buffer);
    }
  });

  socket.on('close', () => {
    console.log(`[Main] Session ${sessionId} disconnected`);
    sessions.delete(sessionId);
  });

  socket.on('error', (err) => {
    console.log(`[Main] Session ${sessionId} error: ${err.message}`);
  });
}

/**
 * Start the main Blaze server
 */
export function startMainServer(port: number = MAIN_PORT): net.Server {
  const server = net.createServer((socket) => {
    handleConnection(socket);
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`[Main] Blaze main server listening on port ${port}`);
  });

  return server;
}
