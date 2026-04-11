/**
 * Blaze Protocol Types
 * 
 * The Blaze protocol is EA's proprietary binary protocol used for game server communication.
 * Packets have a 12-byte header followed by a TDF (Tag Data Format) encoded body.
 */

// Blaze packet header structure (12 bytes)
export interface BlazePacketHeader {
  // Bytes 0-1: Content length (big-endian uint16)
  length: number;
  // Byte 2-3: Component ID (big-endian uint16)
  component: number;
  // Byte 4-5: Command ID (big-endian uint16)
  command: number;
  // Byte 6-7: Error code (big-endian uint16)
  error: number;
  // Byte 8-9: Message type (bits) + Message ID
  msgType: MessageType;
  // Byte 10-11: Message ID (big-endian uint16)
  msgId: number;
}

export enum MessageType {
  MESSAGE = 0x0000,
  REPLY = 0x1000,
  NOTIFICATION = 0x2000,
  ERROR_REPLY = 0x3000,
}

// Known Blaze components
export enum BlazeComponent {
  AUTHENTICATION = 0x0001,
  GAME_MANAGER = 0x0004,
  REDIRECTOR = 0x0005,
  STATS = 0x0007,
  UTIL = 0x0009,
  MESSAGING = 0x000F,
  ASSOCIATION_LISTS = 0x0019,
  GAME_REPORTING = 0x001C,
  USER_SESSIONS = 0x7802,
}

// Redirector commands
export enum RedirectorCommand {
  GET_SERVER_INSTANCE = 0x0001,
}

// Authentication commands
export enum AuthCommand {
  // Pre-auth and auth commands
  CREATE_ACCOUNT = 0x000A,
  UPDATE_ACCOUNT = 0x0014,
  UPDATE_PARENTAL_EMAIL = 0x001C,
  LIST_USER_ENTITLEMENTS_2 = 0x001D,
  GET_ACCOUNT = 0x001E,
  GRANT_ENTITLEMENT = 0x001F,
  LIST_ENTITLEMENTS = 0x0020,
  HAS_ENTITLEMENT = 0x0021,
  GET_USE_COUNT = 0x0022,
  DECREMENT_USE_COUNT = 0x0023,
  GET_AUTH_TOKEN = 0x0024,
  GET_HANDOFF_TOKEN = 0x0025,
  GET_PASSWORD_RULES = 0x0026,
  GRANT_ENTITLEMENT_2 = 0x0027,
  LOGIN = 0x0028,
  ACCEPT_TOS = 0x0029,
  GET_TOS_INFO = 0x002A,
  MODIFY_ENTITLEMENT_2 = 0x002B,
  CONSUME_CODE = 0x002C,
  PASSWORD_FORGOT = 0x002D,
  GET_TOS_CONTENT = 0x002E,
  GET_PRIVACY_POLICY_CONTENT = 0x002F,
  LIST_PERSONA = 0x0030,
  GET_PERSONA = 0x0031,
  SILENT_LOGIN = 0x0032,
  CHECK_AGE_REQUIREMENT = 0x0033,
  GET_OPT_IN = 0x0034,
  ENABLE_OPT_IN = 0x0035,
  DISABLE_OPT_IN = 0x0036,
  EXPRESS_LOGIN = 0x003C,
  LOGOUT = 0x0046,
  CREATE_PERSONA = 0x0050,
  GET_PERSONA_2 = 0x005A,
  LIST_DEVICE_ACCOUNTS = 0x0064,
  XBOX_CREATE_ACCOUNT = 0x0096,
  ORIGIN_LOGIN = 0x00C8,
  XBOX_ASSOCIATE_ACCOUNT = 0x00C9,
  XBOX_LOGIN = 0x00CA,
  PS3_CREATE_ACCOUNT = 0x00FA,
  PS3_ASSOCIATE_ACCOUNT = 0x00FB,
  PS3_LOGIN = 0x00FC,
  X_GET_ACCOUNTS = 0x0104,
  X_LOOKUP_USERS = 0x0105,
  WALEU_ASSOCIATE_ACCOUNT = 0x012C,
  WALEU_LOGIN = 0x012D,
  STADIA_ASSOCIATE_ACCOUNT = 0x0190,
  STADIA_LOGIN = 0x0191,
}

// Util commands
export enum UtilCommand {
  FETCH_CLIENT_CONFIG = 0x0001,
  PING = 0x0002,
  GET_TELEMETRY_SERVER = 0x0003,
  PRE_AUTH = 0x0007,
  POST_AUTH = 0x0008,
  USER_SETTINGS_SAVE = 0x000A,
  USER_SETTINGS_LOAD_ALL = 0x000B,
  SET_CLIENT_METRICS = 0x0016,
}

export interface BlazePacket {
  header: BlazePacketHeader;
  body: Buffer;
}
