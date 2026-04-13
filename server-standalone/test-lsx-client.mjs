/**
 * Test client for the LSX Origin SDK Server.
 * Simulates the game's Origin SDK connection.
 */
import net from 'net';
import crypto from 'crypto';

const RAND_MAX = 32767, MULTIPLIER = 214013, INCREMENT = 2531011, DEFAULT_SEED = 7;
class Random {
  constructor(s) { this.seed = s >>> 0; }
  next() { this.seed = ((this.seed * MULTIPLIER) + INCREMENT) >>> 0; return (this.seed >>> 16) & RAND_MAX; }
  setSeed(s) { this.seed = s >>> 0; }
}

function generateKey(seed) {
  const k = Buffer.alloc(16);
  if (seed === 0) { for (let i = 0; i < 16; i++) k[i] = i; }
  else { const r = new Random(DEFAULT_SEED); const ns = (r.next() + seed) >>> 0; r.setSeed(ns); for (let i = 0; i < 16; i++) k[i] = r.next() & 0xFF; }
  return k;
}

function aesEncrypt(key, pt) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  return Buffer.concat([c.update(pt, 'utf-8'), c.final()]);
}

function aesDecrypt(key, ct) {
  const d = crypto.createDecipheriv('aes-128-ecb', key, null);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf-8');
}

const sock = net.createConnection(4216, '127.0.0.1', () => console.log('Connected'));
let buf = Buffer.alloc(0);
let sessionKey = null;
let handshakeDone = false;

sock.on('data', (data) => {
  buf = Buffer.concat([buf, data]);
  let idx;
  while ((idx = buf.indexOf(0x00)) !== -1) {
    const msg = buf.subarray(0, idx).toString('utf-8');
    buf = buf.subarray(idx + 1);
    if (msg.length === 0) continue;

    if (!handshakeDone && msg.includes('<Challenge ')) {
      console.log('1. Got Challenge');
      const keyMatch = msg.match(/key="([^"]+)"/);
      const challengeKey = keyMatch[1];
      const initialKey = generateKey(0);
      const encrypted = aesEncrypt(initialKey, challengeKey);
      const responseStr = encrypted.toString('hex');
      const seed = (responseStr.charCodeAt(0) << 8) | responseStr.charCodeAt(1);
      sessionKey = generateKey(seed);
      console.log('   Session key: ' + sessionKey.toString('hex'));
      const resp = `<LSX><Request id="0" recipient="EALS"><ChallengeResponse response="${responseStr}" key="${challengeKey}" version="3"><ContentId>FIFA17</ContentId><Title>FIFA 17</Title><MultiplayerId>1026480</MultiplayerId><Language>en_US</Language><Version>10.6.1.8</Version></ChallengeResponse></Request></LSX>`;
      sock.write(Buffer.concat([Buffer.from(resp), Buffer.from([0x00])]));
      console.log('2. Sent ChallengeResponse');
    }
    else if (!handshakeDone && msg.includes('<ChallengeAccepted')) {
      console.log('3. Handshake accepted!');
      handshakeDone = true;
    }
    else if (handshakeDone) {
      try {
        const xml = aesDecrypt(sessionKey, Buffer.from(msg, 'hex'));
        console.log('4. Decrypted: ' + xml.substring(0, 120));
        if (xml.includes('IsLoggedIn="true"')) {
          console.log('5. >>> LOGIN EVENT RECEIVED <<<');
          // Send GetAuthCode
          const req = `<LSX><Request id="1" recipient="EbisuSDK"><GetAuthCode UserId="33068179" ClientId="FIFA17_PC" Scope="basic.identity" AppendAuthSource="false"/></Request></LSX>`;
          const enc = aesEncrypt(sessionKey, req);
          sock.write(Buffer.concat([Buffer.from(enc.toString('hex')), Buffer.from([0x00])]));
          console.log('6. Sent GetAuthCode');
        }
        else if (xml.includes('<AuthCode')) {
          console.log('7. >>> AUTH CODE RECEIVED <<<');
          console.log('   ' + xml);
          console.log('\n=== ALL TESTS PASSED ===');
          sock.destroy();
          process.exit(0);
        }
      } catch (e) {
        console.log('Decrypt error: ' + e.message);
      }
    }
  }
});

sock.on('error', e => { console.log('Error: ' + e.message); process.exit(1); });
setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 5000);
