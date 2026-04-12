// STP Origin Emulator Proxy - intercepts traffic between game and STP emulator
// Run BEFORE the game starts. Listens on 4216, forwards to STP on 4217.
// You must change the STP emulator to listen on 4217 first.

const net = require('net');
const fs = require('fs');

const LISTEN_PORT = 4216;
const STP_PORT = 4217; // Real STP emulator moved to this port
const LOG_FILE = 'stp_traffic.log';

let logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });

function log(msg) {
  const ts = new Date().toISOString();
  const line = `[${ts}] ${msg}\n`;
  process.stdout.write(line);
  logStream.write(line);
}

const server = net.createServer((clientSocket) => {
  log(`Game connected from ${clientSocket.remotePort}`);
  
  const stpSocket = net.createConnection(STP_PORT, '127.0.0.1', () => {
    log('Connected to real STP emulator');
  });
  
  clientSocket.on('data', (data) => {
    const hex = data.toString('hex');
    const ascii = data.toString('ascii').replace(/[^\x20-\x7e]/g, '.');
    log(`GAME -> STP (${data.length} bytes):`);
    log(`  HEX: ${hex.substring(0, 200)}`);
    log(`  ASCII: ${ascii.substring(0, 200)}`);
    stpSocket.write(data);
  });
  
  stpSocket.on('data', (data) => {
    const hex = data.toString('hex');
    const ascii = data.toString('ascii').replace(/[^\x20-\x7e]/g, '.');
    log(`STP -> GAME (${data.length} bytes):`);
    log(`  HEX: ${hex.substring(0, 200)}`);
    log(`  ASCII: ${ascii.substring(0, 200)}`);
    clientSocket.write(data);
  });
  
  clientSocket.on('close', () => log('Game disconnected'));
  clientSocket.on('error', (e) => log(`Game error: ${e.message}`));
  stpSocket.on('close', () => log('STP disconnected'));
  stpSocket.on('error', (e) => log(`STP error: ${e.message}`));
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
  log(`STP Proxy listening on port ${LISTEN_PORT}, forwarding to ${STP_PORT}`);
  log('NOTE: You must change the STP emulator to listen on port 4217');
});
