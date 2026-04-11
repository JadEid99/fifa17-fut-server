/**
 * FIFA 17 Ultimate Team Private Server
 * 
 * Entry point - starts all server components:
 * 1. Blaze Redirector (port 42230) - tells the game where to connect
 * 2. Blaze Main Server (port 10041) - handles auth, matchmaking, etc.
 * 3. HTTP API Server (port 80/443) - handles FUT/EASW REST API
 */

import { startRedirector } from './blaze/redirector.js';
import { startMainServer } from './blaze/main-server.js';
import express from 'express';

const MAIN_BLAZE_PORT = 10041;
const HTTP_PORT = 8080;

// Determine the target host - use localhost for local testing
const TARGET_HOST = process.env.TARGET_HOST || '127.0.0.1';

console.log('===========================================');
console.log('  FIFA 17 Ultimate Team Private Server');
console.log('===========================================');
console.log('');

// Start Blaze Redirector
const redirector = startRedirector({
  targetHost: TARGET_HOST,
  targetPort: MAIN_BLAZE_PORT,
});

// Start Blaze Main Server
const mainServer = startMainServer(MAIN_BLAZE_PORT);

// Start HTTP API Server (for EASW/FUT API)
const app = express();
app.use(express.json());

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', server: 'fifa17-fut-server' });
});

// Stub for EASW/FUT API endpoints
app.all('/ut/game/fifa17/*', (req, res) => {
  console.log(`[HTTP] ${req.method} ${req.path}`);
  console.log(`[HTTP] Headers:`, JSON.stringify(req.headers, null, 2));
  res.json({ success: true });
});

// Stub for gameface
app.get('/gameface/*', (req, res) => {
  console.log(`[HTTP] Gameface request: ${req.path}`);
  res.json({});
});

// Catch-all to log any requests we haven't handled
app.all('*', (req, res) => {
  console.log(`[HTTP] Unhandled: ${req.method} ${req.path}`);
  res.status(200).json({});
});

app.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`[HTTP] API server listening on port ${HTTP_PORT}`);
});

console.log('');
console.log('Server components started. Waiting for connections...');
console.log('');
console.log('To connect FIFA 17, add this to your Windows hosts file:');
console.log(`  ${TARGET_HOST} winter15.gosredirector.ea.com`);
console.log('');
