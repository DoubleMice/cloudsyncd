#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const ADMIN_PORT = process.env.ADMIN_PORT || 21900;
const ADMIN_HOST = process.env.ADMIN_HOST || '127.0.0.1';
const tokenFile = path.join(__dirname, 'data', '.admin-token');

let token;
try {
  token = fs.readFileSync(tokenFile, 'utf8').trim();
} catch {
  console.error('Cannot read admin token. Is the server running?');
  process.exit(1);
}

(async () => {
  try {
    const res = await fetch(`http://${ADMIN_HOST}:${ADMIN_PORT}/api/local/new-pin`, {
      method: 'POST',
      headers: { 'x-admin-token': token },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.pin) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    console.log(`\nNew pairing PIN: ${data.pin}\n`);
  } catch (err) {
    console.error('Error:', err.message || 'Server not running?');
    process.exit(1);
  }
})();
