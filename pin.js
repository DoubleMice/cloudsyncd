#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const ADMIN_PORT = process.env.ADMIN_PORT || 21900;
const tokenFile = path.join(__dirname, 'data', '.admin-token');

let token;
try {
  token = fs.readFileSync(tokenFile, 'utf8').trim();
} catch {
  console.error('Cannot read admin token. Is the server running?');
  process.exit(1);
}

fetch(`http://127.0.0.1:${ADMIN_PORT}/api/local/new-pin`, {
  method: 'POST',
  headers: { 'x-admin-token': token },
})
  .then(r => r.json())
  .then(data => {
    if (data.pin) console.log(`\nNew pairing PIN: ${data.pin}\n`);
    else console.error('Error:', data.error);
  })
  .catch(() => console.error('Server not running?'));
