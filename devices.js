#!/usr/bin/env node
// Local device management for cloudsyncd.
// Lists, revokes, or revokes-all paired devices via the admin-token-guarded API.
// Run while the server is up (the server must be listening on loopback).

const fs = require('fs');
const path = require('path');

// Admin API lives on the separate local-only admin port (not the client/tunnel port).
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

const base = `http://${ADMIN_HOST}:${ADMIN_PORT}`;
const headers = { 'x-admin-token': token };

const args = process.argv.slice(2);
const cmd = args[0] || '--list';

function usage() {
  console.log('用法:');
  console.log('  node devices.js                    — 列出已配对设备');
  console.log('  node devices.js --list             — 列出已配对设备');
  console.log('  node devices.js --revoke <deviceId> — 撤销单个设备');
  console.log('  node devices.js --revoke-all        — 撤销全部设备（紧急下线）');
  console.log('  node devices.js --rotate-key        — 轮换主密钥（全部设备需重新配对）');
  console.log('  node devices.js --rotate-token      — 轮换管理 Token');
}

async function list() {
  const r = await fetch(`${base}/api/local/devices`, { headers });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  if (!data.devices || data.devices.length === 0) {
    console.log('\nNo paired devices.\n');
    return;
  }
  console.log(`\nPaired devices (${data.devices.length}):`);
  for (const d of data.devices) {
    console.log(`  ${d.id}    (paired ${d.pairedAt})`);
  }
  console.log('');
}

async function revoke(deviceId) {
  const r = await fetch(`${base}/api/local/revoke`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ deviceId }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  console.log(`\nRevoked: ${data.revoked}  (${data.remaining} remaining)\n`);
}

async function revokeAll() {
  const r = await fetch(`${base}/api/local/revoke-all`, {
    method: 'POST',
    headers,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  console.log(`\nRevoked ${data.revoked} device(s). All devices are now offline.\n`);
}

async function rotateKey() {
  const r = await fetch(`${base}/api/local/rotate-key`, { method: 'POST', headers });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  console.log(`\nMaster key rotated. ${data.revoked} device(s) must re-pair.\n`);
}

async function rotateToken() {
  const r = await fetch(`${base}/api/local/rotate-token`, { method: 'POST', headers });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  console.log(`\nAdmin token rotated. New token: ${data.adminToken}\n`);
}

(async () => {
  try {
    if (cmd === '--list' || cmd === '-l') {
      await list();
    } else if (cmd === '--revoke' || cmd === '-r') {
      const deviceId = args[1];
      if (!deviceId) { usage(); process.exit(1); }
      await revoke(deviceId);
    } else if (cmd === '--revoke-all' || cmd === '-R') {
      await revokeAll();
    } else if (cmd === '--rotate-key' || cmd === '-k') {
      await rotateKey();
    } else if (cmd === '--rotate-token' || cmd === '-t') {
      await rotateToken();
    } else if (cmd === '--help' || cmd === '-h') {
      usage();
    } else {
      usage();
      process.exit(1);
    }
  } catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
  }
})();
