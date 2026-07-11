#!/usr/bin/env node
// Local device management for cloudsyncd.
// Lists, revokes, or revokes-all paired devices via the local admin API.
// Run while the server is up (the server must be listening on loopback).

const { fetchAdminJson } = require('../lib/local-admin');

const args = process.argv.slice(2);
const cmd = args[0] || '--list';

function usage() {
  console.log('用法:');
  console.log('  cloudsyncd server devices           — 列出已配对设备');
  console.log('  cloudsyncd server revoke <deviceId> — 撤销单个设备');
  console.log('  cloudsyncd server revoke-all        — 撤销全部设备（紧急下线）');
  console.log('  cloudsyncd server rotate-key        — 轮换主密钥（全部设备需重新配对）');
  console.log('  cloudsyncd server rotate-token      — 轮换管理 Token');
}

async function list() {
  const data = await fetchAdminJson('/api/local/devices');
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
  const data = await fetchAdminJson('/api/local/revoke', {
    method: 'POST',
    body: { deviceId },
  });
  console.log(`\nRevoked: ${data.revoked}  (${data.remaining} remaining)\n`);
}

async function revokeAll() {
  const data = await fetchAdminJson('/api/local/revoke-all', {
    method: 'POST',
  });
  console.log(`\nRevoked ${data.revoked} device(s). All devices are now offline.\n`);
}

async function rotateKey() {
  const data = await fetchAdminJson('/api/local/rotate-key', { method: 'POST' });
  console.log(`\nMaster key rotated. ${data.revoked} device(s) must re-pair.\n`);
}

async function rotateToken() {
  const data = await fetchAdminJson('/api/local/rotate-token', { method: 'POST' });
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
