#!/usr/bin/env node
const { fetchAdminJson } = require('./lib/local-admin');

(async () => {
  try {
    const data = await fetchAdminJson('/api/local/new-pin', { method: 'POST' });
    if (!data.pin) throw new Error('Missing PIN in admin response');
    console.log(`\nNew pairing PIN: ${data.pin}\n`);
  } catch (err) {
    console.error('Error:', err.message || 'Server not running?');
    process.exit(1);
  }
})();
