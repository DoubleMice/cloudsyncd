const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const test = require('node:test');

const client = require('../lib/client');
const profiles = require('../lib/client-profiles');
const {
  cloudflaredRouteDnsArgs,
  cloudflaredRunArgs,
  cloudflaredSetupPlan,
  cloudflaredValidateArgs,
  expandShareAliasArgs,
  main,
  normalizeShareAddArgs,
  parseOptions,
  parseTunnelConfigText,
  resolveTunnelPidFile,
  stopTunnel,
  usage,
} = require('../lib/cli');
const {
  buildRequestSignatureMessage,
  decryptEnvelope,
  deriveRequestAuthKey,
  encodeRemotePath,
  encryptEnvelope,
  hmac,
  hkdf,
} = require('../lib/protocol');

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function encryptedStreamPayload(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    iv,
    payload: Buffer.concat([ciphertext, cipher.getAuthTag()]),
  };
}

async function startMockShareServer() {
  const pin = '123456';
  const masterKey = crypto.randomBytes(32);
  const pairKey = crypto.createECDH('prime256v1');
  pairKey.generateKeys();
  const devices = new Set();
  const entries = [
    { name: '目录', type: 'dir' },
    { name: '目录/文件 空格.txt', type: 'file', size: 12, modified: '2026-07-06T00:00:00.000Z' },
  ];
  const files = new Map([
    ['目录/文件 空格.txt', Buffer.from('hello world\n')],
  ]);

  function requireAuth(req, res) {
    const deviceId = req.headers['x-device-id'];
    const timestamp = req.headers['x-auth-timestamp'];
    const nonce = req.headers['x-auth-nonce'];
    const signature = req.headers['x-auth-signature'];
    if (!deviceId || !timestamp || !nonce || !signature || !devices.has(deviceId)) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request authentication' }));
      return false;
    }
    const bodyHash = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    const expected = hmac(
      deriveRequestAuthKey(masterKey, deviceId),
      buildRequestSignatureMessage(req.method, req.url, timestamp, nonce, bodyHash)
    );
    if (expected !== signature) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request authentication' }));
      return false;
    }
    return true;
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'GET' && url.pathname === '/api/pair/init') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ serverPublicKey: pairKey.getPublicKey('hex') }));
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/pair/verify') {
        const body = JSON.parse((await readBody(req)).toString('utf8'));
        const sharedSecret = pairKey.computeSecret(Buffer.from(body.clientPublicKey, 'hex'));
        const authKey = hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32);
        const expectedProof = hmac(authKey, pin);
        if (body.proof !== expectedProof) {
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid PIN' }));
          return;
        }
        const transportKey = hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32);
        devices.add(body.deviceId);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          serverProof: hmac(authKey, 'server-confirmed'),
          encryptedMasterKey: encryptEnvelope(transportKey, masterKey),
        }));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/files') {
        if (!requireAuth(req, res)) return;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ encrypted: encryptEnvelope(masterKey, Buffer.from(JSON.stringify(entries))) }));
        return;
      }

      if (req.method === 'GET' && url.pathname.startsWith('/api/files/')) {
        if (!requireAuth(req, res)) return;
        const remotePath = decodeURIComponent(url.pathname.slice('/api/files/'.length));
        const payload = files.get(remotePath);
        if (!payload) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Not found' }));
          return;
        }
        const encrypted = encryptedStreamPayload(masterKey, payload);
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'x-encrypted-iv': encrypted.iv.toString('hex'),
          'x-encrypted-tag-length': '16',
          'x-file-name': encodeURIComponent(path.basename(remotePath)),
          'x-file-size': String(payload.length),
        });
        res.end(encrypted.payload);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/batch') {
        if (!requireAuth(req, res)) return;
        if (url.searchParams.get('since') === 'empty') {
          res.writeHead(204);
          res.end();
          return;
        }
      }

      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    } catch (err) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    pin,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function startMockServerWithoutPairing() {
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && new URL(req.url, 'http://127.0.0.1').pathname === '/api/pair/init') {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'No active pairing session. Generate a new PIN on the server.' }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function withTempConfig() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-test-'));
  process.env.CLOUDSYNCD_CONFIG_DIR = dir;
  return dir;
}

test.afterEach(() => {
  delete process.env.CLOUDSYNCD_CONFIG_DIR;
  delete process.env.CLOUDSYNCD_CLIENT_PROFILE_FILE;
});

test('help output separates server and client roles', () => {
  const text = usage();
  assert.match(text, /encrypted file sharing/);
  assert.match(text, /server\s+Share-side commands/);
  assert.match(text, /client\s+Receive-side commands/);
  assert.match(text, /npm link/);
  assert.match(text, /cloudsyncd server start \[--tunnel\]/);
  assert.match(text, /cloudsyncd server tunnel setup \[--start\]/);
  assert.match(text, /cloudsyncd server tunnel stop/);
  assert.match(text, /cloudsyncd server tunnel validate/);
  assert.match(text, /cloudsyncd server tunnel route-dns/);
  assert.match(text, /cloudsyncd server start/);
  assert.match(text, /cloudsyncd client get/);
  assert.match(text, /cloudsyncd share <paths/);
  assert.match(text, /cloudsyncd receive/);
  assert.match(text, /automatically pair/);
  assert.match(text, /Tunnel setup:/);
  assert.match(text, /cloudflared tunnel create sync/);
  assert.match(text, /Edit cloudflared-config\.yml/);
  assert.match(text, /Tunnel commands:/);
  assert.match(text, /setup\s+Validate cloudflared-config\.yml/);
  assert.match(text, /start\s+Start cloudflared in the background/);
  assert.match(text, /stop\s+Stop the CLI-managed cloudflared process/);
  assert.match(text, /Named tunnel start requires cloudflared-config\.yml/);
  assert.match(text, /tunnel setup reads tunnel and hostname/);
  assert.match(text, /setup --start/);
  assert.match(text, /setup --tunnel/);
  assert.match(text, /client-profiles\.json/);
  assert.match(text, /no plain curl URL/);
});

test('share alias defaults to add and resolves paths from caller cwd', () => {
  const callerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-share-cwd-'));
  const relativePath = path.join('dist', 'offline', 'patch.tar.gz');

  assert.deepStrictEqual(
    expandShareAliasArgs([relativePath]),
    ['share', 'add', relativePath]
  );
  assert.deepStrictEqual(
    expandShareAliasArgs(['--copy', relativePath]),
    ['share', 'add', '--copy', relativePath]
  );
  assert.deepStrictEqual(expandShareAliasArgs(['list']), ['share', 'list']);
  assert.deepStrictEqual(expandShareAliasArgs(['clear']), ['share', 'clear']);

  assert.deepStrictEqual(
    normalizeShareAddArgs(['--copy', relativePath], callerDir),
    ['--copy', path.join(callerDir, relativePath)]
  );
  assert.deepStrictEqual(
    normalizeShareAddArgs(['/tmp/already-absolute.tar.gz'], callerDir),
    ['/tmp/already-absolute.tar.gz']
  );
});

test('option parser handles client flags and rejects missing values', () => {
  const parsed = parseOptions([
    'https://share.example',
    '目录/a.txt',
    '-o',
    'out.txt',
    '--force',
    '--pin',
    '123456',
    '--since',
    '2026-07-01T00:00:00.000Z',
    '--start',
    '--tunnel',
    '--config',
    'cloudflared-config.yml',
    '--name',
    'sync',
    '--hostname',
    'sync.example.com',
    '--pidfile',
    '/tmp/cloudflared-sync.pid',
  ]);

  assert.deepStrictEqual(parsed.positionals, ['https://share.example', '目录/a.txt']);
  assert.deepStrictEqual(parsed.options, {
    output: 'out.txt',
    force: true,
    pin: '123456',
    since: '2026-07-01T00:00:00.000Z',
    start: true,
    tunnel: true,
    config: 'cloudflared-config.yml',
    name: 'sync',
    hostname: 'sync.example.com',
    pidfile: '/tmp/cloudflared-sync.pid',
  });

  assert.throws(() => parseOptions(['--pin']), /--pin requires a value/);
  assert.throws(() => parseOptions(['-o']), /-o requires a value/);
  assert.throws(() => parseOptions(['--since']), /--since requires a value/);
  assert.throws(() => parseOptions(['--config']), /--config requires a value/);
  assert.throws(() => parseOptions(['--name']), /--name requires a value/);
  assert.throws(() => parseOptions(['--hostname']), /--hostname requires a value/);
  assert.throws(() => parseOptions(['--pidfile']), /--pidfile requires a value/);
});

test('cloudflared helper args match documented tunnel commands', () => {
  const config = path.resolve('cloudflared-config.yml');
  assert.deepStrictEqual(
    cloudflaredRunArgs({ config: 'cloudflared-config.yml', name: 'sync' }),
    ['tunnel', '--config', config, '--pidfile', '/tmp/cloudflared-sync.pid', 'run', 'sync']
  );
  assert.deepStrictEqual(
    cloudflaredRunArgs({ config: 'cloudflared-config.yml' }),
    ['tunnel', '--config', config, '--pidfile', '/tmp/cloudflared-sync.pid', 'run']
  );
  assert.deepStrictEqual(
    cloudflaredValidateArgs({ config: 'cloudflared-config.yml' }),
    ['tunnel', '--config', config, 'ingress', 'validate']
  );
  assert.deepStrictEqual(
    cloudflaredRouteDnsArgs('sync.example.com', { name: 'sync' }),
    ['tunnel', 'route', 'dns', 'sync', 'sync.example.com']
  );
  assert.throws(() => cloudflaredRouteDnsArgs('', { name: 'sync' }), /route-dns <hostname>/);
});

test('tunnel pidfile defaults and stop stale process handling', () => {
  assert.strictEqual(resolveTunnelPidFile({ name: 'sync' }), '/tmp/cloudflared-sync.pid');
  assert.strictEqual(resolveTunnelPidFile({ name: 'name with spaces' }), '/tmp/cloudflared-name-with-spaces.pid');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-tunnel-stop-'));
  assert.strictEqual(stopTunnel({ pidfile: path.join(dir, 'missing.pid') }), 0);

  const pidfile = path.join(dir, 'cloudflared.pid');
  fs.writeFileSync(pidfile, '99999999');

  assert.strictEqual(stopTunnel({ pidfile }), 0);
  assert.strictEqual(fs.existsSync(pidfile), false);

  fs.writeFileSync(pidfile, 'not-a-pid');
  assert.strictEqual(stopTunnel({ pidfile }), 0);
  assert.strictEqual(fs.existsSync(pidfile), false);
});

test('tunnel setup reads tunnel and hostname from config file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-tunnel-test-'));
  const config = path.join(dir, 'cloudflared-config.yml');
  fs.writeFileSync(config, [
    'tunnel: tunnel-from-config',
    'credentials-file: /tmp/tunnel.json',
    'ingress:',
    '  - hostname: "sync.mydomain.test"',
    '    service: http://127.0.0.1:21891',
    '  - service: http_status:404',
  ].join('\n'));

  const parsed = parseTunnelConfigText(fs.readFileSync(config, 'utf8'));
  assert.deepStrictEqual(parsed, {
    tunnel: 'tunnel-from-config',
    credentialsFile: '/tmp/tunnel.json',
    hostname: 'sync.mydomain.test',
  });

  const plan = cloudflaredSetupPlan({ config });
  assert.strictEqual(plan.tunnel, 'tunnel-from-config');
  assert.strictEqual(plan.hostname, 'sync.mydomain.test');
  assert.deepStrictEqual(plan.validateArgs, ['tunnel', '--config', config, 'ingress', 'validate']);
  assert.deepStrictEqual(plan.routeDnsArgs, ['tunnel', 'route', 'dns', 'tunnel-from-config', 'sync.mydomain.test']);

  const overridden = cloudflaredSetupPlan({ config, name: 'override-tunnel', hostname: 'override.example.com' });
  assert.deepStrictEqual(overridden.routeDnsArgs, ['tunnel', 'route', 'dns', 'override-tunnel', 'override.example.com']);
});

test('tunnel setup rejects placeholder config values', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-tunnel-placeholder-'));
  const config = path.join(dir, 'cloudflared-config.yml');
  fs.writeFileSync(config, fs.readFileSync(path.join(__dirname, '..', 'cloudflared-config.example.yml'), 'utf8'));

  assert.throws(
    () => cloudflaredSetupPlan({ config }),
    /missing a real tunnel value/
  );
});

test('receive alias routes to client logout', async () => {
  withTempConfig();
  const baseUrl = 'http://127.0.0.1:1';
  profiles.saveProfile(baseUrl, {
    deviceId: 'client-alias',
    masterKey: Buffer.alloc(32, 2).toString('hex'),
    pairedAt: new Date().toISOString(),
  });

  let output = '';
  const originalWrite = process.stdout.write;
  process.stdout.write = (chunk, ...args) => {
    output += String(chunk);
    if (typeof args[args.length - 1] === 'function') args[args.length - 1]();
    return true;
  };
  try {
    await main(['receive', 'logout', baseUrl]);
  } finally {
    process.stdout.write = originalWrite;
  }

  assert.match(output, /Receiver profile removed/);
  assert.strictEqual(profiles.getProfile(baseUrl), null);
});

test('protocol helpers encode remote paths and sign request messages', () => {
  assert.strictEqual(encodeRemotePath('/目录/文件 空格.txt'), '%E7%9B%AE%E5%BD%95/%E6%96%87%E4%BB%B6%20%E7%A9%BA%E6%A0%BC.txt');
  const key = Buffer.alloc(32, 7);
  const headers = require('../lib/protocol').signRequest({
    masterKey: key,
    deviceId: 'client-test',
    method: 'GET',
    signedPath: '/api/files/a%20b.txt',
    timestamp: '1',
    nonce: 'n',
  });
  const expected = hmac(
    deriveRequestAuthKey(key, 'client-test'),
    buildRequestSignatureMessage('GET', '/api/files/a%20b.txt', '1', 'n', crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex'))
  );
  assert.strictEqual(headers['X-Auth-Signature'], expected);
});

test('client list auto-pairs and stores a receiver profile', async () => {
  withTempConfig();
  const server = await startMockShareServer();
  try {
    const entries = await client.listFiles(server.baseUrl, { pin: server.pin });
    assert.strictEqual(entries.find((entry) => entry.type === 'file').name, '目录/文件 空格.txt');
    const profile = profiles.getProfile(server.baseUrl);
    assert.ok(profile.deviceId.startsWith('client-'));
    assert.strictEqual(profile.masterKey.length, 64);
    const mode = fs.statSync(profiles.profileFile()).mode & 0o777;
    assert.strictEqual(mode, 0o600);
  } finally {
    await server.close();
  }
});

test('client pairing checks active server PIN before requiring a PIN', async () => {
  withTempConfig();
  const server = await startMockServerWithoutPairing();
  try {
    await assert.rejects(
      () => client.listFiles(server.baseUrl),
      /Generate a PIN on the server with: cloudsyncd server pin/
    );
    assert.strictEqual(profiles.getProfile(server.baseUrl), null);
  } finally {
    await server.close();
  }
});

test('client pairing requires --pin in non-interactive mode after active PIN exists', async () => {
  withTempConfig();
  const server = await startMockShareServer();
  const originalIsTTY = process.stdin.isTTY;
  process.stdin.isTTY = false;
  try {
    await assert.rejects(
      () => client.listFiles(server.baseUrl),
      /Missing --pin/
    );
    assert.strictEqual(profiles.getProfile(server.baseUrl), null);
  } finally {
    process.stdin.isTTY = originalIsTTY;
    await server.close();
  }
});

test('client pairing with invalid PIN does not save a profile', async () => {
  withTempConfig();
  const server = await startMockShareServer();
  try {
    await assert.rejects(
      () => client.listFiles(server.baseUrl, { pin: '000000' }),
      /Invalid PIN/
    );
    assert.strictEqual(profiles.getProfile(server.baseUrl), null);
  } finally {
    await server.close();
  }
});

test('client reports actionable network errors for unreachable share URL', async () => {
  withTempConfig();
  const probe = http.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  const baseUrl = `http://127.0.0.1:${port}`;

  await assert.rejects(
    () => client.listFiles(baseUrl),
    (err) => {
      assert.match(err.message, new RegExp(`Cannot reach cloudsyncd share URL: http://127\\.0\\.0\\.1:${port}/api/pair/init`));
      assert.match(err.message, /Check the URL, DNS\/TLS, firewall/);
      assert.match(err.message, /127\.0\.0\.1:21891/);
      assert.notStrictEqual(err.message, 'fetch failed');
      return true;
    }
  );
});

test('client get decrypts unicode path downloads and refuses overwrite', async () => {
  const dir = withTempConfig();
  const server = await startMockShareServer();
  const out = path.join(dir, 'download.txt');
  try {
    const result = await client.downloadFile(server.baseUrl, '目录/文件 空格.txt', { pin: server.pin, output: out });
    assert.strictEqual(result.outputPath, out);
    assert.strictEqual(fs.readFileSync(out, 'utf8'), 'hello world\n');
    await assert.rejects(
      () => client.downloadFile(server.baseUrl, '目录/文件 空格.txt', { output: out }),
      /already exists/
    );
    await client.downloadFile(server.baseUrl, '目录/文件 空格.txt', { output: out, force: true });
    assert.strictEqual(fs.readFileSync(out, 'utf8'), 'hello world\n');

    const outputDir = path.join(dir, 'downloads');
    fs.mkdirSync(outputDir);
    const namedResult = await client.downloadFile(server.baseUrl, '目录/文件 空格.txt', { output: outputDir });
    assert.strictEqual(namedResult.outputPath, path.join(outputDir, '文件 空格.txt'));
    assert.strictEqual(fs.readFileSync(namedResult.outputPath, 'utf8'), 'hello world\n');
  } finally {
    await server.close();
  }
});

test('client get treats trailing-slash output as a directory', async () => {
  const dir = withTempConfig();
  const server = await startMockShareServer();
  const outputDir = path.join(dir, 'slash-output');
  try {
    const result = await client.downloadFile(server.baseUrl, '目录/文件 空格.txt', {
      pin: server.pin,
      output: `${outputDir}/`,
    });
    assert.strictEqual(result.outputPath, path.join(outputDir, '文件 空格.txt'));
    assert.strictEqual(fs.readFileSync(result.outputPath, 'utf8'), 'hello world\n');
  } finally {
    await server.close();
  }
});

test('client batch 204 does not create an output file', async () => {
  const dir = withTempConfig();
  const server = await startMockShareServer();
  const out = path.join(dir, 'empty.tar.gz');
  try {
    const result = await client.downloadBatch(server.baseUrl, { pin: server.pin, output: out, since: 'empty' });
    assert.strictEqual(result.empty, true);
    assert.strictEqual(fs.existsSync(out), false);
  } finally {
    await server.close();
  }
});

test('client repairs stale profile after a 401 and retries once', async () => {
  withTempConfig();
  const server = await startMockShareServer();
  try {
    profiles.saveProfile(server.baseUrl, {
      deviceId: 'client-stale',
      masterKey: Buffer.alloc(32, 1).toString('hex'),
      pairedAt: new Date().toISOString(),
    });
    const entries = await client.listFiles(server.baseUrl, { pin: server.pin });
    assert.strictEqual(entries.length, 2);
    assert.notStrictEqual(profiles.getProfile(server.baseUrl).deviceId, 'client-stale');
  } finally {
    await server.close();
  }
});
