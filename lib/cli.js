const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const client = require('./client');
const { fetchAdminJson } = require('./local-admin');
const { formatSize } = require('./format');

const ROOT = path.resolve(__dirname, '..');

function print(text, stream = process.stdout) {
  stream.write(`${text}\n`);
}

function usage() {
  return `cloudsyncd - encrypted file sharing over a paired server/client workflow

Roles:
  server   Share-side commands. Run these on the machine that owns shared/.
  client   Receive-side commands. Run these on the machine downloading files.

Install:
  npm install
  npm link                 # exposes cloudsyncd on PATH
  npm unlink -g cloudsyncd # removes the global command

Usage:
  cloudsyncd server start [--tunnel] [--config FILE] [--name NAME]
  cloudsyncd server status
  cloudsyncd server share add <paths...> [--copy]
  cloudsyncd server share list
  cloudsyncd server share clear
  cloudsyncd server tunnel setup [--start] [--config FILE] [--name NAME] [--hostname HOST]
  cloudsyncd server tunnel start [--config FILE] [--name NAME]
  cloudsyncd server tunnel stop [--name NAME] [--pidfile FILE]
  cloudsyncd server tunnel validate [--config FILE]
  cloudsyncd server tunnel route-dns <hostname> [--name NAME]
  cloudsyncd server pin
  cloudsyncd server devices
  cloudsyncd server revoke <deviceId>
  cloudsyncd server revoke-all
  cloudsyncd server rotate-key
  cloudsyncd server rotate-token

  cloudsyncd client list <share-url> [--json] [--pin <PIN>]
  cloudsyncd client get <share-url> <remote-path> [-o <path>] [--force] [--pin <PIN>]
  cloudsyncd client batch <share-url> [-o <file.tar.gz>] [--since <ISO>] [--force] [--pin <PIN>]
  cloudsyncd client logout <share-url>

Aliases:
  cloudsyncd share <paths...> [--copy] -> cloudsyncd server share add <paths...>
  cloudsyncd share list                -> cloudsyncd server share list
  cloudsyncd share clear               -> cloudsyncd server share clear
  cloudsyncd receive ...  -> cloudsyncd client ...

Typical flow:
  # On the server/share side
  cloudsyncd server tunnel setup
  cloudsyncd server start --tunnel
  cloudsyncd server share add ./file.pdf
  cloudsyncd server pin

  # On the client/receive side
  cloudsyncd client list https://your-sync-host.example
  cloudsyncd client get https://your-sync-host.example "file.pdf"

Tunnel setup:
  1. cloudflared tunnel login
  2. cloudflared tunnel create sync
  3. cp cloudflared-config.example.yml cloudflared-config.yml
  4. Edit cloudflared-config.yml: tunnel, credentials-file, ingress hostname
  5. cloudsyncd server tunnel setup
  6. cloudsyncd server start --tunnel

Tunnel commands:
  setup      Validate cloudflared-config.yml and route its hostname to its tunnel
  validate   Validate local ingress rules only
  route-dns  Bind one DNS hostname to the named tunnel
  start      Start cloudflared in the background using the local config
  stop       Stop the CLI-managed cloudflared process by pidfile

Notes:
  - Named tunnel start requires cloudflared-config.yml with tunnel, credentials-file, and ingress hostname.
  - tunnel setup reads tunnel and hostname from cloudflared-config.yml, then validates and routes DNS.
  - Use cloudsyncd server tunnel setup --start to validate, route DNS, and start the tunnel.
  - setup --tunnel is accepted as an alias for setup --start.
  - client list/get/batch automatically pair when no profile exists.
  - Use --pin <PIN> for non-interactive scripts.
  - --config defaults to this repo's cloudflared-config.yml for tunnel commands.
  - --name defaults to sync for named Cloudflare Tunnel commands.
  - --pidfile defaults to /tmp/cloudflared-<name>.pid for tunnel stop.
  - Receiver profiles are stored in ~/.config/cloudsyncd/client-profiles.json.
  - Local admin at 127.0.0.1:21900 opens without login by default; set ADMIN_AUTH=1 to require token auth.
  - Downloads are authenticated and AES-GCM encrypted; there is no plain curl URL.`;
}

function parseOptions(argv) {
  const positionals = [];
  const options = {};
  const requireValue = (flag, index) => {
    if (index + 1 >= argv.length) throw new Error(`${flag} requires a value`);
    return argv[index + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') options.json = true;
    else if (arg === '--force') options.force = true;
    else if (arg === '--copy') options.copy = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--start') options.start = true;
    else if (arg === '--tunnel') options.tunnel = true;
    else if (arg === '--pin') options.pin = requireValue(arg, i++);
    else if (arg === '--since') options.since = requireValue(arg, i++);
    else if (arg === '--output' || arg === '-o') options.output = requireValue(arg, i++);
    else if (arg === '--config' || arg === '--tunnel-config') options.config = requireValue(arg, i++);
    else if (arg === '--name' || arg === '--tunnel-name') options.name = requireValue(arg, i++);
    else if (arg === '--hostname') options.hostname = requireValue(arg, i++);
    else if (arg === '--pidfile' || arg === '--pid-file') options.pidfile = requireValue(arg, i++);
    else positionals.push(arg);
  }
  return { positionals, options };
}

function normalizeShareAddArgs(args, baseDir = process.cwd()) {
  return args.map((arg) => {
    if (arg === '--copy') return arg;
    return path.isAbsolute(arg) ? arg : path.resolve(baseDir, arg);
  });
}

function expandShareAliasArgs(rest) {
  const [first, ...tail] = rest;
  if (!first || first === '--help' || first === '-h') return ['share', ...rest];
  if (first === 'add' || first === 'list' || first === 'clear') return ['share', ...rest];
  return ['share', 'add', first, ...tail];
}

function runNodeScript(script, args = []) {
  const result = spawnSync(process.execPath, [path.join(ROOT, script), ...args], {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  return result.status || 0;
}

function ensureCloudflared() {
  const result = spawnSync('cloudflared', ['--version'], { stdio: 'ignore' });
  if (result.error || result.status !== 0) {
    throw new Error('cloudflared is not installed or not available in PATH');
  }
}

function resolveTunnelConfig(options = {}) {
  const config = options.config || process.env.TUNNEL_CONFIG || path.join(ROOT, 'cloudflared-config.yml');
  return path.isAbsolute(config) ? config : path.resolve(process.cwd(), config);
}

function resolveTunnelName(options = {}) {
  return options.name || process.env.TUNNEL_NAME || 'sync';
}

function safeTunnelName(name) {
  return String(name || 'sync').replace(/[^a-zA-Z0-9_.-]/g, '-');
}

function resolveTunnelPidFile(options = {}) {
  if (options.pidfile) return path.resolve(options.pidfile);
  if (process.env.TUNNEL_PIDFILE) return path.resolve(process.env.TUNNEL_PIDFILE);
  return path.join('/tmp', `cloudflared-${safeTunnelName(resolveTunnelName(options))}.pid`);
}

function resolveTunnelLogFile(options = {}) {
  if (options.logfile) return path.resolve(options.logfile);
  if (process.env.TUNNEL_LOGFILE) return path.resolve(process.env.TUNNEL_LOGFILE);
  return path.join('/tmp', `cloudflared-${safeTunnelName(resolveTunnelName(options))}.log`);
}

function requireTunnelConfig(config) {
  if (!fs.existsSync(config)) {
    throw new Error(`Named tunnel start requires a config file: ${config}. Copy cloudflared-config.example.yml to cloudflared-config.yml, then fill tunnel, credentials-file, and hostname.`);
  }
}

function cleanYamlScalar(value) {
  const trimmed = String(value || '').trim();
  if (!trimmed) return '';
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed.replace(/\s+#.*$/, '').trim();
}

function isPlaceholder(value) {
  return !value || /^<.*>$/.test(value) || value === 'sync.example.com';
}

function parseTunnelConfigText(text) {
  const result = { tunnel: '', credentialsFile: '', hostname: '' };
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    let match = trimmed.match(/^tunnel:\s*(.+)$/);
    if (match && !result.tunnel) {
      result.tunnel = cleanYamlScalar(match[1]);
      continue;
    }

    match = trimmed.match(/^credentials-file:\s*(.+)$/);
    if (match && !result.credentialsFile) {
      result.credentialsFile = cleanYamlScalar(match[1]);
      continue;
    }

    match = trimmed.match(/^-?\s*hostname:\s*(.+)$/);
    if (match && !result.hostname) {
      result.hostname = cleanYamlScalar(match[1]);
    }
  }
  return result;
}

function readTunnelConfig(options = {}) {
  const config = resolveTunnelConfig(options);
  requireTunnelConfig(config);
  return {
    path: config,
    ...parseTunnelConfigText(fs.readFileSync(config, 'utf8')),
  };
}

function configuredTunnelTarget(options = {}) {
  const parsed = readTunnelConfig(options);
  const tunnel = options.name || process.env.TUNNEL_NAME || parsed.tunnel;
  const hostname = options.hostname || parsed.hostname;
  if (isPlaceholder(tunnel)) {
    throw new Error(`Tunnel config is missing a real tunnel value: ${parsed.path}`);
  }
  if (isPlaceholder(hostname)) {
    throw new Error(`Tunnel config is missing a real ingress hostname: ${parsed.path}`);
  }
  return { ...parsed, tunnel, hostname };
}

function cloudflaredRunArgs(options = {}) {
  const args = [
    'tunnel',
    '--config', resolveTunnelConfig(options),
    '--pidfile', resolveTunnelPidFile(options),
    'run',
  ];
  if (options.name || process.env.TUNNEL_NAME) {
    args.push(resolveTunnelName(options));
  }
  return args;
}

function cloudflaredValidateArgs(options = {}) {
  return ['tunnel', '--config', resolveTunnelConfig(options), 'ingress', 'validate'];
}

function cloudflaredRouteDnsArgs(hostname, options = {}) {
  if (!hostname) throw new Error('Usage: cloudsyncd server tunnel route-dns <hostname> [--name NAME]');
  return ['tunnel', 'route', 'dns', resolveTunnelName(options), hostname];
}

function cloudflaredSetupPlan(options = {}) {
  const target = configuredTunnelTarget(options);
  return {
    ...target,
    validateArgs: cloudflaredValidateArgs({ ...options, config: target.path }),
    routeDnsArgs: ['tunnel', 'route', 'dns', target.tunnel, target.hostname],
  };
}

function runCloudflared(args) {
  ensureCloudflared();
  const result = spawnSync('cloudflared', args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  return result.status || 0;
}

function isProcessRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err.code === 'ESRCH') return false;
    if (err.code === 'EPERM') return true;
    throw err;
  }
}

function readPid(pidfile) {
  const raw = fs.readFileSync(pidfile, 'utf8').trim();
  const pid = Number.parseInt(raw, 10);
  return Number.isFinite(pid) && pid > 0 ? pid : null;
}

function clearStaleTunnelPidfile(pidfile) {
  if (!fs.existsSync(pidfile)) return;
  const pid = readPid(pidfile);
  if (!pid) {
    fs.rmSync(pidfile, { force: true });
    print(`Removed invalid tunnel pidfile: ${pidfile}`);
    return;
  }
  if (isProcessRunning(pid)) {
    throw new Error(`Tunnel already appears to be running (pid ${pid}, pidfile: ${pidfile}). Stop it first with cloudsyncd server tunnel stop.`);
  }
  fs.rmSync(pidfile, { force: true });
  print(`Removed stale tunnel pidfile: ${pidfile}`);
}

function tunnelLabel(options = {}) {
  if (options.name || process.env.TUNNEL_NAME) return resolveTunnelName(options);
  return 'configured tunnel';
}

function stopTunnel(options = {}) {
  const pidfile = resolveTunnelPidFile(options);
  if (!fs.existsSync(pidfile)) {
    print(`No CLI-managed Cloudflare Tunnel pidfile found: ${pidfile}`);
    return 0;
  }

  const pid = readPid(pidfile);
  if (!pid) {
    fs.rmSync(pidfile, { force: true });
    print(`Removed invalid tunnel pidfile: ${pidfile}`);
    return 0;
  }

  try {
    process.kill(pid, 'SIGTERM');
  } catch (err) {
    if (err.code === 'ESRCH') {
      fs.rmSync(pidfile, { force: true });
      print(`Tunnel process ${pid} is not running; removed stale pidfile: ${pidfile}`);
      return 0;
    }
    throw err;
  }

  fs.rmSync(pidfile, { force: true });
  print(`Stopped Cloudflare Tunnel process ${pid}.`);
  return 0;
}

async function waitForTunnelStartup(child, logPath) {
  const earlyExit = await Promise.race([
    new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => child.once('error', (error) => resolve({ error }))),
    new Promise((resolve) => setTimeout(() => resolve(null), 800)),
  ]);
  if (!earlyExit) return;
  if (earlyExit.error) throw earlyExit.error;
  throw new Error(`cloudflared exited early (${earlyExit.signal || earlyExit.code}). Check logs: ${logPath}`);
}

function prepareTunnelStart(options = {}) {
  ensureCloudflared();
  const config = resolveTunnelConfig(options);
  requireTunnelConfig(config);

  const plan = {
    name: tunnelLabel(options),
    logPath: resolveTunnelLogFile(options),
    pidfile: resolveTunnelPidFile(options),
    args: cloudflaredRunArgs(options),
  };
  clearStaleTunnelPidfile(plan.pidfile);
  return plan;
}

function spawnCloudflaredTunnel(plan, spawnOptions = {}) {
  const logFd = fs.openSync(plan.logPath, 'a');
  try {
    return spawn('cloudflared', plan.args, {
      ...spawnOptions,
      stdio: ['ignore', logFd, logFd],
    });
  } finally {
    fs.closeSync(logFd);
  }
}

function writeTunnelPidfile(pidfile, child) {
  if (!fs.existsSync(pidfile)) {
    fs.writeFileSync(pidfile, String(child.pid), { mode: 0o600 });
  }
}

function registerTunnelProcessCleanup(child, pidfile) {
  const cleanup = () => {
    if (!child.killed) child.kill();
    fs.rmSync(pidfile, { force: true });
  };
  process.once('exit', cleanup);
  process.once('SIGINT', () => {
    cleanup();
    process.exit(130);
  });
  process.once('SIGTERM', () => {
    cleanup();
    process.exit(143);
  });
}

async function startTunnelBackground(options = {}) {
  const plan = prepareTunnelStart(options);

  print(`Starting Cloudflare Tunnel (${plan.name}) in the background...`);
  const child = spawnCloudflaredTunnel(plan);
  registerTunnelProcessCleanup(child, plan.pidfile);

  await waitForTunnelStartup(child, plan.logPath);

  writeTunnelPidfile(plan.pidfile, child);
  print(`  tunnel pid: ${child.pid}  (pidfile: ${plan.pidfile}, logs: ${plan.logPath})`);
}

async function startTunnelDetached(options = {}) {
  const plan = prepareTunnelStart(options);

  print(`Starting Cloudflare Tunnel (${plan.name}) in the background...`);
  const child = spawnCloudflaredTunnel(plan, { detached: true });

  try {
    await waitForTunnelStartup(child, plan.logPath);
  } catch (err) {
    fs.rmSync(plan.pidfile, { force: true });
    throw err;
  }

  writeTunnelPidfile(plan.pidfile, child);
  child.unref();
  print(`  tunnel pid: ${child.pid}  (pidfile: ${plan.pidfile}, logs: ${plan.logPath})`);
}

async function runServer(argv) {
  const [cmd, subcmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h') {
    print(usage());
    return 0;
  }

  if (cmd === 'start') {
    const { options } = parseOptions([subcmd, ...rest].filter(Boolean));
    if (options.tunnel || process.env.WITH_TUNNEL === '1') {
      await startTunnelBackground(options);
    }
    require(path.join(ROOT, 'server.js'));
    return 0;
  }

  if (cmd === 'tunnel') {
    const { positionals, options } = parseOptions(rest);
    if (subcmd === 'setup') {
      const plan = cloudflaredSetupPlan(options);
      print(`Using tunnel config: ${plan.path}`);
      print(`  tunnel: ${plan.tunnel}`);
      print(`  hostname: ${plan.hostname}`);
      print('Validating ingress config...');
      const validateStatus = runCloudflared(plan.validateArgs);
      if (validateStatus !== 0) return validateStatus;
      print('Routing DNS hostname to tunnel...');
      const routeStatus = runCloudflared(plan.routeDnsArgs);
      if (routeStatus !== 0) return routeStatus;
      if (options.start || options.tunnel) {
        await startTunnelDetached({ ...options, config: plan.path });
        print('Tunnel setup complete and tunnel started.');
      } else {
        print('Tunnel setup complete. Start with: cloudsyncd server start --tunnel or cloudsyncd server tunnel start');
      }
      return 0;
    }
    if (subcmd === 'start') {
      await startTunnelDetached(options);
      return 0;
    }
    if (subcmd === 'stop') {
      return stopTunnel(options);
    }
    if (subcmd === 'validate') {
      const config = resolveTunnelConfig(options);
      requireTunnelConfig(config);
      return runCloudflared(cloudflaredValidateArgs(options));
    }
    if (subcmd === 'route-dns') {
      return runCloudflared(cloudflaredRouteDnsArgs(positionals[0], options));
    }
    throw new Error('Usage: cloudsyncd server tunnel <setup|start|stop|validate|route-dns>');
  }

  if (cmd === 'status') {
    const status = await fetchAdminJson('/api/local/status');
    print(`cloudsyncd server`);
    print(`  paired devices: ${status.deviceCount}`);
    print(`  shared files: ${status.sharedFiles} (${formatSize(status.sharedSize)})`);
    print(`  shared texts: ${status.textsCount}/${status.textsMax}`);
    print(`  started: ${new Date(status.startedAt).toLocaleString()}`);
    return 0;
  }

  if (cmd === 'pin') {
    const data = await fetchAdminJson('/api/local/new-pin', { method: 'POST' });
    print(`\nNew pairing PIN: ${data.pin}\n`);
    return 0;
  }

  if (cmd === 'share') {
    if (subcmd === 'add') {
      return runNodeScript('share.js', normalizeShareAddArgs(rest));
    }
    if (subcmd === 'list') return runNodeScript('share.js', ['--list']);
    if (subcmd === 'clear') return runNodeScript('share.js', ['--clear']);
    throw new Error('Usage: cloudsyncd server share <add|list|clear>');
  }

  if (cmd === 'devices') return runNodeScript('devices.js', ['--list']);
  if (cmd === 'revoke') {
    if (!subcmd) throw new Error('Usage: cloudsyncd server revoke <deviceId>');
    return runNodeScript('devices.js', ['--revoke', subcmd]);
  }
  if (cmd === 'revoke-all') return runNodeScript('devices.js', ['--revoke-all']);
  if (cmd === 'rotate-key') return runNodeScript('devices.js', ['--rotate-key']);
  if (cmd === 'rotate-token') return runNodeScript('devices.js', ['--rotate-token']);

  throw new Error(`Unknown server command: ${cmd}`);
}

function printEntries(entries, options = {}) {
  if (options.json) {
    print(JSON.stringify(entries, null, 2));
    return;
  }
  if (!entries.length) {
    print('No shared files.');
    return;
  }
  for (const entry of entries) {
    if (entry.type === 'dir') {
      print(`[dir]  ${entry.name}/`);
    } else {
      print(`[file] ${entry.name}  ${formatSize(entry.size)}  ${entry.modified}`);
    }
  }
}

async function runClient(argv) {
  const [cmd, ...rest] = argv;
  const { positionals, options } = parseOptions(rest);
  options.stderr = process.stderr;

  if (!cmd || cmd === '--help' || cmd === '-h' || options.help) {
    print(usage());
    return 0;
  }

  if (cmd === 'list') {
    const [baseUrl] = positionals;
    if (!baseUrl) throw new Error('Usage: cloudsyncd client list <share-url>');
    const entries = await client.listFiles(baseUrl, options);
    printEntries(entries, options);
    return 0;
  }

  if (cmd === 'get') {
    const [baseUrl, remotePath] = positionals;
    if (!baseUrl || !remotePath) throw new Error('Usage: cloudsyncd client get <share-url> <remote-path>');
    const result = await client.downloadFile(baseUrl, remotePath, options);
    print(`Downloaded: ${result.outputPath}`);
    return 0;
  }

  if (cmd === 'batch') {
    const [baseUrl] = positionals;
    if (!baseUrl) throw new Error('Usage: cloudsyncd client batch <share-url>');
    const result = await client.downloadBatch(baseUrl, options);
    if (result.empty) print('No files to download.');
    else print(`Downloaded: ${result.outputPath}`);
    return 0;
  }

  if (cmd === 'logout') {
    const [baseUrl] = positionals;
    if (!baseUrl) throw new Error('Usage: cloudsyncd client logout <share-url>');
    const existed = client.logout(baseUrl);
    print(existed ? 'Receiver profile removed.' : 'No receiver profile found.');
    return 0;
  }

  throw new Error(`Unknown client command: ${cmd}`);
}

async function main(argv = process.argv.slice(2)) {
  const [scope, ...rest] = argv;
  if (!scope || scope === '--help' || scope === '-h') {
    print(usage());
    return 0;
  }

  if (scope === 'share') return runServer(expandShareAliasArgs(rest));
  if (scope === 'receive') return runClient(rest);
  if (scope === 'server') return runServer(rest);
  if (scope === 'client') return runClient(rest);

  throw new Error(`Unknown command scope: ${scope}`);
}

module.exports = {
  main,
  usage,
  parseOptions,
  normalizeShareAddArgs,
  expandShareAliasArgs,
  cloudflaredRunArgs,
  cloudflaredValidateArgs,
  cloudflaredRouteDnsArgs,
  cloudflaredSetupPlan,
  parseTunnelConfigText,
  resolveTunnelPidFile,
  stopTunnel,
};
