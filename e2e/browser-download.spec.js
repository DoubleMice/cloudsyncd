const { test, expect } = require('@playwright/test');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const LARGE_FILE_BYTES = 33 * 1024 * 1024 + 123;
const CLI_FILE_BYTES = 5 * 1024 * 1024 + 321;

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function writePatternFile(filePath, size) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const fd = fs.openSync(filePath, 'w');
  const chunk = Buffer.alloc(1024 * 1024);
  try {
    let written = 0;
    while (written < size) {
      const n = Math.min(chunk.length, size - written);
      for (let i = 0; i < n; i += 1) chunk[i] = (written + i) & 0xff;
      fs.writeSync(fd, chunk, 0, n);
      written += n;
    }
  } finally {
    fs.closeSync(fd);
  }
}

function writeSharedFiles(sharedDir, files) {
  for (const [relPath, content] of Object.entries(files)) {
    const target = path.join(sharedDir, relPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function parseStoredZip(bytes) {
  const buffer = Buffer.from(bytes);
  const entries = new Map();
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const sig = buffer.readUInt32LE(offset);
    if (sig === 0x02014b50 || sig === 0x06054b50) break;
    if (sig !== 0x04034b50) throw new Error(`Unexpected zip signature at ${offset}: 0x${sig.toString(16)}`);

    const method = buffer.readUInt16LE(offset + 8);
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const uncompressedSize = buffer.readUInt32LE(offset + 22);
    const nameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    if (method !== 0) throw new Error(`Unexpected compressed zip entry method: ${method}`);
    if (compressedSize !== uncompressedSize) throw new Error('Stored zip entry size mismatch');

    const nameStart = offset + 30;
    const nameEnd = nameStart + nameLength;
    const dataStart = nameEnd + extraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > buffer.length) throw new Error('Zip entry body is truncated');

    const name = buffer.subarray(nameStart, nameEnd).toString('utf8');
    entries.set(name, buffer.subarray(dataStart, dataEnd));
    offset = dataEnd;
  }
  return entries;
}

async function waitForHttp(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
      lastError = new Error(`HTTP ${res.status}`);
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError ? lastError.message : 'no response'}`);
}

function runCli(args, env = {}, timeoutMs = 90000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['bin/cloudsyncd.js', ...args], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`CLI timed out: cloudsyncd ${args.join(' ')}\n${stdout}\n${stderr}`));
    }, timeoutMs);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const result = { code, stdout, stderr };
      if (code !== 0) {
        const err = new Error(`CLI failed (${code}): cloudsyncd ${args.join(' ')}\n${stdout}\n${stderr}`);
        Object.assign(err, result);
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

async function installWritableDownloadSink(page, options = {}) {
  await page.addInitScript(({ cancelPicker }) => {
    window.__cloudsyncdTestDownload = null;
    window.__cloudsyncdPickerCalls = 0;
    window.showSaveFilePicker = async ({ suggestedName } = {}) => {
      window.__cloudsyncdPickerCalls += 1;
      if (cancelPicker) throw new DOMException('cancelled by test', 'AbortError');
      const record = {
        filename: suggestedName || 'download.bin',
        chunks: [],
        closed: false,
        aborted: false,
      };
      window.__cloudsyncdTestDownload = record;
      return {
        async createWritable() {
          return {
            async write(chunk) {
              if (chunk instanceof Uint8Array) {
                record.chunks.push(chunk.slice());
                return;
              }
              if (chunk instanceof ArrayBuffer) {
                record.chunks.push(new Uint8Array(chunk.slice(0)));
                return;
              }
              if (chunk instanceof Blob) {
                record.chunks.push(new Uint8Array(await chunk.arrayBuffer()));
                return;
              }
              throw new Error(`Unsupported test download chunk: ${typeof chunk}`);
            },
            async close() {
              record.closed = true;
            },
            async abort() {
              record.aborted = true;
            },
          };
        },
      };
    };
  }, { cancelPicker: !!options.cancelPicker });
}

async function readWritableDownloadResult(page, options = {}) {
  return page.evaluate(async ({ includeBytes }) => {
    const record = window.__cloudsyncdTestDownload;
    if (!record) return null;
    const total = record.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of record.chunks) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }
    const digest = await crypto.subtle.digest('SHA-256', merged);
    const sha256 = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    return {
      filename: record.filename,
      size: total,
      sha256,
      closed: record.closed,
      aborted: record.aborted,
      bytes: includeBytes ? Array.from(merged) : undefined,
    };
  }, { includeBytes: !!options.includeBytes });
}

function attachPageDiagnostics(page, testInfo) {
  page.context().on('serviceworker', (worker) => {
    worker.on('console', (msg) => {
      if (msg.type() === 'error') testInfo.attach(`serviceworker-console-${Date.now()}`, { body: msg.text(), contentType: 'text/plain' });
    });
  });
  page.on('console', (msg) => {
    if (msg.type() === 'error') testInfo.attach(`console-${Date.now()}`, { body: msg.text(), contentType: 'text/plain' });
  });
  page.on('response', async (response) => {
    if (response.status() >= 500) {
      let body = '';
      try {
        body = await response.text();
      } catch (err) {
        body = `failed to read body: ${err.message}`;
      }
      testInfo.attach(`response-${Date.now()}`, {
        body: `${response.status()} ${response.url()}\n${body}`,
        contentType: 'text/plain',
      });
    }
  });
  page.on('requestfailed', (request) => {
    testInfo.attach(`requestfailed-${Date.now()}`, {
      body: `${request.url()} ${request.failure() ? request.failure().errorText : ''}`,
      contentType: 'text/plain',
    });
  });
}

async function startCloudsyncd({ port, adminPort, dataDir, sharedDir }) {
  const logs = [];
  let pinResolve;
  let pinReject;
  const pinPromise = new Promise((resolve, reject) => {
    pinResolve = resolve;
    pinReject = reject;
  });

  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      ADMIN_PORT: String(adminPort),
      HOST: '127.0.0.1',
      ADMIN_HOST: '127.0.0.1',
      CLOUDSYNCD_DATA_DIR: dataDir,
      CLOUDSYNCD_SHARED_DIR: sharedDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const collect = (chunk) => {
    const text = chunk.toString();
    logs.push(text);
    const match = text.match(/Pairing PIN:\s*(\d{6})/);
    if (match) pinResolve(match[1]);
  };

  child.stdout.on('data', collect);
  child.stderr.on('data', collect);
  child.once('error', pinReject);
  child.once('exit', (code, signal) => {
    pinReject(new Error(`cloudsyncd exited early (${signal || code}): ${logs.join('')}`));
  });

  await waitForHttp(`http://127.0.0.1:${port}/api/status`);
  const pin = await Promise.race([
    pinPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`Timed out waiting for PIN:\n${logs.join('')}`)), 10000)),
  ]);

  return {
    pin,
    logs,
    stop: async () => {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    },
  };
}

async function startFixture(files = {}, setup) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsyncd-e2e-'));
  const dataDir = path.join(tmp, 'data');
  const sharedDir = path.join(tmp, 'shared');
  fs.mkdirSync(sharedDir, { recursive: true });
  writeSharedFiles(sharedDir, files);
  if (setup) await setup({ tmp, dataDir, sharedDir });
  const port = await freePort();
  const adminPort = await freePort();
  const server = await startCloudsyncd({ port, adminPort, dataDir, sharedDir });
  return {
    tmp,
    dataDir,
    sharedDir,
    port,
    adminPort,
    baseUrl: `http://127.0.0.1:${port}`,
    adminUrl: `http://127.0.0.1:${adminPort}`,
    pin: server.pin,
    logs: server.logs,
    async cleanup() {
      await server.stop();
      fs.rmSync(tmp, { recursive: true, force: true });
    },
  };
}

async function pairBrowser(page, fixture) {
  await page.goto(`${fixture.baseUrl}/`, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('#pair-screen.active')).toBeVisible();

  const inputs = page.locator('.pin-input');
  for (let i = 0; i < fixture.pin.length; i += 1) {
    await inputs.nth(i).fill(fixture.pin[i]);
  }

  await expect(page.locator('#main-screen.active')).toBeVisible();
}

test('CLI list/get uses a real server and streams chunked downloads', async () => {
  const fixture = await startFixture({}, ({ sharedDir }) => {
    writePatternFile(path.join(sharedDir, 'large-cli.bin'), CLI_FILE_BYTES);
    writeSharedFiles(sharedDir, {
      '目录/文件 空格.txt': 'hello from cli\n',
    });
  });
  const clientConfigDir = path.join(fixture.tmp, 'client-config');
  const out = path.join(fixture.tmp, 'downloads', 'large-cli.bin');
  const env = { CLOUDSYNCD_CONFIG_DIR: clientConfigDir };

  try {
    const list = await runCli(['client', 'list', fixture.baseUrl, '--pin', fixture.pin], env);
    expect(list.stdout).toContain('[file] large-cli.bin');
    expect(list.stdout).toContain('目录/文件 空格.txt');

    const get = await runCli(['client', 'get', fixture.baseUrl, 'large-cli.bin', '-o', out], env);
    expect(get.stdout).toContain(`Downloaded: ${out}`);
    expect(sha256File(out)).toBe(sha256File(path.join(fixture.sharedDir, 'large-cli.bin')));
    expect(fs.readdirSync(path.dirname(out)).filter((name) => name.includes('.cloudsyncd-'))).toEqual([]);
  } finally {
    await fixture.cleanup();
  }
});

test('browser receiver downloads a small unicode filename through the native download path', async ({ page }, testInfo) => {
  const fixture = await startFixture({
    '目录/文件 空格.txt': 'hello unicode browser\n',
  });
  try {
    attachPageDiagnostics(page, testInfo);
    await pairBrowser(page, fixture);
    await expect(page.locator('#file-list')).toContainText('文件 空格.txt');

    const fileRow = page.locator('.file-item').filter({ hasText: '文件 空格.txt' }).first();
    const downloadPromise = page.waitForEvent('download');
    await fileRow.locator('.file-dl').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('文件 空格.txt');

    const saved = path.join(fixture.tmp, 'small-download.txt');
    await download.saveAs(saved);
    expect(fs.readFileSync(saved, 'utf8')).toBe('hello unicode browser\n');
    await expect(page.locator('.toast.ok').last()).toContainText('下载完成：文件 空格.txt');
    await expect(fileRow.locator('.file-dl-label')).toHaveText('已完成');
    await expect(fileRow).toHaveClass(/download-complete/);
    await expect(page.locator('.toast.err')).toHaveCount(0);
  } finally {
    await fixture.cleanup();
  }
});

test('browser receiver filters files and exits selection mode cleanly', async ({ page }, testInfo) => {
  const fixture = await startFixture({
    'alpha.txt': 'alpha\n',
    'reports/季度 数据 2026.xlsx': 'report\n',
    'media/demo.mov': 'movie\n',
  });
  try {
    attachPageDiagnostics(page, testInfo);
    await pairBrowser(page, fixture);

    await expect(page.locator('#file-count-summary')).toHaveText('3 个文件');
    await page.locator('#file-search-input').fill('reports');
    await expect(page.locator('#file-count-summary')).toHaveText('显示 1/3');
    await expect(page.locator('#file-list')).toContainText('季度 数据 2026.xlsx');
    await expect(page.locator('#file-list')).not.toContainText('alpha.txt');

    await page.locator('#toggle-selection-mode-btn').click();
    await expect(page.locator('#top-selection-bar')).toHaveClass(/active/);
    await page.locator('.file-item', { hasText: '季度 数据 2026.xlsx' }).click();
    await expect(page.locator('#selection-count')).toHaveText('1');

    await page.locator('#close-top-selection-btn').click();
    await expect(page.locator('#toggle-selection-mode-btn')).toHaveText('选择');
    await expect(page.locator('#file-list')).not.toHaveClass(/selection-mode/);

    await page.locator('#toggle-selection-mode-btn').click();
    await expect(page.locator('#selection-count')).toHaveText('0');
  } finally {
    await fixture.cleanup();
  }
});

test('browser receiver downloads a large encrypted file through the browser-managed path', async ({ page }, testInfo) => {
  const fixture = await startFixture({}, ({ sharedDir }) => {
    writePatternFile(path.join(sharedDir, 'large-e2e.bin'), LARGE_FILE_BYTES);
  });

  try {
    attachPageDiagnostics(page, testInfo);
    await pairBrowser(page, fixture);
    await expect(page.locator('#file-list')).toContainText('large-e2e.bin');

    const fileRow = page.locator('.file-item').filter({ hasText: 'large-e2e.bin' }).first();
    const downloadPromise = page.waitForEvent('download');
    await fileRow.locator('.file-dl').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('large-e2e.bin');

    const saved = path.join(fixture.tmp, 'large-browser.bin');
    await download.saveAs(saved);
    expect(fs.statSync(saved).size).toBe(LARGE_FILE_BYTES);
    expect(sha256File(saved)).toBe(sha256File(path.join(fixture.sharedDir, 'large-e2e.bin')));
    await expect(page.locator('.toast.ok').last()).toContainText('下载完成：large-e2e.bin');
    await expect(fileRow.locator('.file-dl-label')).toHaveText('已完成');
    await expect(fileRow).toHaveClass(/download-complete/);
    await expect(page.locator('.toast.err')).toHaveCount(0);
  } finally {
    await fixture.cleanup();
  }
});

test('browser-managed large download survives receiver page navigation', async ({ page }, testInfo) => {
  const fixture = await startFixture({}, ({ sharedDir }) => {
    writePatternFile(path.join(sharedDir, 'background-large.bin'), LARGE_FILE_BYTES);
  });

  try {
    attachPageDiagnostics(page, testInfo);
    await pairBrowser(page, fixture);
    await expect(page.locator('#file-list')).toContainText('background-large.bin');

    const fileRow = page.locator('.file-item').filter({ hasText: 'background-large.bin' }).first();
    const downloadPromise = page.waitForEvent('download');
    await fileRow.locator('.file-dl').click();
    const download = await downloadPromise;
    await page.goto('about:blank');

    const saved = path.join(fixture.tmp, 'background-large.bin');
    await download.saveAs(saved);
    expect(fs.statSync(saved).size).toBe(LARGE_FILE_BYTES);
    expect(sha256File(saved)).toBe(sha256File(path.join(fixture.sharedDir, 'background-large.bin')));
  } finally {
    await fixture.cleanup();
  }
});

test('browser filesystem fallback cancellation does not start the encrypted file request', async ({ page }, testInfo) => {
  const fixture = await startFixture({}, ({ sharedDir }) => {
    writePatternFile(path.join(sharedDir, 'cancel-large.bin'), LARGE_FILE_BYTES);
  });
  let chunkedRequests = 0;

  try {
    await installWritableDownloadSink(page, { cancelPicker: true });
    await page.addInitScript(() => {
      localStorage.setItem('cloudsyncd-download-mode', 'filesystem');
    });
    attachPageDiagnostics(page, testInfo);
    page.on('request', (request) => {
      if (request.url().includes('/api/files-chunked/')) chunkedRequests += 1;
    });
    await pairBrowser(page, fixture);
    await expect(page.locator('#file-list')).toContainText('cancel-large.bin');

    const fileRow = page.locator('.file-item').filter({ hasText: 'cancel-large.bin' }).first();
    await fileRow.locator('.file-dl').click();
    await expect(page.locator('.toast.info')).toContainText('已取消下载');
    expect(await page.evaluate(() => window.__cloudsyncdPickerCalls)).toBe(1);
    expect(chunkedRequests).toBe(0);
  } finally {
    await fixture.cleanup();
  }
});

test('browser batch download writes a valid zip for selected files', async ({ page }, testInfo) => {
  const fixture = await startFixture({
    'a.txt': 'alpha\n',
    '目录/b.txt': 'bravo\n',
  });

  try {
    await installWritableDownloadSink(page);
    attachPageDiagnostics(page, testInfo);
    await pairBrowser(page, fixture);
    await expect(page.locator('#file-list')).toContainText('a.txt');
    await expect(page.locator('#file-list')).toContainText('b.txt');

    await page.locator('#toggle-selection-mode-btn').click();
    await page.locator('#select-all-btn').click();
    await expect(page.locator('#selection-count')).toHaveText('2');
    await page.locator('#batch-download-btn').click();
    await page.waitForFunction(() => {
      const record = window.__cloudsyncdTestDownload;
      return !!record && record.closed;
    }, null, { timeout: 90000 });

    const result = await readWritableDownloadResult(page, { includeBytes: true });
    expect(result).toMatchObject({
      filename: 'cloudsyncd-files-2.zip',
      closed: true,
      aborted: false,
    });
    await expect(page.locator('.toast.ok').last()).toContainText('下载完成：cloudsyncd-files-2.zip（2/2 个文件）');
    await expect(page.locator('#batch-download-btn')).toHaveText('已完成');
    await expect(page.locator('#batch-download-btn')).toHaveClass(/download-complete/);
    const entries = parseStoredZip(result.bytes);
    expect(entries.get('a.txt').toString('utf8')).toBe('alpha\n');
    expect(entries.get('目录/b.txt').toString('utf8')).toBe('bravo\n');
    await expect(page.locator('.toast.err')).toHaveCount(0);
  } finally {
    await fixture.cleanup();
  }
});

test('local admin can upload, search, and delete shared entries without deleting linked originals', async ({ page }, testInfo) => {
  const fixture = await startFixture({}, ({ tmp, sharedDir }) => {
    const original = path.join(tmp, 'outside-original.txt');
    const linked = path.join(sharedDir, 'linked-source.txt');
    fs.writeFileSync(original, 'original survives\n');
    fs.linkSync(original, linked);
  });
  const originalPath = path.join(fixture.tmp, 'outside-original.txt');
  const linkedSharedPath = path.join(fixture.sharedDir, 'linked-source.txt');
  const uploadPath = path.join(fixture.tmp, '上传 文件.txt');
  fs.writeFileSync(uploadPath, 'uploaded from admin\n');

  try {
    attachPageDiagnostics(page, testInfo);
    page.on('dialog', (dialog) => dialog.accept());
    await page.goto(`${fixture.adminUrl}/admin`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('#files-body')).toContainText('linked-source.txt');

    await page.setInputFiles('#upload-input', uploadPath);
    await expect(page.locator('#files-body')).toContainText('上传 文件.txt');
    expect(fs.readFileSync(path.join(fixture.sharedDir, '上传 文件.txt'), 'utf8')).toBe('uploaded from admin\n');

    await page.locator('#file-search').fill('上传');
    await expect(page.locator('#files-body')).toContainText('上传 文件.txt');
    await expect(page.locator('#files-body')).not.toContainText('linked-source.txt');
    await page.locator('#select-visible-files-btn').click();
    await expect(page.locator('#file-selection-count')).toContainText('已选 1');
    await page.locator('#delete-selected-files-btn').click();
    await expect(page.locator('#files-body')).not.toContainText('上传 文件.txt');
    expect(fs.existsSync(path.join(fixture.sharedDir, '上传 文件.txt'))).toBe(false);

    await page.locator('#file-search').fill('linked');
    await expect(page.locator('#files-body')).toContainText('linked-source.txt');
    await page.locator('#select-visible-files-btn').click();
    await page.locator('#delete-selected-files-btn').click();
    await expect(page.locator('#files-body')).not.toContainText('linked-source.txt');
    expect(fs.existsSync(linkedSharedPath)).toBe(false);
    expect(fs.readFileSync(originalPath, 'utf8')).toBe('original survives\n');
  } finally {
    await fixture.cleanup();
  }
});

test('admin routes stay off the tunnel-facing listener while local admin remains reachable', async () => {
  const fixture = await startFixture({ 'public.txt': 'public\n' });
  try {
    const publicAdmin = await fetch(`${fixture.baseUrl}/admin`);
    const publicLocalStatus = await fetch(`${fixture.baseUrl}/api/local/status`);
    const localAdmin = await fetch(`${fixture.adminUrl}/admin`);
    const localStatus = await fetch(`${fixture.adminUrl}/api/local/status`);

    expect(publicAdmin.status).toBe(404);
    expect(publicLocalStatus.status).toBe(404);
    expect(localAdmin.status).toBe(200);
    expect(localStatus.status).toBe(200);
    expect((await localStatus.json()).sharedFiles).toBe(1);
  } finally {
    await fixture.cleanup();
  }
});
