// ============ Crypto Utilities (Web Crypto API) ============

const Crypto = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const pubRaw = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
    return { keyPair, publicKeyHex: buf2hex(new Uint8Array(pubRaw)) };
  },

  async importPublicKey(hex) {
    return window.crypto.subtle.importKey(
      'raw', hex2buf(hex), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
  },

  async deriveSharedSecret(privateKey, publicKey) {
    const bits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey }, privateKey, 256
    );
    return new Uint8Array(bits);
  },

  async hkdf(ikm, salt, info, length = 32) {
    const baseKey = await window.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await window.crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode(salt),
      info: new TextEncoder().encode(info),
    }, baseKey, length * 8);
    return new Uint8Array(bits);
  },

  async hmac(key, data) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await window.crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
    return buf2hex(new Uint8Array(sig));
  },

  async decryptBytes(keyBytes, ivBytes, ciphertextBytes, tagBytes) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combined.set(ciphertextBytes);
    combined.set(tagBytes, ciphertextBytes.length);
    return new Uint8Array(await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, combined));
  },

  async decryptCombinedBytes(keyBytes, ivBytes, encryptedBytes, tagLength = 16, additionalData = null) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const algorithm = {
      name: 'AES-GCM',
      iv: ivBytes,
      tagLength: tagLength * 8,
    };
    if (additionalData) algorithm.additionalData = additionalData;
    return new Uint8Array(await window.crypto.subtle.decrypt(algorithm, key, encryptedBytes));
  },

  async decrypt(keyBytes, iv, ciphertext, tag) {
    return this.decryptBytes(keyBytes, hex2buf(iv), hex2buf(ciphertext), hex2buf(tag));
  },

  async encrypt(keyBytes, plaintext) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encBuf = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    const ciphertext = encBuf.slice(0, encBuf.length - 16);
    const tag = encBuf.slice(encBuf.length - 16);
    return { iv: buf2hex(iv), ciphertext: buf2hex(ciphertext), tag: buf2hex(tag) };
  },
};

function buf2hex(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); }
function hex2buf(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

const LARGE_FILE_STREAM_THRESHOLD = 32 * 1024 * 1024;
const CHUNKED_ENCRYPTION_MODE = 'chunked-v2';
const FINAL_FRAME_MARKER = 0;
const FINAL_MANIFEST_MAX_BYTES = 64 * 1024;
const DOWNLOAD_SW_PATH = '/download-sw.js';
const DOWNLOAD_SW_PREFIX = '/__cloudsyncd_download__/';
const DOWNLOAD_SW_PROTOCOL = 'chunked-fetch-v1';
const DOWNLOAD_READY_TIMEOUT_MS = 8000;
const DOWNLOAD_MODE_KEY = 'cloudsyncd-download-mode';
const BLOB_DOWNLOAD_FALLBACK_MAX_BYTES = 32 * 1024 * 1024;
const DOWNLOAD_COMPLETE_HOLD_MS = 3000;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ============ Theme (light/dark) ============

const THEME_KEY = 'cloudsyncd-theme';
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.setAttribute('content', theme === 'light' ? '#f6f8fb' : '#0a0d12');
  const colorScheme = document.querySelector('meta[name="color-scheme"]');
  if (colorScheme) colorScheme.setAttribute('content', theme);
}
function initTheme() {
  let theme = null;
  try { theme = localStorage.getItem(THEME_KEY); } catch {}
  if (theme !== 'light' && theme !== 'dark') {
    theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  applyTheme(theme);
}
function toggleTheme() {
  const next = (document.documentElement.getAttribute('data-theme') === 'light') ? 'dark' : 'light';
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch {}
}
initTheme();

function safeDecodeHeader(value) {
  if (!value) return '';
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

async function decryptDownloadResponse(res) {
  const streamIv = res.headers.get('x-encrypted-iv');
  if (streamIv) {
    const tagLength = Number.parseInt(res.headers.get('x-encrypted-tag-length') || '16', 10);
    const payload = new Uint8Array(await res.arrayBuffer());
    if (payload.length < tagLength) {
      throw new Error('Encrypted payload is truncated');
    }

    const plainBuf = await Crypto.decryptCombinedBytes(encryptionKey, hex2buf(streamIv), payload, tagLength);

    return {
      filename: safeDecodeHeader(res.headers.get('x-file-name')),
      plainBuf,
    };
  }

  const { encrypted } = await res.json();
  return {
    filename: encrypted.filename || '',
    plainBuf: await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag),
  };
}

async function getErrorMessage(res, fallback) {
  try {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const body = await res.json();
      if (body && body.error) return `${fallback}: ${res.status} ${body.error}`;
    }
    const text = await res.text();
    if (text) return `${fallback}: ${res.status} ${text.slice(0, 160)}`;
  } catch {
    // Keep the original error path if the response body cannot be parsed.
  }
  return `${fallback}: ${res.status}`;
}

function saveByteChunks(filename, chunks) {
  const blob = new Blob(chunks);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();

  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 60000);
}

function saveBytes(filename, plainBuf) {
  saveByteChunks(filename, [plainBuf]);
}

function readUint32BE(bytes) {
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

function chunkIv(prefix, counter) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, counter, false);
  return iv;
}

function chunkFrameAad(kind, counter, context) {
  return textEncoder.encode([
    'cloudsyncd',
    CHUNKED_ENCRYPTION_MODE,
    kind,
    String(counter),
    String(context.fileSize),
    String(context.chunkSize),
    context.relPath,
  ].join('\n'));
}

function parseSafeInteger(value, label, min = 0) {
  const number = Number.parseInt(value || '', 10);
  if (!Number.isSafeInteger(number) || number < min) throw new Error(`${label} 无效`);
  return number;
}

function validateChunkedManifest(manifest, context, chunkCount) {
  if (!manifest || typeof manifest !== 'object') throw new Error('分块下载缺少 final manifest');
  if (manifest.mode !== CHUNKED_ENCRYPTION_MODE) throw new Error('分块下载 manifest 模式不匹配');
  if (manifest.fileSize !== context.fileSize) throw new Error('分块下载文件大小不匹配');
  if (manifest.chunkSize !== context.chunkSize) throw new Error('分块下载 chunk size 不匹配');
  if (manifest.chunkCount !== chunkCount) throw new Error('分块下载 chunk 数量不匹配');
  if (manifest.relPath !== context.relPath) throw new Error('分块下载路径不匹配');
}

async function* decryptChunkedDownloadResponse(res, relPath, onFinalManifest) {
  if (!res.body || !res.body.getReader) {
    throw new Error('浏览器不支持流式下载，无法使用大文件模式');
  }
  if (res.headers.get('x-encrypted-mode') !== CHUNKED_ENCRYPTION_MODE) {
    throw new Error('服务端未返回分块加密响应');
  }

  const ivPrefix = hex2buf(res.headers.get('x-encrypted-iv-prefix') || '');
  if (ivPrefix.length !== 8) throw new Error('分块加密响应缺少 IV prefix');

  const tagLength = Number.parseInt(res.headers.get('x-encrypted-tag-length') || '16', 10);
  const chunkSize = parseSafeInteger(res.headers.get('x-encrypted-chunk-size'), '分块大小', 1);
  const fileSize = parseSafeInteger(res.headers.get('x-file-size'), '文件大小');
  const context = { fileSize, chunkSize, relPath };
  if (!Number.isFinite(tagLength) || tagLength <= 0) throw new Error('分块加密 tag 长度无效');

  const reader = res.body.getReader();
  const pendingChunks = [];
  let pendingBytes = 0;
  let counter = 0;

  function enqueue(chunk) {
    if (!chunk || chunk.length === 0) return;
    pendingChunks.push(chunk);
    pendingBytes += chunk.length;
  }

  function readQueued(size) {
    if (pendingBytes < size) return null;
    if (size === 0) return new Uint8Array(0);

    const first = pendingChunks[0];
    if (first.length === size) {
      pendingChunks.shift();
      pendingBytes -= size;
      return first;
    }
    if (first.length > size) {
      const out = first.subarray(0, size);
      pendingChunks[0] = first.subarray(size);
      pendingBytes -= size;
      return out;
    }

    const out = new Uint8Array(size);
    let offset = 0;
    let remaining = size;
    while (remaining > 0) {
      const head = pendingChunks[0];
      const take = Math.min(head.length, remaining);
      out.set(head.subarray(0, take), offset);
      offset += take;
      remaining -= take;
      if (take === head.length) {
        pendingChunks.shift();
      } else {
        pendingChunks[0] = head.subarray(take);
      }
    }
    pendingBytes -= size;
    return out;
  }

  async function readExact(size) {
    while (pendingBytes < size) {
      const { value, done } = await reader.read();
      if (done) {
        if (pendingBytes === 0) return null;
        throw new Error('分块加密响应被截断');
      }
      enqueue(value);
    }
    return readQueued(size);
  }

  for (;;) {
    const header = await readExact(4);
    if (!header) throw new Error('分块加密响应缺少 final manifest');

    const encryptedLength = readUint32BE(header);
    if (encryptedLength === FINAL_FRAME_MARKER) {
      const manifestHeader = await readExact(4);
      if (!manifestHeader) throw new Error('分块加密 final manifest header 被截断');
      const manifestLength = readUint32BE(manifestHeader);
      if (manifestLength < tagLength || manifestLength > FINAL_MANIFEST_MAX_BYTES) {
        throw new Error('分块加密 final manifest 长度无效');
      }
      const encryptedManifest = await readExact(manifestLength);
      if (!encryptedManifest) throw new Error('分块加密 final manifest 被截断');
      const manifestBytes = await Crypto.decryptCombinedBytes(
        encryptionKey,
        chunkIv(ivPrefix, counter),
        encryptedManifest,
        tagLength,
        chunkFrameAad('final', counter, context)
      );
      const manifest = JSON.parse(textDecoder.decode(manifestBytes));
      validateChunkedManifest(manifest, context, counter);
      const extra = await readExact(1);
      if (extra) throw new Error('分块加密 final manifest 后存在多余数据');
      onFinalManifest(manifest);
      return;
    }

    if (encryptedLength < tagLength || encryptedLength > chunkSize + tagLength) {
      throw new Error('分块加密帧长度无效');
    }

    const encrypted = await readExact(encryptedLength);
    if (!encrypted) throw new Error('分块加密响应被截断');

    yield await Crypto.decryptCombinedBytes(
      encryptionKey,
      chunkIv(ivPrefix, counter),
      encrypted,
      tagLength,
      chunkFrameAad('data', counter, context)
    );
    counter += 1;
  }
}

function canStreamToDisk() {
  return window.isSecureContext && typeof window.showSaveFilePicker === 'function';
}

async function openWritableDownload(filename) {
  const handle = await window.showSaveFilePicker({ suggestedName: filename });
  const writable = await handle.createWritable();
  return {
    mode: 'filesystem',
    write: (chunk) => writable.write(chunk),
    close: () => writable.close(),
    abort: () => writable.abort(),
  };
}

function downloadModePreference() {
  try {
    return localStorage.getItem(DOWNLOAD_MODE_KEY) || '';
  } catch {
    return '';
  }
}

function wantsBrowserManagedDownload() {
  return downloadModePreference() === 'browser';
}

function wantsFilesystemDownload() {
  return downloadModePreference() === 'filesystem';
}

function downloadStreamSupported() {
  return (
    window.isSecureContext
    && 'serviceWorker' in navigator
    && typeof ReadableStream !== 'undefined'
    && typeof MessageChannel !== 'undefined'
  );
}

function waitForControllerChange(timeoutMs = DOWNLOAD_READY_TIMEOUT_MS) {
  if (navigator.serviceWorker.controller) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      clearTimeout(timer);
      resolve(true);
    }, { once: true });
  });
}

function waitForNextControllerChange(timeoutMs = DOWNLOAD_READY_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      clearTimeout(timer);
      resolve(true);
    }, { once: true });
  });
}

function waitForWorkerState(worker, targetState, timeoutMs = DOWNLOAD_READY_TIMEOUT_MS) {
  if (!worker || worker.state === targetState) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    worker.addEventListener('statechange', () => {
      if (worker.state !== targetState) return;
      clearTimeout(timer);
      resolve(true);
    });
  });
}

async function registerDownloadServiceWorker() {
  let registration;
  try {
    registration = await navigator.serviceWorker.register(DOWNLOAD_SW_PATH, { updateViaCache: 'none' });
  } catch (err) {
    if (!(err instanceof TypeError)) throw err;
    registration = await navigator.serviceWorker.register(DOWNLOAD_SW_PATH);
  }
  return registration;
}

async function pingDownloadServiceWorker(worker, timeoutMs = 1000) {
  if (!worker) return false;
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      resolve(false);
    }, timeoutMs);
    channel.port1.onmessage = (event) => {
      clearTimeout(timer);
      channel.port1.close();
      const data = event.data || {};
      resolve(data.type === 'cloudsyncd-download-pong' && data.protocol === DOWNLOAD_SW_PROTOCOL);
    };
    try {
      worker.postMessage({ type: 'cloudsyncd-download-ping' }, [channel.port2]);
    } catch {
      clearTimeout(timer);
      channel.port1.close();
      resolve(false);
    }
  });
}

async function activateCandidateServiceWorker(registration) {
  const candidate = registration.installing || registration.waiting;
  if (!candidate) return;
  const nextController = navigator.serviceWorker.controller
    ? waitForNextControllerChange(2500)
    : waitForControllerChange(2500);
  try { candidate.postMessage({ type: 'cloudsyncd-skip-waiting' }); } catch {}
  await waitForWorkerState(candidate, 'activated');
  await nextController;
}

async function ensureDownloadServiceWorker() {
  if (!downloadStreamSupported()) throw new Error('浏览器不支持下载 service worker');
  const registration = await registerDownloadServiceWorker();
  try { await registration.update(); } catch {}
  await navigator.serviceWorker.ready;
  await activateCandidateServiceWorker(registration);
  if (!navigator.serviceWorker.controller) await waitForControllerChange();

  let worker = navigator.serviceWorker.controller;
  if (await pingDownloadServiceWorker(worker)) return worker;

  try { await registration.update(); } catch {}
  await activateCandidateServiceWorker(registration);
  await waitForControllerChange(1500);

  worker = navigator.serviceWorker.controller;
  if (await pingDownloadServiceWorker(worker)) return worker;
  throw new Error('下载 service worker 版本过旧，请刷新页面后重试');
}

function requireDownloadServiceWorkerController() {
  if (!downloadStreamSupported()) throw new Error('浏览器不支持下载 service worker');
  if (!navigator.serviceWorker.controller) {
    throw new Error('下载 service worker 未接管页面，请刷新页面后重试');
  }
  return navigator.serviceWorker.controller;
}

async function warmDownloadServiceWorker() {
  if (!downloadStreamSupported()) return;
  try {
    await ensureDownloadServiceWorker();
  } catch (err) {
    console.info('Browser-managed downloads will be enabled after this page is reloaded:', err.message);
  }
}

function transferableChunk(chunk) {
  if (chunk.byteOffset === 0 && chunk.byteLength === chunk.buffer.byteLength) return chunk;
  return chunk.slice();
}

function createPortDownloadWriter(port, readyPromise) {
  let pendingAck = null;
  let closed = false;
  let cancelled = false;

  port.onmessage = (event) => {
    const data = event.data || {};
    if (data.type === 'ack' && pendingAck) {
      pendingAck.resolve();
      pendingAck = null;
      return;
    }
    if (data.type === 'cancel') {
      cancelled = true;
      if (pendingAck) {
        pendingAck.reject(new Error('浏览器已取消下载'));
        pendingAck = null;
      }
      return;
    }
    if ((data.type === 'error' || data.type === 'timeout') && pendingAck) {
      pendingAck.reject(new Error(data.error || '浏览器下载通道失败'));
      pendingAck = null;
    }
  };

  return {
    mode: 'browser',
    async write(chunk) {
      await readyPromise;
      if (closed) throw new Error('下载已关闭');
      if (cancelled) throw new Error('浏览器已取消下载');
      if (pendingAck) throw new Error('下载写入仍在进行');
      const bytes = transferableChunk(chunk);
      await new Promise((resolve, reject) => {
        pendingAck = { resolve, reject };
        port.postMessage({ type: 'chunk', chunk: bytes.buffer }, [bytes.buffer]);
      });
    },
    async close() {
      await readyPromise;
      closed = true;
      port.postMessage({ type: 'close' });
    },
    async abort() {
      closed = true;
      try { port.postMessage({ type: 'abort' }); } catch {}
    },
  };
}

function createDownloadChannel() {
  const id = window.crypto.randomUUID ? window.crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const channel = new MessageChannel();
  let initializedResolve;
  let initializedReject;
  let readyResolve;
  let readyReject;
  const initializedPromise = new Promise((resolve, reject) => {
    initializedResolve = resolve;
    initializedReject = reject;
  });
  const readyPromise = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  let completionResolve;
  let completionReject;
  const completionPromise = new Promise((resolve, reject) => {
    completionResolve = resolve;
    completionReject = reject;
  });
  readyPromise.catch(() => {});
  completionPromise.catch(() => {});

  function rejectDownload(data, fallback, name = 'Error') {
    const err = new Error(data.error || fallback);
    err.name = name;
    if (data.status) err.status = data.status;
    readyReject(err);
    completionReject(err);
  }

  const timer = setTimeout(() => {
    const err = new Error('浏览器下载通道启动超时');
    initializedReject(err);
    readyReject(err);
    completionReject(err);
  }, DOWNLOAD_READY_TIMEOUT_MS);

  channel.port1.addEventListener('message', (event) => {
    const data = event.data || {};
    if (data.type === 'initialized') {
      initializedResolve();
    } else if (data.type === 'ready') {
      clearTimeout(timer);
      readyResolve();
    } else if (data.type === 'closed') {
      clearTimeout(timer);
      readyResolve();
      completionResolve(data);
    } else if (data.type === 'cancel') {
      clearTimeout(timer);
      rejectDownload(data, '浏览器已取消下载', 'AbortError');
    } else if (data.type === 'timeout' || data.type === 'error') {
      clearTimeout(timer);
      rejectDownload(data, '浏览器下载通道失败');
    }
  });
  channel.port1.start();

  return {
    id,
    port: channel.port1,
    transferPort: channel.port2,
    initializedPromise,
    readyPromise,
    completionPromise,
  };
}

function clickBrowserDownload(id, filename) {
  const url = `${DOWNLOAD_SW_PREFIX}${encodeURIComponent(id)}/${encodeURIComponent(filename)}`;
  const a = document.createElement('a');
  a.href = url;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => a.remove(), 1000);
}

async function openBrowserManagedDownload(filename, size) {
  const worker = requireDownloadServiceWorkerController();
  const channel = createDownloadChannel();
  worker.postMessage({
    type: 'cloudsyncd-download-init',
    id: channel.id,
    filename,
    size,
  }, [channel.transferPort]);

  clickBrowserDownload(channel.id, filename);
  const writer = createPortDownloadWriter(channel.port, channel.readyPromise);
  await channel.initializedPromise;
  await channel.readyPromise;
  return writer;
}

async function openWorkerManagedChunkedDownload(filename, size, transfer = {}) {
  if (!encryptionKey || !deviceId) throw new Error('当前设备尚未完成配对');
  if (!transfer.apiPath || !transfer.relPath) throw new Error('下载任务缺少分块路径');
  const worker = await ensureDownloadServiceWorker();
  const channel = createDownloadChannel();
  worker.postMessage({
    type: 'cloudsyncd-download-init',
    source: 'chunked-fetch',
    id: channel.id,
    filename,
    size,
    apiPath: transfer.apiPath,
    relPath: transfer.relPath,
    keyHex: buf2hex(encryptionKey),
    deviceId,
  }, [channel.transferPort]);

  clickBrowserDownload(channel.id, filename);
  await channel.initializedPromise;
  await channel.readyPromise;
  return {
    mode: 'browser',
    ownsTransfer: true,
    completion: channel.completionPromise,
    async abort() {
      try { channel.port.postMessage({ type: 'abort' }); } catch {}
    },
  };
}

async function openChunkedDownloadSink(filename, size, transfer = {}) {
  if (canStreamToDisk() && wantsFilesystemDownload()) {
    return openWritableDownload(filename);
  }

  if (downloadStreamSupported()) {
    try {
      return await openWorkerManagedChunkedDownload(filename, size, transfer);
    } catch (err) {
      console.warn('Background browser download unavailable:', err);
      if (wantsBrowserManagedDownload()) {
        throw new Error(`浏览器后台下载通道未就绪：${err.message}。请刷新页面后重试，或设置 cloudsyncd-download-mode=filesystem 使用文件选择器流式保存`);
      }
    }
  }

  if (canStreamToDisk()) {
    return openWritableDownload(filename);
  }

  throw new Error('当前浏览器无法安全流式保存大文件。请使用支持 File System Access 的 Chrome/Edge，或使用 cloudsyncd client get 下载');
}

function assertChunkedDownloadComplete(finalManifest, total) {
  if (!finalManifest) throw new Error('分块下载未收到 final manifest');
  if (total !== finalManifest.fileSize) {
    throw new Error(`分块下载大小不匹配: expected ${finalManifest.fileSize}, got ${total}`);
  }
}

async function saveChunkedDownloadResponse(res, filename, sink, relPath) {
  let total = 0;
  let finalManifest = null;
  const onFinalManifest = (manifest) => {
    finalManifest = manifest;
  };

  if (sink) {
    try {
      for await (const chunk of decryptChunkedDownloadResponse(res, relPath, onFinalManifest)) {
        await sink.write(chunk);
        total += chunk.length;
      }
      assertChunkedDownloadComplete(finalManifest, total);
      await sink.close();
      return { bytes: total, mode: sink.mode || 'stream' };
    } catch (err) {
      try { await sink.abort(); } catch {}
      throw err;
    }
  }

  const chunks = [];
  for await (const chunk of decryptChunkedDownloadResponse(res, relPath, onFinalManifest)) {
    chunks.push(chunk);
    total += chunk.length;
  }
  assertChunkedDownloadComplete(finalManifest, total);
  saveByteChunks(filename, chunks);
  return { bytes: total, mode: 'blob' };
}

async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return buf2hex(new Uint8Array(digest));
}

// ============ Key Storage (IndexedDB) ============

const KeyStore = {
  DB_NAME: 'syncd', STORE_NAME: 'keys',
  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(this.STORE_NAME);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },
  async save(key, value) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
  async get(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readonly');
      const req = tx.objectStore(this.STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },
  async delete(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

// ============ Toast Notifications ============

function toast(msg, type = 'info') {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.setAttribute('role', type === 'err' ? 'alert' : 'status');
  el.setAttribute('aria-live', type === 'err' ? 'assertive' : 'polite');
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ============ Screen Management ============

let encryptionKey = null;
let deviceId = null;
let fileRefreshTimer = null;
let scrollObserver = null;
let scrollLoaderInterval = null;

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
  });
  const el = document.getElementById(id);
  void el.offsetHeight;
  el.classList.add('active');
}

function showMainScreen() {
  showScreen('main-screen');
  loadFiles();
  if (fileRefreshTimer) clearInterval(fileRefreshTimer);
  fileRefreshTimer = setInterval(loadFiles, 10000);
}

function showPairScreen() {
  showScreen('pair-screen');
  if (fileRefreshTimer) { clearInterval(fileRefreshTimer); fileRefreshTimer = null; }
  teardownScrollLoader();
}

async function clearStoredPairing() {
  encryptionKey = null;
  deviceId = null;
  await Promise.all([
    KeyStore.delete('encryptionKey'),
    KeyStore.delete('deviceId'),
  ]);
}

async function resetToPairing(reason) {
  await clearStoredPairing();
  showPairScreen();
  setStatus('error', reason);
  setTimeout(() => document.querySelector('.pin-input')?.focus(), 100);
}

function buildSignedPath(pathname) {
  const url = new URL(pathname, window.location.origin);
  return url.pathname + url.search;
}

async function deriveRequestAuthKey() {
  if (!encryptionKey || !deviceId) {
    throw new Error('Device is not authenticated');
  }
  return Crypto.hkdf(encryptionKey, 'syncd-request-auth', `device:${deviceId}`);
}

async function apiFetch(pathname, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const signedPath = buildSignedPath(pathname);
  const body = options.body ?? '';
  let bodyBytes = new Uint8Array();
  if (typeof body === 'string') {
    bodyBytes = new TextEncoder().encode(body);
  } else if (body instanceof Uint8Array) {
    bodyBytes = body;
  } else if (body instanceof ArrayBuffer) {
    bodyBytes = new Uint8Array(body);
  }

  const timestamp = Date.now().toString();
  const nonce = window.crypto.randomUUID();
  const bodyHash = await sha256Hex(bodyBytes);
  const authKey = await deriveRequestAuthKey();
  const signature = await Crypto.hmac(
    authKey,
    [method, signedPath, timestamp, nonce, bodyHash].join('\n')
  );

  const headers = new Headers(options.headers || {});
  headers.set('X-Device-Id', deviceId);
  headers.set('X-Auth-Timestamp', timestamp);
  headers.set('X-Auth-Nonce', nonce);
  headers.set('X-Auth-Signature', signature);

  return fetch(pathname, { ...options, method, headers });
}

// ============ Pairing Flow ============

let pairing = false;

function setStatus(type, text) {
  const pill = document.getElementById('pair-status');
  const textEl = document.getElementById('pair-status-text');
  pill.className = `status-pill ${type}`;
  textEl.textContent = text;
}

async function doPairing(pin) {
  if (pairing) return;
  pairing = true;
  const btn = document.getElementById('pair-btn');
  const inputs = document.querySelectorAll('.pin-input');
  btn.disabled = true;

  try {
    setStatus('working', '正在协商密钥...');

    const initRes = await fetch('/api/pair/init');
    if (!initRes.ok) {
      const text = await initRes.text();
      let msg = `Init failed (${initRes.status})`;
      try { msg = JSON.parse(text).error || msg; } catch { msg += ': ' + text.slice(0, 100); }
      throw new Error(msg);
    }
    const { serverPublicKey } = await initRes.json();

    const client = await Crypto.generateKeyPair();
    const serverPub = await Crypto.importPublicKey(serverPublicKey);
    const sharedSecret = await Crypto.deriveSharedSecret(client.keyPair.privateKey, serverPub);

    const authKey = await Crypto.hkdf(sharedSecret, 'syncd-auth', 'pin-verify');
    const proof = await Crypto.hmac(authKey, pin);

    setStatus('working', '正在验证 PIN...');
    const newDeviceId = 'browser-' + Math.random().toString(36).slice(2, 8);
    const verifyRes = await fetch('/api/pair/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: client.publicKeyHex, proof, deviceId: newDeviceId }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      if (err.remaining !== undefined) throw new Error(`PIN 错误，剩余 ${err.remaining} 次尝试`);
      throw new Error(err.error || 'Verification failed');
    }

    const { serverProof, encryptedMasterKey } = await verifyRes.json();
    const expectedServerProof = await Crypto.hmac(authKey, 'server-confirmed');
    if (serverProof !== expectedServerProof) throw new Error('服务端验证失败');

    const transportKey = await Crypto.hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery');
    encryptionKey = await Crypto.decrypt(
      transportKey, encryptedMasterKey.iv, encryptedMasterKey.ciphertext, encryptedMasterKey.tag
    );
    deviceId = newDeviceId;
    await KeyStore.save('encryptionKey', buf2hex(encryptionKey));
    await KeyStore.save('deviceId', newDeviceId);

    setStatus('success', '配对成功');
    setTimeout(() => showMainScreen(), 500);

  } catch (err) {
    setStatus('error', err.message);
    inputs.forEach(el => { el.classList.add('shake'); el.value = ''; });
    setTimeout(() => inputs.forEach(el => el.classList.remove('shake')), 500);
    inputs[0].focus();
    btn.disabled = true;
  } finally {
    pairing = false;
  }
}

// ============ File Operations ============

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatModifiedTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const now = new Date();
  const sameYear = date.getFullYear() === now.getFullYear();
  return new Intl.DateTimeFormat('zh-CN', {
    year: sameYear ? undefined : 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fileIconClass(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) return 'image';
  if (['mp4', 'mov', 'mkv', 'mp3', 'wav', 'flac'].includes(ext)) return 'media';
  if (['zip', 'tar', 'gz', 'tgz', '7z', 'rar'].includes(ext)) return 'archive';
  return 'generic';
}

function fileIconSvg(filename) {
  const kind = fileIconClass(filename);
  if (kind === 'archive') {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8v11a2 2 0 01-2 2H5a2 2 0 01-2-2V8"></path><path d="M3 8l2-5h14l2 5"></path><path d="M12 3v18"></path><path d="M9 7h6"></path></svg>';
  }
  if (kind === 'image' || kind === 'media') {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><path d="M21 15l-5-5L5 21"></path></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path><path d="M14 2v6h6"></path></svg>';
}

function emptyStateHtml(title, hint) {
  return `<li class="empty-state"><div class="empty-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"></path></svg></div>${escapeHtml(title)}<span class="empty-hint">${escapeHtml(hint)}</span></li>`;
}

const PAGE_SIZE = 100;
let allEntries = [];
let currentPage = 0;
let isLoading = false;
let fileFilterQuery = '';

function normalizeSearch(value) {
  return String(value || '').trim().toLowerCase();
}

function fileOnly(entries = allEntries) {
  return entries.filter(entry => entry.type === 'file');
}

function getVisibleEntries() {
  if (!fileFilterQuery) return allEntries;
  const includeNames = new Set();
  for (const entry of allEntries) {
    const name = entry.name || '';
    if (!name.toLowerCase().includes(fileFilterQuery)) continue;
    includeNames.add(name);
    const parts = name.split('/');
    let parent = '';
    for (let i = 0; i < parts.length - 1; i += 1) {
      parent = parent ? `${parent}/${parts[i]}` : parts[i];
      includeNames.add(parent);
    }
  }
  return allEntries.filter(entry => includeNames.has(entry.name));
}

function updateFileSummary(entries = getVisibleEntries()) {
  const el = document.getElementById('file-count-summary');
  if (!el) return;
  const total = fileOnly().length;
  const visible = fileOnly(entries).length;
  if (total === 0) {
    el.textContent = '0 个文件';
  } else if (fileFilterQuery) {
    el.textContent = `显示 ${visible}/${total}`;
  } else {
    el.textContent = `${total} 个文件`;
  }
}

function pruneSelectionToKnownFiles() {
  const knownFiles = new Set(fileOnly().map(entry => entry.name));
  for (const name of Array.from(selectedFiles)) {
    if (!knownFiles.has(name)) selectedFiles.delete(name);
  }
}

function syncRenderedSelection() {
  document.querySelectorAll('.file-item:not(.dir-item)').forEach(li => {
    const selected = !!li.dataset.name && selectedFiles.has(li.dataset.name);
    li.classList.toggle('selected', selected);
    const checkbox = li.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = selected;
  });
  updateSelectionUI();
}

async function loadFiles() {
  const listEl = document.getElementById('file-list');
  const btn = document.getElementById('refresh-files-btn');

  if (btn) { btn.classList.add('spinning'); setTimeout(() => btn.classList.remove('spinning'), 600); }

  try {
    const res = await apiFetch('/api/files');
    if (res.status === 401 || res.status === 403) {
      await resetToPairing('配对已失效，请在服务端生成新 PIN 后重新配对');
      return;
    }
    if (!res.ok) throw new Error('Failed to load files');
    const { encrypted } = await res.json();

    const plainBuf = await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag);
    allEntries = JSON.parse(new TextDecoder().decode(plainBuf));
    currentPage = 0;
    pruneSelectionToKnownFiles();

    teardownScrollLoader();
    listEl.innerHTML = '';
    if (allEntries.length === 0) {
      updateFileSummary([]);
      listEl.innerHTML = emptyStateHtml('暂无共享文件', '分享端添加文件后会自动出现在这里');
      return;
    }

    renderCurrentFileList();
  } catch (err) {
    listEl.innerHTML = `<li class="loading error-state">${escapeHtml(err.message)}</li>`;
  }
}

function renderCurrentFileList() {
  const listEl = document.getElementById('file-list');
  const entries = getVisibleEntries();
  currentPage = 0;
  isLoading = false;
  teardownScrollLoader();
  listEl.innerHTML = '';
  updateFileSummary(entries);

  if (allEntries.length === 0) {
    listEl.innerHTML = emptyStateHtml('暂无共享文件', '分享端添加文件后会自动出现在这里');
    return;
  }

  if (entries.length === 0) {
    listEl.innerHTML = emptyStateHtml('没有匹配文件', '换一个关键词，或清空搜索条件');
    syncRenderedSelection();
    return;
  }

  renderNextPage();
  syncRenderedSelection();

  if (entries.length > PAGE_SIZE) setupScrollLoader(listEl);
}

function renderNextPage() {
  const entries = getVisibleEntries();
  if (isLoading || currentPage * PAGE_SIZE >= entries.length) return;
  isLoading = true;

  const listEl = document.getElementById('file-list');
  const loadMoreEl = listEl.querySelector('.load-more');
  if (loadMoreEl) loadMoreEl.remove();

  const start = currentPage * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, entries.length);

  // Use DocumentFragment for better performance with large lists
  const fragment = document.createDocumentFragment();

  for (let i = start; i < end; i++) {
    const entry = entries[i];
    const depth = (entry.name.match(/\//g) || []).length;
    const indent = Math.min(depth, 3);
    const baseName = entry.name.split('/').pop();
    const li = document.createElement('li');
    const checkboxId = `file-${start}-${i}`;

    if (entry.type === 'dir') {
      li.className = `file-item dir-item indent-${indent}`;
      li.dataset.dir = entry.name;
      li.tabIndex = 0;
      li.setAttribute('role', 'button');
      li.setAttribute('aria-expanded', 'true');
      li.setAttribute('aria-label', `展开或收起目录 ${baseName}`);
      li.innerHTML = `<div class="dir-name"><svg class="dir-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg><svg class="dir-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>${escapeHtml(baseName)}</div>`;
      li.addEventListener('click', () => toggleDir(li, entry.name));
    } else {
      li.className = `file-item indent-${indent}`;
      li.dataset.name = entry.name;
      li.tabIndex = 0;
      li.setAttribute('role', 'button');
      li.setAttribute('aria-label', `下载 ${baseName}，${formatSize(entry.size)}`);
      // Add checkbox for selection mode
      li.innerHTML = `<input type="checkbox" class="file-checkbox" id="${checkboxId}">
        <label for="${checkboxId}" class="file-checkbox-label">
          <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </label>
        <span class="file-icon ${fileIconClass(baseName)}" aria-hidden="true">${fileIconSvg(baseName)}</span>
        <div class="file-content-wrapper">
          <div class="file-name">${escapeHtml(baseName)}</div>
          <div class="file-meta">${formatSize(entry.size)} · ${formatModifiedTime(entry.modified)}</div>
        </div>
        <span class="file-dl" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path><path d="M7 10l5 5 5-5"></path><path d="M12 15V3"></path></svg><span class="file-dl-label">下载</span></span>`;
    }
    fragment.appendChild(li);
  }

  listEl.appendChild(fragment);

  currentPage++;

  if (end < entries.length) {
    const loadMoreLi = document.createElement('li');
    loadMoreLi.className = 'loading load-more';
    loadMoreLi.textContent = `已加载 ${end}/${entries.length}，点击或滚动加载更多`;
    loadMoreLi.style.cursor = 'pointer';
    loadMoreLi.onclick = () => { isLoading = false; renderNextPage(); };
    listEl.appendChild(loadMoreLi);
  }

  isLoading = false;
  syncRenderedSelection();
}

function toggleDir(dirLi, dirName) {
  const collapsed = dirLi.classList.toggle('collapsed');
  dirLi.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  const listEl = document.getElementById('file-list');
  const prefix = dirName + '/';
  let sibling = dirLi.nextElementSibling;
  while (sibling) {
    const name = sibling.dataset.name || sibling.dataset.dir || '';
    if (!name.startsWith(prefix)) break;
    sibling.classList.toggle('dir-child-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }
}

function setupScrollLoader(listEl) {
  teardownScrollLoader();
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !isLoading) {
      const loadMoreEl = listEl.querySelector('.load-more');
      if (loadMoreEl) renderNextPage();
    }
  }, { rootMargin: '100px' });
  scrollObserver = observer;
  
  const checkLoader = () => {
    const loadMoreEl = listEl.querySelector('.load-more');
    if (loadMoreEl) observer.observe(loadMoreEl);
  };
  checkLoader();
  scrollLoaderInterval = setInterval(checkLoader, 500);
}

function teardownScrollLoader() {
  if (scrollObserver) {
    scrollObserver.disconnect();
    scrollObserver = null;
  }
  if (scrollLoaderInterval) {
    clearInterval(scrollLoaderInterval);
    scrollLoaderInterval = null;
  }
}

async function downloadFile(name, li) {
  if (li.classList.contains('downloading')) return;
  let sink = null;
  let completed = false;
  clearFileDownloadComplete(li);
  li.classList.add('downloading');
  setFileDownloadText(li, '解密中...');

  try {
    // Encode each path segment separately to preserve slashes
    const encodedPath = name.split('/').map(encodeURIComponent).join('/');
    const entry = allEntries.find(item => item.type === 'file' && item.name === name);
    const baseName = name.split('/').pop() || 'download.bin';
    const useChunkedDownload = entry && entry.size >= LARGE_FILE_STREAM_THRESHOLD && window.ReadableStream;
    const endpoint = useChunkedDownload ? `/api/files-chunked/${encodedPath}` : `/api/files/${encodedPath}`;

    if (useChunkedDownload) {
      setFileDownloadText(li, '准备下载...');
      try {
        sink = await openChunkedDownloadSink(baseName, entry.size, { apiPath: endpoint, relPath: name });
      } catch (err) {
        if (err && err.name === 'AbortError') {
          toast('已取消下载', 'info');
          return;
        }
        throw err;
      }
      if (sink && sink.ownsTransfer) {
        setFileDownloadText(li, '浏览器下载中...');
        await sink.completion;
        sink = null;
        completed = true;
        markFileDownloadComplete(li);
        toast(`下载完成：${baseName}`, 'ok');
        return;
      }
      setFileDownloadText(li, '解密中...');
    }

    const res = await apiFetch(endpoint);
    if (res.status === 401 || res.status === 403) {
      if (sink) {
        try { await sink.abort(); } catch {}
        sink = null;
      }
      await resetToPairing('配对已失效，请在服务端生成新 PIN 后重新配对');
      return;
    }
    if (!res.ok) throw new Error(await getErrorMessage(res, 'Download failed'));

    if (useChunkedDownload) {
      const filename = safeDecodeHeader(res.headers.get('x-file-name')) || baseName;
      const result = await saveChunkedDownloadResponse(res, filename, sink, name);
      sink = null;
      const suffix = result.mode === 'blob' ? '（内存回退）' : '';
      completed = true;
      markFileDownloadComplete(li);
      toast(`下载完成：${baseName}${suffix}`, 'ok');
    } else {
      const { filename, plainBuf } = await decryptDownloadResponse(res);
      saveBytes(filename || baseName, plainBuf);
      completed = true;
      markFileDownloadComplete(li);
      toast(`下载完成：${baseName}`, 'ok');
    }
  } catch (err) {
    if (sink) {
      try { await sink.abort(); } catch {}
    }
    if (err && err.name === 'AbortError') {
      toast('已取消下载', 'info');
      return;
    }
    if (err && (err.status === 401 || err.status === 403)) {
      await resetToPairing('配对已失效，请在服务端生成新 PIN 后重新配对');
      return;
    }
    toast('下载失败: ' + err.message, 'err');
  } finally {
    li.classList.remove('downloading');
    if (!completed) setFileDownloadText(li, '下载');
  }
}

function setFileDownloadText(li, text) {
  const label = li.querySelector('.file-dl-label') || li.querySelector('.file-dl');
  if (label) label.textContent = text;
}

const fileDownloadCompleteTimers = new WeakMap();

function clearFileDownloadComplete(li) {
  const timer = fileDownloadCompleteTimers.get(li);
  if (timer) clearTimeout(timer);
  fileDownloadCompleteTimers.delete(li);
  li.classList.remove('download-complete');
}

function markFileDownloadComplete(li) {
  clearFileDownloadComplete(li);
  li.classList.add('download-complete');
  setFileDownloadText(li, '已完成');
  const timer = setTimeout(() => {
    fileDownloadCompleteTimers.delete(li);
    if (!li.classList.contains('downloading')) {
      li.classList.remove('download-complete');
      setFileDownloadText(li, '下载');
    }
  }, DOWNLOAD_COMPLETE_HOLD_MS);
  fileDownloadCompleteTimers.set(li, timer);
}

// ============ PIN Input ============

function setupPinInputs() {
  const inputs = document.querySelectorAll('.pin-input');
  const btn = document.getElementById('pair-btn');

  function getPin() { return Array.from(inputs).map(el => el.value).join(''); }

  function updateState() {
    const pin = getPin();
    btn.disabled = pin.length !== 6;
    inputs.forEach(el => el.classList.toggle('filled', !!el.value));
    if (pin.length === 6) {
      setTimeout(() => doPairing(pin), 150);
    }
  }

  inputs.forEach((input, i) => {
    input.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/[^0-9]/g, '');
      if (e.target.value && i < inputs.length - 1) inputs[i + 1].focus();
      updateState();
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && i > 0) {
        inputs[i - 1].focus();
        inputs[i - 1].value = '';
        updateState();
      }
    });

    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g, '');
      for (let j = 0; j < Math.min(pasted.length, inputs.length - i); j++) {
        inputs[i + j].value = pasted[j];
      }
      inputs[Math.min(i + pasted.length, inputs.length - 1)].focus();
      updateState();
    });
  });

  btn.addEventListener('click', () => {
    const pin = getPin();
    if (pin.length === 6) doPairing(pin);
  });
}

// ============ Selection Mode ============
let selectionMode = false;
let selectedFiles = new Set(); // Store selected file names

const selectionBar = document.getElementById('bottom-selection-bar');
const topSelectionBar = document.getElementById('top-selection-bar');
const selectionCountEl = document.getElementById('selection-count');
const batchDownloadBtn = document.getElementById('batch-download-btn');
const selectAllBtn = document.getElementById('select-all-btn');
const selectNoneBtn = document.getElementById('select-none-btn');
const toggleSelectionModeBtn = document.getElementById('toggle-selection-mode-btn');
const closeTopSelectionBtn = document.getElementById('close-top-selection-btn');
const clearSelectionBtn = document.getElementById('clear-selection-btn');

function updateSelectionUI() {
  const count = selectedFiles.size;
  selectionCountEl.textContent = count;
  const batchBusy = batchDownloadBtn.dataset.busy === '1';
  batchDownloadBtn.disabled = batchBusy || count === 0;

  if (selectionMode && topSelectionBar) {
    const visibleSelected = document.querySelectorAll('.file-item.selected:not(.dir-item)').length;
    const suffix = visibleSelected === count ? '' : `，当前显示 ${visibleSelected} 项`;
    document.getElementById('top-selection-text').textContent = `已选择 ${count} 项${suffix}`;
  }
}

function toggleSelection(fileList, name, li) {
  if (selectedFiles.has(name)) {
    selectedFiles.delete(name);
    li.classList.remove('selected');
    const checkbox = li.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = false;
  } else {
    selectedFiles.add(name);
    li.classList.add('selected');
    const checkbox = li.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = true;
  }
  updateSelectionUI();
}

function toggleSelectionMode() {
  setSelectionMode(!selectionMode, { clear: selectionMode });
}

function setSelectionMode(enabled, options = {}) {
  if (enabled) clearBatchDownloadComplete();
  selectionMode = enabled;
  document.body.classList.toggle('selection-active', selectionMode);
  const listEl = document.getElementById('file-list');

  if (selectionMode) {
    listEl.classList.add('selection-mode');
    toggleSelectionModeBtn.textContent = '完成';
    topSelectionBar.classList.add('active');
    selectionBar.classList.add('active');
  } else {
    listEl.classList.remove('selection-mode');
    if (options.clear) selectedFiles.clear();
    toggleSelectionModeBtn.textContent = '选择';
    selectionBar.classList.remove('active');
    topSelectionBar.classList.remove('active');
    document.getElementById('top-selection-text').textContent = '选择文件';
  }
  syncRenderedSelection();
}

function selectAllFiles() {
  // Select only files that are currently rendered, respecting search and pagination.
  const loadedItems = document.querySelectorAll('.file-item:not(.dir-item)');
  loadedItems.forEach(li => {
    if (li.dataset.name) {
      selectedFiles.add(li.dataset.name);
    }
  });
  syncRenderedSelection();
}

function clearSelection() {
  selectedFiles.clear();
  syncRenderedSelection();
}

// ============ ZIP archive writer (STORE method, streamed to disk) ============

const ZIP_MAX_FILE_BYTES = 256 * 1024 * 1024; // skip files larger than this in a batch

const ZIP_CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32Update(buf, crc) {
  let c = (crc ^ 0xFFFFFFFF) >>> 0;
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ ZIP_CRC_TABLE[(c ^ buf[i]) & 0xFF];
  return (c ^ 0xFFFFFFFF) >>> 0;
}

const zipU16 = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
const zipU32 = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
function zipBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// Writes a streaming zip to `sink` (SW port writer / file picker / blob fallback).
function createZipWriter(sink) {
  const encoder = new TextEncoder();
  const centralEntries = [];
  let offset = 0;

  async function write(bytes) { await sink.write(bytes); offset += bytes.length; }

  async function addFile(name, data) {
    const nameBytes = encoder.encode(name);
    const crc = crc32Update(data, 0);
    const size = data.length;
    const startOffset = offset;
    const localHeader = zipBytes(
      new Uint8Array([0x50, 0x4b, 0x03, 0x04]),
      zipU16(20), zipU16(0), zipU16(0),
      zipU16(0), zipU16(0),
      zipU32(crc), zipU32(size), zipU32(size),
      zipU16(nameBytes.length), zipU16(0),
      nameBytes
    );
    await write(localHeader);
    const CHUNK = 8 * 1024 * 1024;
    for (let i = 0; i < data.length; i += CHUNK) {
      await write(data.subarray(i, Math.min(i + CHUNK, data.length)));
    }
    centralEntries.push({ nameBytes, crc, size, offset: startOffset });
  }

  async function finalize() {
    const cdStart = offset;
    for (const e of centralEntries) {
      const cd = zipBytes(
        new Uint8Array([0x50, 0x4b, 0x01, 0x02]),
        zipU16(20), zipU16(20), zipU16(0), zipU16(0),
        zipU16(0), zipU16(0),
        zipU32(e.crc), zipU32(e.size), zipU32(e.size),
        zipU16(e.nameBytes.length), zipU16(0), zipU16(0),
        zipU16(0), zipU16(0), zipU32(0),
        zipU32(e.offset), e.nameBytes
      );
      await write(cd);
    }
    const eocd = zipBytes(
      new Uint8Array([0x50, 0x4b, 0x05, 0x06]),
      zipU16(0), zipU16(0),
      zipU16(centralEntries.length), zipU16(centralEntries.length),
      zipU32(offset - cdStart), zipU32(cdStart),
      zipU16(0)
    );
    await write(eocd);
  }

  return { addFile, finalize };
}

function createBlobZipSink(filename) {
  const chunks = [];
  return {
    mode: 'blob',
    async write(chunk) { chunks.push(chunk); },
    async close() { saveByteChunks(filename, chunks); },
    async abort() { chunks.length = 0; },
  };
}

async function openZipSink(filename, estimatedBytes = 0) {
  if (canStreamToDisk() && !wantsBrowserManagedDownload()) {
    return openWritableDownload(filename);
  }

  if (wantsBrowserManagedDownload()) {
    if (downloadStreamSupported()) {
      try { return await openBrowserManagedDownload(filename, null); }
      catch (err) { console.warn('SW zip sink unavailable:', err); }
    }
    if (estimatedBytes > BLOB_DOWNLOAD_FALLBACK_MAX_BYTES) {
      throw new Error('浏览器下载管理器通道未就绪，批量文件过大，无法安全使用内存回退；请刷新页面后重试，或清除 cloudsyncd-download-mode 后使用文件选择器流式保存');
    }
  }

  if (estimatedBytes > BLOB_DOWNLOAD_FALLBACK_MAX_BYTES) {
    throw new Error('当前浏览器无法安全流式保存大批量文件。请使用支持 File System Access 的 Chrome/Edge，或使用 cloudsyncd client get 下载');
  }
  return createBlobZipSink(filename);
}

async function collectFileBytes(fileName, entry) {
  const encodedPath = fileName.split('/').map(encodeURIComponent).join('/');
  const useChunked = entry && entry.size >= LARGE_FILE_STREAM_THRESHOLD && window.ReadableStream;
  const endpoint = useChunked ? `/api/files-chunked/${encodedPath}` : `/api/files/${encodedPath}`;
  const res = await apiFetch(endpoint);
  if (res.status === 401 || res.status === 403) {
    await resetToPairing('配对已失效，请在服务端生成新 PIN 后重新配对');
    throw new Error('配对已失效');
  }
  if (!res.ok) throw new Error(await getErrorMessage(res, 'Download failed'));
  if (useChunked) {
    const chunks = [];
    let total = 0;
    let finalManifest = null;
    for await (const c of decryptChunkedDownloadResponse(res, fileName, (manifest) => { finalManifest = manifest; })) {
      chunks.push(c);
      total += c.length;
    }
    assertChunkedDownloadComplete(finalManifest, total);
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.length; }
    return merged;
  }
  const { plainBuf } = await decryptDownloadResponse(res);
  return plainBuf;
}

function setBatchBusy(busy, text) {
  if (!batchDownloadBtn) return;
  if (busy) clearBatchDownloadComplete();
  batchDownloadBtn.dataset.busy = busy ? '1' : '0';
  batchDownloadBtn.textContent = text || '批量下载';
  updateSelectionUI();
}

let batchDownloadCompleteTimer = null;

function clearBatchDownloadComplete() {
  if (!batchDownloadBtn) return;
  if (batchDownloadCompleteTimer) {
    clearTimeout(batchDownloadCompleteTimer);
    batchDownloadCompleteTimer = null;
  }
  batchDownloadBtn.classList.remove('download-complete');
}

function markBatchDownloadComplete() {
  if (!batchDownloadBtn) return;
  clearBatchDownloadComplete();
  batchDownloadBtn.dataset.busy = '1';
  batchDownloadBtn.classList.add('download-complete');
  batchDownloadBtn.textContent = '已完成';
  updateSelectionUI();
  batchDownloadCompleteTimer = setTimeout(() => {
    batchDownloadCompleteTimer = null;
    if (selectionMode) setSelectionMode(false, { clear: true });
    batchDownloadBtn.classList.remove('download-complete');
    setBatchBusy(false);
  }, DOWNLOAD_COMPLETE_HOLD_MS);
}

// Batch download = ONE zip archive (not N separate downloads). Streams to disk
// when available; skips failed / oversized files instead of aborting the whole
// batch.
async function batchDownload() {
  if (selectedFiles.size === 0) return;
  const fileNames = Array.from(selectedFiles);
  const total = fileNames.length;
  const zipName = `cloudsyncd-files-${total}.zip`;
  const estimatedBytes = fileNames.reduce((sum, fileName) => {
    const entry = allEntries.find(it => it.type === 'file' && it.name === fileName);
    if (!entry || entry.size > ZIP_MAX_FILE_BYTES) return sum;
    return sum + entry.size;
  }, 0);

  setBatchBusy(true, `打包中 0/${total}`);
  let sink = null;
  const failed = [];
  const skipped = [];
  let done = 0;
  let completed = false;

  try {
    sink = await openZipSink(zipName, estimatedBytes);
    const zip = createZipWriter(sink);

    for (const fileName of fileNames) {
      const entry = allEntries.find(it => it.type === 'file' && it.name === fileName);
      if (entry && entry.size > ZIP_MAX_FILE_BYTES) {
        skipped.push(fileName);
      } else {
        try {
          const data = await collectFileBytes(fileName, entry);
          await zip.addFile(fileName, data);
        } catch (err) {
          if (err.message === '配对已失效') throw err;
          console.error(`Failed to add ${fileName} to zip:`, err);
          failed.push(fileName);
        }
      }
      done += 1;
      setBatchBusy(true, `打包中 ${done}/${total}`);
    }

    await zip.finalize();
    await sink.close();
    sink = null;

    const okCount = total - failed.length - skipped.length;
    let msg = `下载完成：${zipName}（${okCount}/${total} 个文件）`;
    if (failed.length) msg += `，${failed.length} 个失败`;
    if (skipped.length) msg += `，${skipped.length} 个过大已跳过`;
    completed = true;
    markBatchDownloadComplete();
    toast(msg, (failed.length || skipped.length) ? 'info' : 'ok');
  } catch (err) {
    if (sink) { try { await sink.abort(); } catch {} }
    if (err.message !== '配对已失效') toast('打包下载失败: ' + err.message, 'err');
  } finally {
    if (!completed) setBatchBusy(false);
  }
}

function setupEventListeners() {
  // Theme toggle
  const themeToggleBtn = document.getElementById('theme-toggle');
  if (themeToggleBtn) themeToggleBtn.addEventListener('click', toggleTheme);

  // Refresh files button (was an inline onclick; moved here so CSP script-src
  // 'self' can be enforced without 'unsafe-inline').
  const refreshBtn = document.getElementById('refresh-files-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadFiles);

  const fileSearchInput = document.getElementById('file-search-input');
  if (fileSearchInput) {
    fileSearchInput.addEventListener('input', () => {
      fileFilterQuery = normalizeSearch(fileSearchInput.value);
      renderCurrentFileList();
    });
  }

  // Toggle selection mode button
  if (toggleSelectionModeBtn) {
    toggleSelectionModeBtn.addEventListener('click', toggleSelectionMode);
  }

  // Close top selection bar
  if (closeTopSelectionBtn) {
    closeTopSelectionBtn.addEventListener('click', () => setSelectionMode(false, { clear: true }));
  }

  // Select all / Clear
  if (selectAllBtn) {
    selectAllBtn.addEventListener('click', selectAllFiles);
  }
  if (selectNoneBtn) {
    selectNoneBtn.addEventListener('click', clearSelection);
  }
  if (clearSelectionBtn) {
    clearSelectionBtn.addEventListener('click', clearSelection);
  }

  // Batch download
  if (batchDownloadBtn) {
    batchDownloadBtn.addEventListener('click', batchDownload);
  }

  // Setup checkbox click handlers for file items
  document.getElementById('file-list')?.addEventListener('click', (e) => {
    // Label clicks only stop propagation (was an inline onclick); the checkbox
    // toggle is handled by the .file-checkbox branch below via the label's
    // default behavior. Kept here for CSP (no inline handler).
    if (e.target.closest('.file-checkbox-label')) {
      e.stopPropagation();
      return;
    }

    const checkbox = e.target.closest('.file-checkbox');
    if (checkbox) {
      const li = checkbox.closest('.file-item');
      if (li && li.dataset.name) {
        e.stopPropagation();
        toggleSelection(null, li.dataset.name, li);
      }
      return;
    }

    const li = e.target.closest('.file-item');
    if (!li || !li.dataset.name) return;

    if (selectionMode && !e.target.closest('.file-dl')) {
      e.stopPropagation();
      toggleSelection(null, li.dataset.name, li);
      return;
    }

    downloadFile(li.dataset.name, li);
  });

  document.getElementById('file-list')?.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    if (e.target.closest('.file-checkbox')) return;
    const li = e.target.closest('.file-item');
    if (!li) return;
    e.preventDefault();
    if (li.dataset.dir) {
      toggleDir(li, li.dataset.dir);
      return;
    }
    if (!li.dataset.name) return;
    if (selectionMode) {
      toggleSelection(null, li.dataset.name, li);
    } else {
      downloadFile(li.dataset.name, li);
    }
  });

  // Bottom action bar click close
  if (selectionBar) {
    selectionBar.addEventListener('click', (e) => {
      if (e.target === selectionBar) {
        setSelectionMode(false, { clear: true });
      }
    });
  }
}

// ============ Init ============

async function init() {
  setupPinInputs();
  setupEventListeners();
  warmDownloadServiceWorker();

  const storedKey = await KeyStore.get('encryptionKey');
  const storedDeviceId = await KeyStore.get('deviceId');
  if (storedKey && storedDeviceId) {
    try {
      const statusRes = await fetch('/api/status');
      const { paired } = await statusRes.json();
      if (paired) {
        encryptionKey = hex2buf(storedKey);
        deviceId = storedDeviceId;
        showMainScreen();
        return;
      }
      await clearStoredPairing();
    } catch { /* server not paired */ }
  }

  showPairScreen();
  setTimeout(() => document.querySelector('.pin-input').focus(), 100);
}

init();
