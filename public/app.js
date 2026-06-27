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

    const ciphertext = payload.slice(0, payload.length - tagLength);
    const tag = payload.slice(payload.length - tagLength);
    const plainBuf = await Crypto.decryptBytes(encryptionKey, hex2buf(streamIv), ciphertext, tag);

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

function saveBytes(filename, plainBuf) {
  const blob = new Blob([plainBuf]);
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
};

// ============ Toast Notifications ============

function toast(msg, type = 'info') {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ============ Screen Management ============

let encryptionKey = null;
let deviceId = null;
let fileRefreshTimer = null;

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

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

const PAGE_SIZE = 100;
let allEntries = [];
let currentPage = 0;
let isLoading = false;

async function loadFiles() {
  const listEl = document.getElementById('file-list');
  const btn = document.getElementById('refresh-files-btn');
  const previousSelection = selectionMode ? Array.from(selectedFiles) : [];

  if (btn) { btn.classList.add('spinning'); setTimeout(() => btn.classList.remove('spinning'), 600); }

  try {
    const res = await apiFetch('/api/files');
    if (!res.ok) throw new Error('Failed to load files');
    const { encrypted } = await res.json();

    const plainBuf = await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag);
    allEntries = JSON.parse(new TextDecoder().decode(plainBuf));
    currentPage = 0;

    listEl.innerHTML = '';
    if (allEntries.length === 0) {
      listEl.innerHTML = '<li class="empty-state"><div class="empty-icon">📁</div>暂无共享文件<br><span style="font-size:0.72rem;color:var(--text-3)">将文件放入 shared/ 目录即可</span></li>';
      return;
    }

    renderNextPage();

    // Re-apply selection after render
    if (previousSelection.length > 0) {
      reapplySelection(previousSelection);
    }

    if (allEntries.length > PAGE_SIZE) {
      setupScrollLoader(listEl);
    }
  } catch (err) {
    listEl.innerHTML = `<li class="loading" style="color:var(--error)">${escapeHtml(err.message)}</li>`;
  }
}

function reapplySelection(previousSelection) {
  const items = document.querySelectorAll('.file-item');
  items.forEach(li => {
    if (li.dataset.name && previousSelection.includes(li.dataset.name)) {
      selectedFiles.add(li.dataset.name);
      li.classList.add('selected');
      const checkbox = li.querySelector('.file-checkbox');
      if (checkbox) checkbox.checked = true;
    }
  });
  updateSelectionUI();
}

function renderNextPage() {
  if (isLoading || currentPage * PAGE_SIZE >= allEntries.length) return;
  isLoading = true;

  const listEl = document.getElementById('file-list');
  const loadMoreEl = listEl.querySelector('.load-more');
  if (loadMoreEl) loadMoreEl.remove();

  const start = currentPage * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, allEntries.length);

  // Use DocumentFragment for better performance with large lists
  const fragment = document.createDocumentFragment();

  for (let i = start; i < end; i++) {
    const entry = allEntries[i];
    const depth = (entry.name.match(/\//g) || []).length;
    const indent = Math.min(depth, 3);
    const baseName = entry.name.split('/').pop();
    const li = document.createElement('li');
    const checkboxId = `file-${i}`;

    if (entry.type === 'dir') {
      li.className = `file-item dir-item indent-${indent}`;
      li.dataset.dir = entry.name;
      li.innerHTML = `<div class="dir-name"><svg class="dir-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>${escapeHtml(baseName)}</div>`;
      li.addEventListener('click', () => toggleDir(li, entry.name));
    } else {
      li.className = `file-item indent-${indent}`;
      li.dataset.name = entry.name;
      // Add checkbox for selection mode
      li.innerHTML = `<input type="checkbox" class="file-checkbox" id="${checkboxId}">
        <label for="${checkboxId}" class="file-checkbox-label">
          <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </label>
        <div class="file-content-wrapper">
          <div class="file-name">${escapeHtml(baseName)}</div>
          <div class="file-meta">${formatSize(entry.size)} · ${new Date(entry.modified).toLocaleString()}</div>
        </div>
        <span class="file-dl">下载</span>`;
    }
    fragment.appendChild(li);
  }

  listEl.appendChild(fragment);

  currentPage++;

  if (end < allEntries.length) {
    const loadMoreLi = document.createElement('li');
    loadMoreLi.className = 'loading load-more';
    loadMoreLi.textContent = `已加载 ${end}/${allEntries.length}，点击或滚动加载更多`;
    loadMoreLi.style.cursor = 'pointer';
    loadMoreLi.onclick = () => { isLoading = false; renderNextPage(); };
    listEl.appendChild(loadMoreLi);
  }

  // Attach click handlers for newly added items
  const newItems = listEl.querySelectorAll(`li[data-name]:nth-child(n-${end})`);
  newItems.forEach(li => {
    if (!li.classList.contains('dir-item')) {
      li.addEventListener('click', (e) => {
        if (!e.target.closest('.file-checkbox') && !e.target.closest('.file-checkbox-label')) {
          downloadFile(li.dataset.name, li);
        }
      });
    }
  });

  isLoading = false;
}

function toggleDir(dirLi, dirName) {
  const collapsed = dirLi.classList.toggle('collapsed');
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
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !isLoading) {
      const loadMoreEl = listEl.querySelector('.load-more');
      if (loadMoreEl) renderNextPage();
    }
  }, { rootMargin: '100px' });
  
  const checkLoader = () => {
    const loadMoreEl = listEl.querySelector('.load-more');
    if (loadMoreEl) observer.observe(loadMoreEl);
  };
  checkLoader();
  setInterval(checkLoader, 500);
}

async function downloadFile(name, li) {
  if (li.classList.contains('downloading')) return;
  li.classList.add('downloading');
  li.querySelector('.file-dl').textContent = '解密中...';

  try {
    // Encode each path segment separately to preserve slashes
    const encodedPath = name.split('/').map(encodeURIComponent).join('/');
    const res = await apiFetch(`/api/files/${encodedPath}`);
    if (!res.ok) throw new Error(await getErrorMessage(res, 'Download failed'));
    const { filename, plainBuf } = await decryptDownloadResponse(res);

    saveBytes(filename || name.split('/').pop(), plainBuf);
    toast(`${name.split('/').pop()} 下载完成`, 'ok');
  } catch (err) {
    toast('下载失败: ' + err.message, 'err');
  } finally {
    li.classList.remove('downloading');
    li.querySelector('.file-dl').textContent = '下载';
  }
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
  batchDownloadBtn.disabled = count === 0;

  // Update top bar selection count only (don't toggle visibility)
  if (selectionMode && topSelectionBar) {
    document.getElementById('top-selection-text').textContent = `已选择 ${count} 项`;
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
  selectionMode = !selectionMode;
  const listEl = document.getElementById('file-list');

  if (selectionMode) {
    listEl.classList.add('selection-mode');
    toggleSelectionModeBtn.textContent = '完成';
    topSelectionBar.classList.add('active');
    selectionBar.classList.add('active');
    // Update text based on current selection
    document.getElementById('top-selection-text').textContent = `已选择 ${selectedFiles.size} 项`;
  } else {
    listEl.classList.remove('selection-mode');
    selectedFiles.clear();
    toggleSelectionModeBtn.textContent = '选择';
    selectionBar.classList.remove('active');
    topSelectionBar.classList.remove('active');
    selectionCountEl.textContent = '0';
    document.getElementById('top-selection-text').textContent = '选择文件';
  }
}

function selectAllFiles() {
  // Only select files (not directories) that are currently loaded
  const loadedItems = document.querySelectorAll('.file-item:not(.dir-item)');
  loadedItems.forEach(li => {
    if (li.dataset.name) {
      selectedFiles.add(li.dataset.name);
      li.classList.add('selected');
      const checkbox = li.querySelector('.file-checkbox');
      if (checkbox) checkbox.checked = true;
    }
  });
  updateSelectionUI();
}

function clearSelection() {
  selectedFiles.clear();
  document.querySelectorAll('.file-item.selected').forEach(li => {
    li.classList.remove('selected');
    const checkbox = li.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = false;
  });
  updateSelectionUI();
}

async function batchDownload() {
  if (selectedFiles.size === 0) return;

  // Check if selection is too large
  if (selectedFiles.size > 50) {
    toast('批量下载最多选择 50 个文件', 'err');
    return;
  }

  let downloadedCount = 0;
  const totalCount = selectedFiles.size;

  for (const fileName of selectedFiles) {
    const listEl = document.getElementById('file-list');
    const li = Array.from(listEl.querySelectorAll('.file-item')).find(
      item => item.dataset.name === fileName
    );

    if (li) {
      li.classList.add('downloading');
      const dlSpan = li.querySelector('.file-dl') || li.querySelector('.file-name');
      if (dlSpan) dlSpan.textContent = '下载中...';
    }

    try {
      const encodedPath = fileName.split('/').map(encodeURIComponent).join('/');
      const res = await apiFetch(`/api/files/${encodedPath}`);
      if (!res.ok) throw new Error(await getErrorMessage(res, 'Download failed'));
      const { filename, plainBuf } = await decryptDownloadResponse(res);
      saveBytes(filename || fileName.split('/').pop(), plainBuf);
      downloadedCount++;
    } catch (err) {
      console.error(`Failed to download ${fileName}:`, err);
    }

    if (li) {
      li.classList.remove('downloading');
      const dlSpan = li.querySelector('.file-dl');
      if (dlSpan) dlSpan.textContent = '下载';
    }
  }

  toast(`批量下载完成: ${downloadedCount}/${totalCount}`, downloadedCount === totalCount ? 'ok' : 'info');
  clearSelection();
}

function setupEventListeners() {
  // Refresh files button (was an inline onclick; moved here so CSP script-src
  // 'self' can be enforced without 'unsafe-inline').
  const refreshBtn = document.getElementById('refresh-files-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadFiles);

  // Toggle selection mode button
  if (toggleSelectionModeBtn) {
    toggleSelectionModeBtn.addEventListener('click', toggleSelectionMode);
  }

  // Close top selection bar
  if (closeTopSelectionBtn) {
    closeTopSelectionBtn.addEventListener('click', () => {
      selectionMode = false;
      document.getElementById('file-list').classList.remove('selection-mode');
      topSelectionBar.classList.remove('active');
      selectionBar.classList.remove('active');
      updateSelectionUI();
    });
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

    // Handle file item click in selection mode
    if (selectionMode) {
      const li = e.target.closest('.file-item');
      if (li && li.dataset.name && !e.target.closest('.file-dl')) {
        e.stopPropagation();
        toggleSelection(null, li.dataset.name, li);
      }
    }
  });

  // Bottom action bar click close
  if (selectionBar) {
    selectionBar.addEventListener('click', (e) => {
      if (e.target === selectionBar) {
        selectionMode = false;
        document.getElementById('file-list').classList.remove('selection-mode');
        selectionBar.classList.remove('active');
        updateSelectionUI();
      }
    });
  }
}

// ============ Init ============

async function init() {
  setupPinInputs();
  setupEventListeners();

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
    } catch { /* server not paired */ }
  }

  showPairScreen();
  setTimeout(() => document.querySelector('.pin-input').focus(), 100);
}

init();
