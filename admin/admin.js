// cloudsyncd admin panel.
// The admin listener is local-only by default, so the dashboard opens directly.
// If the server is configured to require admin token auth, the same UI falls
// back to a token login screen.

const TOKEN_KEY = 'cloudsyncd-admin';
const $ = (id) => document.getElementById(id);
const loginScreen = () => $('login-screen');
const dashScreen = () => $('dash-screen');
let authRequired = false;

// ---------- toasts ----------
function toast(msg, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3300);
}

// ---------- api ----------
function getToken() { return sessionStorage.getItem(TOKEN_KEY) || ''; }
function setToken(t) { sessionStorage.setItem(TOKEN_KEY, t); }
function clearToken() { sessionStorage.removeItem(TOKEN_KEY); }

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers['x-admin-token'] = token;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch { data = { error: text }; } }
  if (res.status === 403 && authRequired) { logout(true); throw new Error('会话失效，请重新登录'); }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

function encodeSharedPath(relPath) {
  return String(relPath || '').replace(/^\/+/, '').split('/').map(encodeURIComponent).join('/');
}

function normalizeUploadName(file) {
  const relPath = String(file.webkitRelativePath || file.name || '').replace(/\\/g, '/').replace(/^\/+/, '');
  const parts = relPath.split('/');
  if (!relPath || parts.some((part) => !part || part === '.' || part === '..' || part.startsWith('.'))) {
    throw new Error(`文件名无效: ${file.name || relPath}`);
  }
  return parts.join('/');
}

function setUploadProgress(text) {
  const el = $('upload-progress');
  el.textContent = text || '';
  el.classList.toggle('show', !!text);
}

function uploadOneFile(file, relPath, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `/api/local/files/${encodeSharedPath(relPath)}`);
    const token = getToken();
    if (token) xhr.setRequestHeader('x-admin-token', token);
    xhr.setRequestHeader('content-type', 'application/octet-stream');
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) onProgress(event.loaded, event.total);
    };
    xhr.onload = () => {
      let data = {};
      if (xhr.responseText) {
        try { data = JSON.parse(xhr.responseText); } catch { data = { error: xhr.responseText }; }
      }
      if (xhr.status === 403 && authRequired) {
        logout(true);
        reject(new Error('会话失效，请重新登录'));
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(data.error || `HTTP ${xhr.status}`));
        return;
      }
      resolve(data);
    };
    xhr.onerror = () => reject(new Error('上传失败'));
    xhr.send(file);
  });
}

async function loadAuthMode() {
  try {
    const res = await fetch('/api/local/auth');
    if (!res.ok) return;
    const data = await res.json();
    authRequired = !!data.requiresToken;
  } catch {
    authRequired = false;
  }
}

function applyAuthModeUi() {
  $('logout-btn').style.display = authRequired ? '' : 'none';
  const tokenRotationItem = $('token-rotation-item');
  if (tokenRotationItem) tokenRotationItem.style.display = authRequired ? '' : 'none';
}

// ---------- formatting ----------
function fmtSize(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}
function fmtFileTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const pad = (n) => String(n).padStart(2, '0');
  const now = new Date();
  if (d.getFullYear() === now.getFullYear()) return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`;
}
function fmtUptime(ms) {
  if (ms == null || isNaN(ms)) return '—';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ---------- screens ----------
function showLogin() {
  if (!authRequired) {
    showDash();
    return;
  }
  clearToken();
  dashScreen().classList.remove('active');
  loginScreen().classList.add('active');
  $('token-input').value = '';
  $('token-input').focus();
}
function showDash() {
  loginScreen().classList.remove('active');
  dashScreen().classList.add('active');
  refreshAll();
  if (window.__uptimeTimer) clearInterval(window.__uptimeTimer);
  window.__uptimeTimer = setInterval(updateUptime, 30000);
}

async function tryLogin() {
  const token = $('token-input').value.trim();
  if (!token) { toast('请输入 Token', 'err'); return; }
  const btn = $('login-btn');
  btn.disabled = true; btn.textContent = '验证中…';
  setToken(token);
  try {
    await api('/api/local/status'); // 403 if wrong → logout(true) throws
    toast('已进入管理端', 'ok');
    showDash();
  } catch (e) {
    toast(e.message || 'Token 无效', 'err');
    showLogin();
  } finally {
    btn.disabled = false; btn.textContent = '进入';
  }
}

function logout(silent) {
  clearToken();
  if (window.__uptimeTimer) clearInterval(window.__uptimeTimer);
  if (!authRequired) {
    if (!silent) toast('本地管理端无需退出', 'info');
    showDash();
    return;
  }
  dashScreen().classList.remove('active');
  loginScreen().classList.add('active');
  $('token-input').value = '';
  if (!silent) { toast('已退出', 'info'); }
  $('token-input').focus();
}

// ---------- dashboard data ----------
let lastStatus = null;
let allFileEntries = [];
const selectedSharedFiles = new Set();
let fileSearchQuery = '';

async function loadStatus() {
  try {
    const s = await api('/api/local/status');
    lastStatus = s;
    $('stat-devices').textContent = s.deviceCount;
    $('stat-paired-sub').textContent = s.paired ? '已配对' : '未配对';
    $('stat-files').textContent = s.sharedFiles;
    $('stat-files-sub').textContent = fmtSize(s.sharedSize);
    $('stat-texts').textContent = s.textsCount;
    const ttlH = Math.round(s.textsExpiryMs / 3600000);
    $('stat-texts-sub').textContent = `上限 ${s.textsMax} · ${ttlH}h 过期`;
    $('stat-key').textContent = s.hasMasterKey ? '就绪' : '缺失';
    updateUptime();
  } catch (e) { toast(e.message, 'err'); }
}

function updateUptime() {
  if (!lastStatus) return;
  $('uptime').textContent = `运行 ${fmtUptime(Date.now() - lastStatus.startedAt)}`;
}

async function loadDevices() {
  const body = $('devices-body');
  try {
    const { devices } = await api('/api/local/devices');
    if (!devices.length) { body.innerHTML = '<div class="empty">暂无已配对设备</div>'; return; }
    const rows = devices.map((d) => `
      <tr>
        <td class="mono">${escapeHtml(d.id)}</td>
        <td class="muted">${fmtDate(d.pairedAt)}</td>
        <td class="right"><button class="btn btn-ghost revoke-one" data-id="${escapeHtml(d.id)}">撤销</button></td>
      </tr>`).join('');
    body.innerHTML = `<table class="tbl"><thead><tr><th>设备 ID</th><th>配对时间</th><th class="right"></th></tr></thead><tbody>${rows}</tbody></table>`;
    body.querySelectorAll('.revoke-one').forEach((b) => b.addEventListener('click', () => revokeOne(b.dataset.id)));
  } catch (e) { body.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`; }
}

async function loadFiles() {
  const body = $('files-body');
  try {
    const { entries } = await api('/api/local/files');
    allFileEntries = Array.isArray(entries) ? entries : [];
    pruneFileSelection();
    renderFiles();
  } catch (e) {
    allFileEntries = [];
    selectedSharedFiles.clear();
    body.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
    updateFileSelectionUi();
  }
}

function renderFiles() {
  const body = $('files-body');
  const visibleEntries = visibleFileEntries();
  if (!allFileEntries.length) {
    body.innerHTML = '<div class="empty">shared/ 目录为空</div>';
  } else if (!visibleEntries.length) {
    body.innerHTML = '<div class="empty">没有匹配的共享文件</div>';
  } else {
    body.innerHTML = visibleEntries.map(renderFileRow).join('');
    body.querySelectorAll('.shared-file-checkbox').forEach((checkbox) => {
      checkbox.addEventListener('change', () => toggleSharedFileSelection(checkbox.dataset.name, checkbox.checked));
    });
    body.querySelectorAll('.delete-file').forEach((button) => {
      button.addEventListener('click', () => deleteSharedFile(button.dataset.name));
    });
  }
  updateFileSelectionUi();
}

function visibleFileEntries() {
  const q = fileSearchQuery.trim().toLowerCase();
  if (!q) return allFileEntries;
  const matchingFileNames = allFileEntries
    .filter((entry) => entry.type === 'file' && entry.name.toLowerCase().includes(q))
    .map((entry) => entry.name);
  return allFileEntries.filter((entry) => {
    const name = entry.name.toLowerCase();
    if (name.includes(q)) return true;
    if (entry.type !== 'dir') return false;
    const prefix = `${entry.name}/`;
    return matchingFileNames.some((fileName) => fileName.startsWith(prefix));
  });
}

function visibleFileNames() {
  return visibleFileEntries().filter((entry) => entry.type === 'file').map((entry) => entry.name);
}

function existingFileNames() {
  return new Set(allFileEntries.filter((entry) => entry.type === 'file').map((entry) => entry.name));
}

function pruneFileSelection() {
  const existing = existingFileNames();
  Array.from(selectedSharedFiles).forEach((name) => {
    if (!existing.has(name)) selectedSharedFiles.delete(name);
  });
}

function updateFileSelectionUi() {
  const selectedCount = selectedSharedFiles.size;
  const visibleCount = visibleFileNames().length;
  const totalCount = allFileEntries.filter((entry) => entry.type === 'file').length;
  $('file-selection-count').textContent = `已选 ${selectedCount} · 显示 ${visibleCount}/${totalCount}`;
  $('select-visible-files-btn').disabled = visibleCount === 0;
  $('clear-file-selection-btn').disabled = selectedCount === 0;
  $('delete-selected-files-btn').disabled = selectedCount === 0;
}

function toggleSharedFileSelection(name, checked) {
  if (checked) selectedSharedFiles.add(name);
  else selectedSharedFiles.delete(name);
  updateFileSelectionUi();
}

function selectVisibleFiles() {
  visibleFileNames().forEach((name) => selectedSharedFiles.add(name));
  renderFiles();
}

function clearFileSelection() {
  selectedSharedFiles.clear();
  renderFiles();
}

function deleteSharedFileApi(name) {
  return api(`/api/local/files/${encodeSharedPath(name)}`, { method: 'DELETE' });
}

function renderFileRow(entry) {
  const depth = entry.name.split('/').length - 1;
  const indent = depth ? `<span class="indent">${'·  '.repeat(depth)}</span>` : '';
  if (entry.type === 'dir') {
    return `<div class="file-row dir" title="${escapeHtml(entry.name)}"><span class="file-check" aria-hidden="true"></span><span class="indent">▸</span><span class="name">${indent}${escapeHtml(basename(entry.name))}/</span></div>`;
  }
  const checked = selectedSharedFiles.has(entry.name) ? ' checked' : '';
  const selectedClass = checked ? ' selected' : '';
  return `<div class="file-row${selectedClass}"><input class="file-check shared-file-checkbox" type="checkbox" aria-label="选择 ${escapeHtml(entry.name)}" data-name="${escapeHtml(entry.name)}"${checked}><svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M13 2v7h7"/></svg><span class="name" title="${escapeHtml(entry.name)}">${indent}${escapeHtml(basename(entry.name))}</span><span class="file-time" title="${escapeHtml(fmtDate(entry.modified))}">${escapeHtml(fmtFileTime(entry.modified))}</span><span class="sz">${fmtSize(entry.size)}</span><button class="btn btn-ghost delete-file" data-name="${escapeHtml(entry.name)}">删除</button></div>`;
}

function basename(p) { const i = p.lastIndexOf('/'); return i === -1 ? p : p.slice(i + 1); }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// ---------- actions ----------
async function newPin() {
  const btn = $('newpin-btn');
  btn.disabled = true; btn.textContent = '生成中…';
  try {
    const { pin } = await api('/api/local/new-pin', { method: 'POST' });
    $('pin-value').textContent = pin;
    $('pin-result').classList.add('show');
    toast(`新 PIN: ${pin}`, 'ok');
  } catch (e) { toast(e.message, 'err'); }
  finally { btn.disabled = false; btn.textContent = '生成新 PIN'; }
}

async function revokeOne(id) {
  if (!confirm(`撤销设备 ${id}？\n该设备将立即无法访问，需重新走 PIN 配对。`)) return;
  try {
    await api('/api/local/revoke', { method: 'POST', body: { deviceId: id } });
    toast(`已撤销 ${id}`, 'ok');
    await loadDevices();
    await loadStatus();
  } catch (e) { toast(e.message, 'err'); }
}

async function revokeAll() {
  if (!confirm('撤销全部已配对设备？\n所有设备将立即下线，需逐一重新配对。')) return;
  try {
    const r = await api('/api/local/revoke-all', { method: 'POST' });
    toast(`已撤销 ${r.revoked} 个设备`, 'ok');
    await loadDevices();
    await loadStatus();
  } catch (e) { toast(e.message, 'err'); }
}

async function uploadFiles() {
  const input = $('upload-input');
  const files = Array.from(input.files || []);
  if (!files.length) return;

  const uploadBtn = $('upload-btn');
  const clearBtn = $('clear-files-btn');
  uploadBtn.disabled = true;
  clearBtn.disabled = true;
  try {
    for (let i = 0; i < files.length; i += 1) {
      const file = files[i];
      const relPath = normalizeUploadName(file);
      setUploadProgress(`上传 ${i + 1}/${files.length}: ${relPath}`);
      await uploadOneFile(file, relPath, (loaded, total) => {
        setUploadProgress(`上传 ${i + 1}/${files.length}: ${relPath} ${Math.round((loaded / total) * 100)}%`);
      });
    }
    toast(`已上传 ${files.length} 个文件`, 'ok');
    input.value = '';
    refreshAll();
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    uploadBtn.disabled = false;
    clearBtn.disabled = false;
    setUploadProgress('');
  }
}

async function deleteSharedFile(name) {
  if (!confirm(`删除共享文件 ${name}？`)) return;
  try {
    await deleteSharedFileApi(name);
    selectedSharedFiles.delete(name);
    toast(`已删除 ${basename(name)}`, 'ok');
    await loadFiles();
    await loadStatus();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deleteSelectedFiles() {
  pruneFileSelection();
  const names = Array.from(selectedSharedFiles);
  if (!names.length) {
    renderFiles();
    return;
  }
  if (!confirm(`删除选中的 ${names.length} 个共享文件？`)) return;

  const button = $('delete-selected-files-btn');
  const previousText = button.textContent;
  button.disabled = true;
  button.textContent = '删除中…';
  let deleted = 0;
  const failed = [];
  try {
    for (const name of names) {
      try {
        await deleteSharedFileApi(name);
        selectedSharedFiles.delete(name);
        deleted += 1;
      } catch (e) {
        failed.push({ name, error: e.message });
      }
    }
    await loadFiles();
    await loadStatus();
    if (failed.length) {
      console.warn('cloudsyncd batch delete failures', failed);
      toast(`已删除 ${deleted} 个，失败 ${failed.length} 个`, 'err');
    } else {
      toast(`已删除 ${deleted} 个文件`, 'ok');
    }
  } finally {
    button.textContent = previousText;
    updateFileSelectionUi();
  }
}

async function clearSharedFiles() {
  if (!confirm('清空 shared/ 下的全部共享文件？')) return;
  try {
    await api('/api/local/files/clear', { method: 'POST' });
    selectedSharedFiles.clear();
    toast('shared/ 已清空', 'ok');
    refreshAll();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function rotateKey() {
  if (!confirm('轮换主密钥？\n将生成新主密钥并清空全部已配对设备，所有设备需重新走 PIN 配对。')) return;
  try {
    const r = await api('/api/local/rotate-key', { method: 'POST' });
    toast(`已轮换主密钥，${r.revoked} 个设备需重新配对`, 'ok');
    refreshAll();
  } catch (e) { toast(e.message, 'err'); }
}

async function rotateToken() {
  if (!authRequired) {
    toast('本地管理端未启用 Token 认证', 'info');
    return;
  }
  if (!confirm('轮换管理 Token？')) return;
  try {
    const r = await api('/api/local/rotate-token', { method: 'POST' });
    setToken(r.adminToken); // keep the current session alive with the new token
    toast('管理 Token 已轮换', 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

function refreshAll() { loadStatus(); loadDevices(); loadFiles(); }

// ---------- init ----------
document.addEventListener('DOMContentLoaded', async () => {
  $('login-btn').addEventListener('click', tryLogin);
  $('token-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryLogin(); });
  $('logout-btn').addEventListener('click', () => logout(false));
  $('refresh-btn').addEventListener('click', () => {
    const btn = $('refresh-btn');
    btn.classList.add('spinning');
    setTimeout(() => btn.classList.remove('spinning'), 600);
    refreshAll();
  });
  $('newpin-btn').addEventListener('click', newPin);
  $('revoke-all-btn').addEventListener('click', revokeAll);
  $('upload-btn').addEventListener('click', () => $('upload-input').click());
  $('upload-input').addEventListener('change', uploadFiles);
  $('file-search').addEventListener('input', (e) => { fileSearchQuery = e.target.value; renderFiles(); });
  $('select-visible-files-btn').addEventListener('click', selectVisibleFiles);
  $('clear-file-selection-btn').addEventListener('click', clearFileSelection);
  $('delete-selected-files-btn').addEventListener('click', deleteSelectedFiles);
  $('clear-files-btn').addEventListener('click', clearSharedFiles);
  $('rotate-key-btn').addEventListener('click', rotateKey);
  $('rotate-token-btn').addEventListener('click', rotateToken);

  await loadAuthMode();
  applyAuthModeUi();
  if (!authRequired || getToken()) { showDash(); } else { showLogin(); }
});
