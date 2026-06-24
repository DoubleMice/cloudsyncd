// cloudsyncd admin panel.
// Auth: the operator's admin token (from data/.admin-token) is stored in
// sessionStorage and sent as x-admin-token on every /api/local/* call.
// 403 from any call bounces back to the login screen.

const TOKEN_KEY = 'cloudsyncd-admin';
const $ = (id) => document.getElementById(id);
const loginScreen = () => $('login-screen');
const dashScreen = () => $('dash-screen');

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
  const headers = { 'x-admin-token': getToken() };
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch { data = { error: text }; } }
  if (res.status === 403) { logout(true); throw new Error('会话失效，请重新登录'); }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
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
  dashScreen().classList.remove('active');
  loginScreen().classList.add('active');
  $('token-input').value = '';
  if (!silent) { toast('已退出', 'info'); }
  $('token-input').focus();
}

// ---------- dashboard data ----------
let lastStatus = null;

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
    if (!entries.length) { body.innerHTML = '<div class="empty">shared/ 目录为空</div>'; return; }
    body.innerHTML = entries.map(renderFileRow).join('');
  } catch (e) { body.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`; }
}

function renderFileRow(entry) {
  const depth = entry.name.split('/').length - 1;
  const indent = depth ? `<span class="indent">${'·  '.repeat(depth)}</span>` : '';
  if (entry.type === 'dir') {
    return `<div class="file-row dir"><span class="indent">▸</span><span class="name">${indent}${escapeHtml(basename(entry.name))}/</span></div>`;
  }
  return `<div class="file-row"><svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M13 2v7h7"/></svg><span class="name">${indent}${escapeHtml(basename(entry.name))}</span><span class="sz">${fmtSize(entry.size)}</span></div>`;
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
    $('pin-empty').style.display = 'none';
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

async function rotateKey() {
  if (!confirm('轮换主密钥？\n将生成新主密钥并清空全部已配对设备，所有设备需重新走 PIN 配对。')) return;
  try {
    const r = await api('/api/local/rotate-key', { method: 'POST' });
    toast(`已轮换主密钥，${r.revoked} 个设备需重新配对`, 'ok');
    refreshAll();
  } catch (e) { toast(e.message, 'err'); }
}

async function rotateToken() {
  if (!confirm('轮换管理 Token？')) return;
  try {
    const r = await api('/api/local/rotate-token', { method: 'POST' });
    setToken(r.adminToken); // keep the current session alive with the new token
    toast('管理 Token 已轮换', 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

function refreshAll() { loadStatus(); loadDevices(); loadFiles(); }

// ---------- init ----------
document.addEventListener('DOMContentLoaded', () => {
  $('login-btn').addEventListener('click', tryLogin);
  $('token-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryLogin(); });
  $('logout-btn').addEventListener('click', () => logout(false));
  $('refresh-btn').addEventListener('click', refreshAll);
  $('newpin-btn').addEventListener('click', newPin);
  $('revoke-all-btn').addEventListener('click', revokeAll);
  $('rotate-key-btn').addEventListener('click', rotateKey);
  $('rotate-token-btn').addEventListener('click', rotateToken);

  if (getToken()) { showDash(); } else { showLogin(); }
});
