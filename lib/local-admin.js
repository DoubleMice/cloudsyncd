const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function adminHost() {
  return process.env.ADMIN_HOST || '127.0.0.1';
}

function adminPort() {
  return process.env.ADMIN_PORT || 21900;
}

function adminBaseUrl() {
  return `http://${adminHost()}:${adminPort()}`;
}

function readAdminTokenOptional() {
  const tokenFile = path.join(ROOT, 'data', '.admin-token');
  try {
    return fs.readFileSync(tokenFile, 'utf8').trim();
  } catch {
    return '';
  }
}

function normalizeBody(body, headers) {
  if (
    body
    && typeof body === 'object'
    && !Buffer.isBuffer(body)
    && !(body instanceof Uint8Array)
  ) {
    if (!headers['content-type']) headers['content-type'] = 'application/json';
    return JSON.stringify(body);
  }
  return body;
}

async function fetchAdminJson(route, options = {}) {
  const base = adminBaseUrl();
  const token = readAdminTokenOptional();
  const headers = { ...(options.headers || {}) };
  if (token) headers['x-admin-token'] = token;
  const body = normalizeBody(options.body, headers);

  let res;
  try {
    res = await fetch(`${base}${route}`, {
      ...options,
      headers,
      body,
    });
  } catch {
    throw new Error(`Cannot reach local admin API at ${base}. Is the server running?`);
  }

  const text = await res.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

module.exports = {
  adminBaseUrl,
  fetchAdminJson,
  readAdminTokenOptional,
};
