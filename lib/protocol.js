const crypto = require('crypto');

function toBuffer(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

function hkdf(ikm, salt, info, length = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', toBuffer(ikm), salt, info, length));
}

function hmac(key, data) {
  return crypto.createHmac('sha256', toBuffer(key)).update(data).digest('hex');
}

function sha256Hex(data = Buffer.alloc(0)) {
  return crypto.createHash('sha256').update(toBuffer(data)).digest('hex');
}

function decryptBytes(key, iv, ciphertext, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', toBuffer(key), toBuffer(iv));
  decipher.setAuthTag(toBuffer(tag));
  return Buffer.concat([decipher.update(toBuffer(ciphertext)), decipher.final()]);
}

function decryptEnvelope(key, encrypted) {
  if (!encrypted || !encrypted.iv || !encrypted.ciphertext || !encrypted.tag) {
    throw new Error('Invalid encrypted payload');
  }
  return decryptBytes(
    key,
    Buffer.from(encrypted.iv, 'hex'),
    Buffer.from(encrypted.ciphertext, 'hex'),
    Buffer.from(encrypted.tag, 'hex')
  );
}

function encryptEnvelope(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', toBuffer(key), iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(plaintext)), cipher.final()]);
  return {
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
  };
}

function deriveRequestAuthKey(masterKey, deviceId) {
  return hkdf(masterKey, 'syncd-request-auth', `device:${deviceId}`, 32);
}

function buildRequestSignatureMessage(method, signedPath, timestamp, nonce, bodyHash) {
  return [method.toUpperCase(), signedPath, timestamp, nonce, bodyHash].join('\n');
}

function signRequest({ masterKey, deviceId, method = 'GET', signedPath, body = Buffer.alloc(0), nonce, timestamp }) {
  const ts = timestamp || Date.now().toString();
  const requestNonce = nonce || crypto.randomUUID();
  const bodyHash = sha256Hex(body);
  const authKey = deriveRequestAuthKey(masterKey, deviceId);
  const signature = hmac(
    authKey,
    buildRequestSignatureMessage(method, signedPath, ts, requestNonce, bodyHash)
  );

  return {
    'X-Device-Id': deviceId,
    'X-Auth-Timestamp': ts,
    'X-Auth-Nonce': requestNonce,
    'X-Auth-Signature': signature,
  };
}

function createClientPairKey() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    ecdh,
    publicKeyHex: ecdh.getPublicKey('hex'),
  };
}

function derivePairingMaterial(ecdh, serverPublicKeyHex, pin) {
  const sharedSecret = ecdh.computeSecret(Buffer.from(serverPublicKeyHex, 'hex'));
  const authKey = hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32);
  const proof = hmac(authKey, pin);
  const expectedServerProof = hmac(authKey, 'server-confirmed');
  const transportKey = hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32);
  return { proof, expectedServerProof, transportKey };
}

function encodeRemotePath(remotePath) {
  const cleaned = String(remotePath || '').replace(/^\/+/, '');
  if (!cleaned) throw new Error('Missing remote path');
  return cleaned.split('/').map(encodeURIComponent).join('/');
}

module.exports = {
  hkdf,
  hmac,
  sha256Hex,
  decryptBytes,
  decryptEnvelope,
  encryptEnvelope,
  deriveRequestAuthKey,
  buildRequestSignatureMessage,
  signRequest,
  createClientPairKey,
  derivePairingMaterial,
  encodeRemotePath,
};
