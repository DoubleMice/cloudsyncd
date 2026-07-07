const crypto = require('crypto');
const { Transform } = require('stream');

const CHUNKED_ENCRYPTION_MODE = 'chunked-v2';
const CHUNKED_TAG_LENGTH = 16;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const FRAME_HEADER_BYTES = 4;
const FINAL_FRAME_MARKER = 0;
const FINAL_MANIFEST_MAX_BYTES = 64 * 1024;

function chunkIv(prefix, counter) {
  const prefixBuf = Buffer.from(prefix);
  if (prefixBuf.length !== 8) throw new Error('Chunk IV prefix must be 8 bytes');
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > 0xffffffff) {
    throw new Error('Chunk counter out of range');
  }
  const iv = Buffer.alloc(12);
  prefixBuf.copy(iv, 0);
  iv.writeUInt32BE(counter, 8);
  return iv;
}

function validateFileSize(fileSize) {
  if (!Number.isSafeInteger(fileSize) || fileSize < 0) {
    throw new Error('Invalid file size');
  }
}

function validateChunkSize(chunkSize) {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new Error('Invalid chunk size');
  }
}

function normalizeContext(options = {}) {
  const chunkSize = options.chunkSize || DEFAULT_CHUNK_SIZE;
  const relPath = options.relPath || '';
  validateChunkSize(chunkSize);
  validateFileSize(options.fileSize);
  if (typeof relPath !== 'string') throw new Error('Invalid relative path');
  return {
    fileSize: options.fileSize,
    chunkSize,
    relPath,
  };
}

function chunkCountForSize(fileSize, chunkSize = DEFAULT_CHUNK_SIZE) {
  validateFileSize(fileSize);
  validateChunkSize(chunkSize);
  return fileSize === 0 ? 0 : Math.ceil(fileSize / chunkSize);
}

function finalManifest(context, chunkCount) {
  return {
    mode: CHUNKED_ENCRYPTION_MODE,
    fileSize: context.fileSize,
    chunkSize: context.chunkSize,
    chunkCount,
    relPath: context.relPath,
  };
}

function finalManifestBytes(context, chunkCount) {
  return Buffer.from(JSON.stringify(finalManifest(context, chunkCount)), 'utf8');
}

function frameAad(kind, counter, context) {
  return Buffer.from([
    'cloudsyncd',
    CHUNKED_ENCRYPTION_MODE,
    kind,
    String(counter),
    String(context.fileSize),
    String(context.chunkSize),
    context.relPath,
  ].join('\n'), 'utf8');
}

function encryptChunk(key, iv, chunk, aad) {
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  return Buffer.concat([cipher.update(chunk), cipher.final(), cipher.getAuthTag()]);
}

function decryptChunk(key, iv, encrypted, tagLength = CHUNKED_TAG_LENGTH, aad) {
  if (encrypted.length < tagLength) throw new Error('Encrypted chunk is truncated');
  const ciphertext = encrypted.subarray(0, encrypted.length - tagLength);
  const tag = encrypted.subarray(encrypted.length - tagLength);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), iv);
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function frameEncryptedChunk(encrypted) {
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  header.writeUInt32BE(encrypted.length, 0);
  return Buffer.concat([header, encrypted]);
}

function frameFinalManifest(encrypted) {
  const marker = Buffer.alloc(FRAME_HEADER_BYTES);
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  marker.writeUInt32BE(FINAL_FRAME_MARKER, 0);
  header.writeUInt32BE(encrypted.length, 0);
  return Buffer.concat([marker, header, encrypted]);
}

function createChunkedEncryptStream(key, options = {}) {
  const ivPrefix = options.ivPrefix ? Buffer.from(options.ivPrefix) : crypto.randomBytes(8);
  const tagLength = options.tagLength || CHUNKED_TAG_LENGTH;
  const context = normalizeContext(options);
  const chunkSize = context.chunkSize;
  let counter = 0;
  let bytesWritten = 0;
  let pending = Buffer.alloc(0);

  if (tagLength !== CHUNKED_TAG_LENGTH) {
    throw new Error(`Unsupported AES-GCM tag length: ${tagLength}`);
  }

  function encryptPlainChunk(chunk) {
    const encrypted = encryptChunk(key, chunkIv(ivPrefix, counter), chunk, frameAad('data', counter, context));
    counter += 1;
    bytesWritten += chunk.length;
    return frameEncryptedChunk(encrypted);
  }

  const stream = new Transform({
    transform(chunk, encoding, callback) {
      try {
        if (!chunk.length) return callback();
        pending = pending.length ? Buffer.concat([pending, chunk]) : Buffer.from(chunk);
        while (pending.length >= chunkSize) {
          this.push(encryptPlainChunk(pending.subarray(0, chunkSize)));
          pending = pending.subarray(chunkSize);
        }
        callback();
      } catch (err) {
        callback(err);
      }
    },
    flush(callback) {
      try {
        if (pending.length) {
          this.push(encryptPlainChunk(pending));
          pending = Buffer.alloc(0);
        }
        if (bytesWritten !== context.fileSize) {
          throw new Error(`Chunked stream size changed: expected ${context.fileSize}, got ${bytesWritten}`);
        }
        const manifestBytes = finalManifestBytes(context, counter);
        const encryptedManifest = encryptChunk(
          key,
          chunkIv(ivPrefix, counter),
          manifestBytes,
          frameAad('final', counter, context)
        );
        this.push(frameFinalManifest(encryptedManifest));
        callback();
      } catch (err) {
        callback(err);
      }
    },
  });

  return { stream, ivPrefix, tagLength };
}

function encryptedChunkedContentLength(plainSize, chunkSize = DEFAULT_CHUNK_SIZE, options = {}) {
  const context = normalizeContext({ ...options, fileSize: plainSize, chunkSize });
  const chunks = chunkCountForSize(plainSize, chunkSize);
  const manifestLength = finalManifestBytes(context, chunks).length;
  return (
    plainSize
    + chunks * (FRAME_HEADER_BYTES + CHUNKED_TAG_LENGTH)
    + FRAME_HEADER_BYTES
    + FRAME_HEADER_BYTES
    + manifestLength
    + CHUNKED_TAG_LENGTH
  );
}

function validateManifest(manifest, context, chunkCount) {
  if (!manifest || typeof manifest !== 'object') throw new Error('Invalid final manifest');
  if (manifest.mode !== CHUNKED_ENCRYPTION_MODE) throw new Error('Invalid final manifest mode');
  if (manifest.fileSize !== context.fileSize) throw new Error('Invalid final manifest file size');
  if (manifest.chunkSize !== context.chunkSize) throw new Error('Invalid final manifest chunk size');
  if (manifest.chunkCount !== chunkCount) throw new Error('Invalid final manifest chunk count');
  if (manifest.relPath !== context.relPath) throw new Error('Invalid final manifest path');
}

function decryptChunkedFrames(buffer, key, ivPrefix, options = {}) {
  const tagLength = options.tagLength || CHUNKED_TAG_LENGTH;
  const context = normalizeContext(options);
  const maxChunkSize = context.chunkSize;
  const frames = [];
  let offset = 0;
  let counter = 0;
  let finalSeen = false;

  while (offset < buffer.length) {
    if (buffer.length - offset < FRAME_HEADER_BYTES) {
      throw new Error('Encrypted chunk frame header is truncated');
    }
    const encryptedLength = buffer.readUInt32BE(offset);
    offset += FRAME_HEADER_BYTES;

    if (encryptedLength === FINAL_FRAME_MARKER) {
      if (finalSeen) throw new Error('Duplicate final manifest frame');
      finalSeen = true;
      if (buffer.length - offset < FRAME_HEADER_BYTES) {
        throw new Error('Final manifest frame header is truncated');
      }
      const manifestLength = buffer.readUInt32BE(offset);
      offset += FRAME_HEADER_BYTES;
      if (manifestLength < tagLength || manifestLength > FINAL_MANIFEST_MAX_BYTES) {
        throw new Error('Invalid final manifest length');
      }
      if (buffer.length - offset < manifestLength) {
        throw new Error('Final manifest frame body is truncated');
      }
      const encrypted = buffer.subarray(offset, offset + manifestLength);
      offset += manifestLength;
      if (offset !== buffer.length) {
        throw new Error('Unexpected data after final manifest');
      }
      const manifestBytes = decryptChunk(
        key,
        chunkIv(ivPrefix, counter),
        encrypted,
        tagLength,
        frameAad('final', counter, context)
      );
      const manifest = JSON.parse(manifestBytes.toString('utf8'));
      validateManifest(manifest, context, counter);
      return { plaintext: Buffer.concat(frames), manifest };
    }

    if (encryptedLength < tagLength || encryptedLength > maxChunkSize + tagLength) {
      throw new Error('Invalid encrypted chunk length');
    }
    if (buffer.length - offset < encryptedLength) {
      throw new Error('Encrypted chunk frame body is truncated');
    }
    const encrypted = buffer.subarray(offset, offset + encryptedLength);
    offset += encryptedLength;
    frames.push(decryptChunk(
      key,
      chunkIv(ivPrefix, counter),
      encrypted,
      tagLength,
      frameAad('data', counter, context)
    ));
    counter += 1;
  }

  throw new Error('Missing final manifest frame');
}

module.exports = {
  CHUNKED_ENCRYPTION_MODE,
  CHUNKED_TAG_LENGTH,
  DEFAULT_CHUNK_SIZE,
  FRAME_HEADER_BYTES,
  FINAL_FRAME_MARKER,
  chunkIv,
  createChunkedEncryptStream,
  decryptChunkedFrames,
  encryptedChunkedContentLength,
  frameAad,
};
