'use strict'

const crypto = require('crypto')
const secp = require('@noble/secp256k1')

secp.utils.sha256Sync = function (...messages) {
  const hash = crypto.createHash('sha256')
  messages.forEach(message => hash.update(Buffer.from(message)))
  return hash.digest()
}

secp.utils.hmacSha256Sync = function (key, ...messages) {
  const hmac = crypto.createHmac('sha256', Buffer.from(key))
  messages.forEach(message => hmac.update(Buffer.from(message)))
  return hmac.digest()
}

function bytesToHex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function hexToBytes (hex) {
  return Buffer.from(hex, 'hex')
}

function normalizePrivateKey (privateKey) {
  if (Buffer.isBuffer(privateKey) || privateKey instanceof Uint8Array) {
    privateKey = bytesToHex(privateKey)
  }

  if (typeof privateKey !== 'string') {
    throw new Error('Nostr private key must be a hex string or bytes')
  }

  const normalized = privateKey.trim().toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error('Nostr private key must be 32 bytes hex')
  }

  if (!secp.utils.isValidPrivateKey(hexToBytes(normalized))) {
    throw new Error('Nostr private key is outside the secp256k1 range')
  }

  return normalized
}

function generatePrivateKey () {
  return bytesToHex(secp.utils.randomPrivateKey())
}

function derivePrivateKey (secret) {
  if (typeof secret === 'string') {
    secret = Buffer.from(secret, 'utf8')
  } else if (secret instanceof Uint8Array) {
    secret = Buffer.from(secret)
  }

  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new Error('Secret must be non-empty bytes or string')
  }

  for (let counter = 0; counter < 256; counter++) {
    const candidate = crypto
      .createHmac('sha256', 'codimd-nostr-private-key-v1')
      .update(secret)
      .update(Buffer.from([counter]))
      .digest()

    if (secp.utils.isValidPrivateKey(candidate)) {
      return bytesToHex(candidate)
    }
  }

  throw new Error('Failed to derive a valid secp256k1 private key')
}

function getPublicKey (privateKey) {
  return bytesToHex(secp.schnorr.getPublicKey(hexToBytes(normalizePrivateKey(privateKey))))
}

module.exports = {
  bytesToHex,
  derivePrivateKey,
  generatePrivateKey,
  getPublicKey,
  hexToBytes,
  normalizePrivateKey
}
