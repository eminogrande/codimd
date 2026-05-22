'use strict'

const crypto = require('crypto')
const secp = require('@noble/secp256k1')

const {
  bytesToHex,
  getPublicKey,
  hexToBytes,
  normalizePrivateKey
} = require('./keys')

function unixNow () {
  return Math.floor(Date.now() / 1000)
}

function normalizeEventTemplate (template, privateKey) {
  return {
    pubkey: template.pubkey || getPublicKey(privateKey),
    created_at: template.created_at || unixNow(),
    kind: template.kind,
    tags: template.tags || [],
    content: template.content || ''
  }
}

function serializeEvent (event) {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ])
}

function hashEvent (event) {
  return crypto.createHash('sha256').update(serializeEvent(event)).digest('hex')
}

function signEvent (template, privateKey) {
  privateKey = normalizePrivateKey(privateKey)
  const event = normalizeEventTemplate(template, privateKey)
  event.id = hashEvent(event)
  event.sig = bytesToHex(secp.schnorr.signSync(hexToBytes(event.id), hexToBytes(privateKey)))
  return event
}

function verifyEvent (event) {
  if (!event || event.id !== hashEvent(event)) {
    return false
  }

  return secp.schnorr.verifySync(
    hexToBytes(event.sig),
    hexToBytes(event.id),
    hexToBytes(event.pubkey)
  )
}

module.exports = {
  hashEvent,
  serializeEvent,
  signEvent,
  unixNow,
  verifyEvent
}
