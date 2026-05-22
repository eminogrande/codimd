'use strict'

const crypto = require('crypto')
const zlib = require('zlib')
const base64url = require('base64url')

const { getPublicKey, normalizePrivateKey } = require('./keys')
const { signEvent, unixNow } = require('./events')

const VAULT_KIND = 30078
const ARTICLE_KIND = 30023
const DEFAULT_VAULT_IDENTIFIER = 'codimd-vault'
const VAULT_VERSION = 1

function encode (buffer) {
  return base64url.encode(buffer)
}

function decode (value) {
  return base64url.toBuffer(value)
}

function normalizeDate (value) {
  if (!value) return null
  return new Date(value).toISOString()
}

function plainRecord (record) {
  if (record && typeof record.get === 'function') {
    return record.get({ plain: true })
  }
  return record || {}
}

function hkdfSha256 (ikm, salt, info, length) {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest()
  let block = Buffer.alloc(0)
  let output = Buffer.alloc(0)
  let counter = 1

  while (output.length < length) {
    block = crypto
      .createHmac('sha256', prk)
      .update(Buffer.concat([block, info, Buffer.from([counter])]))
      .digest()
    output = Buffer.concat([output, block])
    counter++
  }

  return output.slice(0, length)
}

function deriveVaultKey (privateKey) {
  const normalized = normalizePrivateKey(privateKey)
  const salt = crypto.createHash('sha256').update('codimd-nostr-vault-salt-v1').digest()
  return hkdfSha256(
    Buffer.from(normalized, 'hex'),
    salt,
    Buffer.from('codimd encrypted nostr vault v1'),
    32
  )
}

function encryptPayload (payload, privateKey) {
  const plaintext = zlib.gzipSync(Buffer.from(JSON.stringify(payload), 'utf8'))
  const nonce = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveVaultKey(privateKey), nonce)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])

  return {
    version: VAULT_VERSION,
    alg: 'aes-256-gcm',
    kdf: 'hkdf-sha256',
    compression: 'gzip',
    nonce: encode(nonce),
    tag: encode(cipher.getAuthTag()),
    ciphertext: encode(ciphertext)
  }
}

function decryptPayload (box, privateKey) {
  if (!box || box.version !== VAULT_VERSION || box.alg !== 'aes-256-gcm') {
    throw new Error('Unsupported vault payload')
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    deriveVaultKey(privateKey),
    decode(box.nonce)
  )
  decipher.setAuthTag(decode(box.tag))
  const zipped = Buffer.concat([
    decipher.update(decode(box.ciphertext)),
    decipher.final()
  ])

  return JSON.parse(zlib.gunzipSync(zipped).toString('utf8'))
}

function createVault (user, notes, options) {
  user = plainRecord(user)
  options = options || {}

  return {
    version: VAULT_VERSION,
    app: 'codimd',
    exportedAt: options.exportedAt || new Date().toISOString(),
    user: {
      id: user.id,
      profileid: user.profileid || null,
      profile: user.profile || null,
      email: user.email || null,
      history: user.history || null
    },
    notes: notes.map(note => {
      note = plainRecord(note)
      return {
        id: note.id,
        shortid: note.shortid,
        alias: note.alias || null,
        permission: note.permission || null,
        title: note.title || '',
        content: note.content || '',
        authorship: note.authorship || [],
        createdAt: normalizeDate(note.createdAt),
        updatedAt: normalizeDate(note.updatedAt),
        lastchangeAt: normalizeDate(note.lastchangeAt),
        savedAt: normalizeDate(note.savedAt)
      }
    })
  }
}

function buildVaultEvent (vault, privateKey, options) {
  options = options || {}
  const identifier = options.identifier || DEFAULT_VAULT_IDENTIFIER
  const box = encryptPayload(vault, privateKey)

  return signEvent({
    kind: VAULT_KIND,
    created_at: options.createdAt || unixNow(),
    tags: [
      ['d', identifier],
      ['application', 'codimd'],
      ['format', 'codimd-vault-v1'],
      ['encrypted', 'aes-256-gcm'],
      ['compression', 'gzip']
    ],
    content: JSON.stringify(box)
  }, privateKey)
}

function openVaultEvent (event, privateKey) {
  if (!event || event.kind !== VAULT_KIND) {
    throw new Error('Not a CodiMD vault event')
  }

  return decryptPayload(JSON.parse(event.content), privateKey)
}

function firstHeading (content) {
  const match = String(content || '').match(/^#\s+(.+)$/m)
  return match ? match[1].trim() : null
}

function description (content) {
  return String(content || '')
    .replace(/^---[\s\S]*?\n---\n/, '')
    .replace(/[#*_`>\-[\]()]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240)
}

function hashtags (content) {
  const found = String(content || '').match(/#[A-Za-z0-9_-]+/g) || []
  return Array.from(new Set(found.map(tag => tag.slice(1).toLowerCase())))
}

function buildArticleEvent (note, privateKey, options) {
  note = plainRecord(note)
  options = options || {}

  const content = options.content || note.content || ''
  const identifier = String(options.identifier || note.alias || note.shortid || note.id)
  const title = options.title || note.title || firstHeading(content) || identifier
  const publishedAt = options.publishedAt || unixNow()
  const tags = [
    ['d', identifier],
    ['title', title],
    ['published_at', String(publishedAt)],
    ['client', 'codimd-nostr']
  ]
  const summary = options.summary || description(content)
  if (summary) tags.push(['summary', summary])
  hashtags(content).forEach(tag => tags.push(['t', tag]))

  return signEvent({
    kind: ARTICLE_KIND,
    created_at: options.createdAt || publishedAt,
    tags: tags,
    content: content
  }, privateKey)
}

module.exports = {
  ARTICLE_KIND,
  DEFAULT_VAULT_IDENTIFIER,
  VAULT_KIND,
  buildArticleEvent,
  buildVaultEvent,
  createVault,
  decryptPayload,
  encryptPayload,
  getPublicKey,
  openVaultEvent
}
