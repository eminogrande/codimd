/* eslint-env browser */
/* global CompressionStream, DecompressionStream */

export const VAULT_KIND = 30078
export const ARTICLE_KIND = 30023
export const VAULT_IDENTIFIER = 'nostr-hugo-vault'
export const PRF_SALT_LABEL = 'codimd-nostr-passkey-prf-v1'
export const PRIVATE_KEY_LABEL = 'codimd-nostr-private-key-v1'
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net'
]

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

export function utf8 (value) {
  return textEncoder.encode(String(value))
}

export function fromUtf8 (bytes) {
  return textDecoder.decode(bytes)
}

export function bytesToHex (bytes) {
  return Array.from(new Uint8Array(bytes))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
}

export function hexToBytes (hex) {
  const normalized = String(hex || '').trim().toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('Invalid hex')
  }
  const bytes = new Uint8Array(normalized.length / 2)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = parseInt(normalized.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

export function base64URLToBytes (value) {
  value = String(value || '').replace(/-/g, '+').replace(/_/g, '/')
  while (value.length % 4) value += '='
  return Uint8Array.from(atob(value), character => character.charCodeAt(0))
}

export function bytesToBase64URL (bytes) {
  let binary = ''
  new Uint8Array(bytes).forEach(byte => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function concatBytes (...arrays) {
  const total = arrays.reduce((sum, array) => sum + array.length, 0)
  const output = new Uint8Array(total)
  let offset = 0
  arrays.forEach(array => {
    output.set(array, offset)
    offset += array.length
  })
  return output
}

export async function sha256Bytes (bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

export async function sha256Hex (bytes) {
  return bytesToHex(await sha256Bytes(bytes))
}

export async function hmacSha256Bytes (keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, messageBytes))
}

export async function hkdfSha256 (ikm, salt, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt,
    info
  }, key, length * 8)
  return new Uint8Array(bits)
}

export async function prfSalt () {
  return sha256Bytes(utf8(PRF_SALT_LABEL))
}

export async function deriveVaultKey (privateKeyHex) {
  const salt = await sha256Bytes(utf8('codimd-nostr-vault-salt-v1'))
  return hkdfSha256(
    hexToBytes(privateKeyHex),
    salt,
    utf8('codimd encrypted nostr vault v1'),
    32
  )
}

async function compressPayload (bytes) {
  if (typeof CompressionStream === 'undefined') {
    return { bytes, compression: 'none' }
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'))
  return {
    bytes: new Uint8Array(await new Response(stream).arrayBuffer()),
    compression: 'gzip'
  }
}

async function decompressPayload (bytes, compression) {
  if (!compression || compression === 'none') return bytes
  if (compression !== 'gzip') throw new Error('Unsupported vault compression')
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot decompress gzip vaults')
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

export async function encryptVaultPayload (payload, privateKeyHex) {
  const encoded = utf8(JSON.stringify(payload))
  const compressed = await compressPayload(encoded)
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const rawKey = await deriveVaultKey(privateKeyHex)
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
  const sealed = new Uint8Array(await crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: nonce,
    tagLength: 128
  }, key, compressed.bytes))
  const tagSize = 16

  return {
    version: 1,
    alg: 'aes-256-gcm',
    kdf: 'hkdf-sha256',
    compression: compressed.compression,
    nonce: bytesToBase64URL(nonce),
    tag: bytesToBase64URL(sealed.slice(sealed.length - tagSize)),
    ciphertext: bytesToBase64URL(sealed.slice(0, sealed.length - tagSize))
  }
}

export async function decryptVaultPayload (box, privateKeyHex) {
  if (!box || box.version !== 1 || box.alg !== 'aes-256-gcm') {
    throw new Error('Unsupported vault payload')
  }
  const rawKey = await deriveVaultKey(privateKeyHex)
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
  const sealed = concatBytes(base64URLToBytes(box.ciphertext), base64URLToBytes(box.tag))
  const compressed = new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: base64URLToBytes(box.nonce),
    tagLength: 128
  }, key, sealed))
  const plaintext = await decompressPayload(compressed, box.compression)
  return JSON.parse(fromUtf8(plaintext))
}

export function serializeEvent (event) {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags || [],
    event.content || ''
  ])
}

export async function hashEvent (event) {
  return sha256Hex(utf8(serializeEvent(event)))
}

export function slugify (value) {
  const slug = String(value || '')
    .toLowerCase()
    .replace(/['"]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug || 'note-' + Date.now().toString(36)
}

export function firstHeading (content) {
  const match = String(content || '').match(/^#\s+(.+)$/m)
  return match ? match[1].trim() : ''
}

export function plainSummary (content, length = 220) {
  return String(content || '')
    .replace(/^---[\s\S]*?\n---\n/, '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/[#*_`>\-[\]()]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, length)
}

export function hashtags (content) {
  const found = String(content || '').match(/#[A-Za-z0-9_-]+/g) || []
  return Array.from(new Set(found.map(tag => tag.slice(1).toLowerCase())))
}

export function normalizeNote (note) {
  const now = new Date().toISOString()
  const title = String(note.title || firstHeading(note.content) || 'Untitled')
  return {
    id: note.id || crypto.randomUUID(),
    slug: note.slug || slugify(title),
    title,
    content: String(note.content || ''),
    visibility: note.visibility === 'public' ? 'public' : 'private',
    createdAt: note.createdAt || now,
    updatedAt: now,
    publishedAt: note.publishedAt || null
  }
}

export function createVault (pubkey, notes) {
  return {
    version: 1,
    app: 'nostr-hugo',
    exportedAt: new Date().toISOString(),
    pubkey,
    notes: notes.map(normalizeNote)
  }
}

export function vaultEventTemplate (box) {
  return {
    kind: VAULT_KIND,
    tags: [
      ['d', VAULT_IDENTIFIER],
      ['application', 'nostr-hugo'],
      ['format', 'nostr-hugo-vault-v1'],
      ['encrypted', 'aes-256-gcm']
    ],
    content: JSON.stringify(box)
  }
}

export function articleEventTemplate (note) {
  note = normalizeNote(note)
  const tags = [
    ['d', note.slug],
    ['title', note.title],
    ['published_at', String(Math.floor(new Date(note.publishedAt || note.updatedAt).getTime() / 1000))],
    ['client', 'nostr-hugo-cloudflare']
  ]
  const summary = plainSummary(note.content)
  if (summary) tags.push(['summary', summary])
  hashtags(note.content).forEach(tag => tags.push(['t', tag]))

  return {
    kind: ARTICLE_KIND,
    tags,
    content: note.content
  }
}

export function tagValue (event, name) {
  const tag = (event.tags || []).find(candidate => candidate[0] === name)
  return tag ? tag[1] : ''
}

export function publicPostFromEvent (event) {
  const title = tagValue(event, 'title') || firstHeading(event.content) || tagValue(event, 'd') || 'Untitled'
  return {
    id: event.id,
    slug: tagValue(event, 'd') || event.id,
    title,
    summary: tagValue(event, 'summary') || plainSummary(event.content),
    content: event.content || '',
    createdAt: new Date((event.created_at || 0) * 1000).toISOString(),
    event
  }
}
