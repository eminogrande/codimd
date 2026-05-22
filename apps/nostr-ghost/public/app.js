/* eslint-env browser */

import * as secp from 'https://esm.sh/@noble/secp256k1@1.7.1'
import { sha256 as nobleSha256 } from 'https://esm.sh/@noble/hashes@1.3.3/sha256'
import { hmac } from 'https://esm.sh/@noble/hashes@1.3.3/hmac'

import {
  ARTICLE_KIND,
  DEFAULT_RELAYS,
  PRIVATE_KEY_LABEL,
  VAULT_IDENTIFIER,
  VAULT_KIND,
  articleEventTemplate,
  base64URLToBytes,
  bytesToBase64URL,
  bytesToHex,
  concatBytes,
  createVault,
  decryptVaultPayload,
  encryptVaultPayload,
  hashEvent,
  hexToBytes,
  hmacSha256Bytes,
  normalizeNote,
  prfSalt,
  publicPostFromEvent,
  tagValue,
  utf8,
  vaultEventTemplate
} from './core.js'

secp.utils.sha256Sync = function (...messages) {
  return nobleSha256(concatBytes(...messages.map(message => new Uint8Array(message))))
}
secp.utils.hmacSha256Sync = function (key, ...messages) {
  return hmac(nobleSha256, new Uint8Array(key), concatBytes(...messages.map(message => new Uint8Array(message))))
}

const credentialStorageKey = 'nostrGhost.credentialId'
const relayStorageKey = 'nostrGhost.relays'
const pubkeyStorageKey = 'nostrGhost.pubkey'

const state = {
  privateKey: null,
  pubkey: null,
  notes: [],
  posts: [],
  selectedId: null,
  relays: loadRelays(),
  blogPubkey: localStorage.getItem(pubkeyStorageKey) || ''
}

const dom = {
  signinButton: document.getElementById('signinButton'),
  identityLabel: document.getElementById('identityLabel'),
  relaysInput: document.getElementById('relaysInput'),
  restoreButton: document.getElementById('restoreButton'),
  backupButton: document.getElementById('backupButton'),
  newNoteButton: document.getElementById('newNoteButton'),
  saveButton: document.getElementById('saveButton'),
  publishButton: document.getElementById('publishButton'),
  titleInput: document.getElementById('titleInput'),
  contentInput: document.getElementById('contentInput'),
  visibilityInput: document.getElementById('visibilityInput'),
  noteList: document.getElementById('noteList'),
  postGrid: document.getElementById('postGrid'),
  postView: document.getElementById('postView'),
  blogView: document.getElementById('blogView'),
  studioView: document.getElementById('studioView'),
  blogHero: document.getElementById('blogHero'),
  postTitle: document.getElementById('postTitle'),
  postDate: document.getElementById('postDate'),
  postContent: document.getElementById('postContent'),
  pubkeyForm: document.getElementById('pubkeyForm'),
  pubkeyInput: document.getElementById('pubkeyInput'),
  refreshPublicButton: document.getElementById('refreshPublicButton'),
  toast: document.getElementById('toast')
}

function loadRelays () {
  const stored = localStorage.getItem(relayStorageKey)
  if (!stored) return DEFAULT_RELAYS.slice()
  return stored.split(/\s+/).map(relay => relay.trim()).filter(Boolean)
}

function saveRelays () {
  state.relays = dom.relaysInput.value.split(/\s+/).map(relay => relay.trim()).filter(Boolean)
  localStorage.setItem(relayStorageKey, state.relays.join('\n'))
}

function toast (message) {
  dom.toast.textContent = message
  dom.toast.classList.add('visible')
  clearTimeout(toast.timer)
  toast.timer = setTimeout(() => dom.toast.classList.remove('visible'), 3600)
}

function requireKey () {
  if (!state.privateKey || !state.pubkey) {
    throw new Error('Sign in with passkey first')
  }
}

async function derivePrivateKey (secret) {
  const key = utf8(PRIVATE_KEY_LABEL)
  for (let counter = 0; counter < 256; counter++) {
    const message = new Uint8Array(secret.length + 1)
    message.set(secret)
    message[secret.length] = counter
    const candidate = await hmacSha256Bytes(key, message)
    if (secp.utils.isValidPrivateKey(candidate)) return candidate
  }
  throw new Error('Failed to derive a valid Nostr private key')
}

async function createPasskeyCredential (challenge, salt) {
  const userId = crypto.getRandomValues(new Uint8Array(32))
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'Nostr Ghost' },
      user: {
        id: userId,
        name: 'nostr-ghost',
        displayName: 'Nostr Ghost'
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required'
      },
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: salt
          }
        }
      }
    }
  })
  localStorage.setItem(credentialStorageKey, bytesToBase64URL(credential.rawId))
}

async function getPasskeySecret () {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('This browser does not support passkeys')
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const salt = await prfSalt()
  let credentialId = localStorage.getItem(credentialStorageKey)
  if (!credentialId) {
    await createPasskeyCredential(challenge, salt)
    credentialId = localStorage.getItem(credentialStorageKey)
  }

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{
        type: 'public-key',
        id: base64URLToBytes(credentialId)
      }],
      userVerification: 'required',
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: salt
          }
        }
      }
    }
  })

  const extensions = assertion.getClientExtensionResults()
  if (!extensions.prf || !extensions.prf.results || !extensions.prf.results.first) {
    localStorage.removeItem(credentialStorageKey)
    throw new Error('Passkey PRF is unavailable for this credential')
  }
  return new Uint8Array(extensions.prf.results.first)
}

async function signIn () {
  const secret = await getPasskeySecret()
  const privateKey = await derivePrivateKey(secret)
  state.privateKey = bytesToHex(privateKey)
  state.pubkey = bytesToHex(secp.schnorr.getPublicKey(privateKey))
  state.blogPubkey = state.pubkey
  localStorage.setItem(pubkeyStorageKey, state.pubkey)
  dom.pubkeyInput.value = state.pubkey
  renderIdentity()
  await restoreVault({ silent: true })
  location.hash = '#/studio'
  toast('Passkey unlocked Nostr identity')
}

async function signEvent (template) {
  requireKey()
  const event = {
    pubkey: state.pubkey,
    created_at: template.created_at || Math.floor(Date.now() / 1000),
    kind: template.kind,
    tags: template.tags || [],
    content: template.content || ''
  }
  event.id = await hashEvent(event)
  event.sig = bytesToHex(secp.schnorr.signSync(hexToBytes(event.id), hexToBytes(state.privateKey)))
  return event
}

function verifyEvent (event) {
  try {
    return event.id && event.sig && event.pubkey &&
      secp.schnorr.verifySync(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey))
  } catch (err) {
    return false
  }
}

function queryRelay (relay, filter, timeout = 6000) {
  return new Promise(resolve => {
    const events = []
    const subscription = 'nostr-ghost-' + Math.random().toString(16).slice(2)
    let settled = false
    const ws = new WebSocket(relay)
    const timer = setTimeout(finish, timeout)

    function finish () {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        ws.close()
      } catch (err) {}
      resolve(events)
    }

    ws.addEventListener('open', () => {
      ws.send(JSON.stringify(['REQ', subscription, filter]))
    })
    ws.addEventListener('message', event => {
      let message
      try {
        message = JSON.parse(event.data)
      } catch (err) {
        return
      }
      if (message[0] === 'EVENT' && message[1] === subscription && verifyEvent(message[2])) {
        events.push(message[2])
      }
      if (message[0] === 'EOSE' && message[1] === subscription) finish()
    })
    ws.addEventListener('error', finish)
    ws.addEventListener('close', finish)
  })
}

function publishRelay (relay, event, timeout = 6000) {
  return new Promise(resolve => {
    let settled = false
    const ws = new WebSocket(relay)
    const timer = setTimeout(() => finish(false, 'timeout'), timeout)

    function finish (ok, message) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        ws.close()
      } catch (err) {}
      resolve({ relay, ok, message: message || '' })
    }

    ws.addEventListener('open', () => ws.send(JSON.stringify(['EVENT', event])))
    ws.addEventListener('message', eventMessage => {
      let message
      try {
        message = JSON.parse(eventMessage.data)
      } catch (err) {
        return
      }
      if (message[0] === 'OK' && message[1] === event.id) finish(!!message[2], message[3])
    })
    ws.addEventListener('error', err => finish(false, err.message))
    ws.addEventListener('close', () => finish(false, 'closed before OK'))
  })
}

async function publishToRelays (event) {
  saveRelays()
  const results = await Promise.all(state.relays.map(relay => publishRelay(relay, event)))
  const ok = results.filter(result => result.ok).length
  return { ok, total: results.length, results }
}

async function fetchLatestVault () {
  requireKey()
  saveRelays()
  const filter = {
    kinds: [VAULT_KIND],
    authors: [state.pubkey],
    '#d': [VAULT_IDENTIFIER],
    limit: 5
  }
  const batches = await Promise.all(state.relays.map(relay => queryRelay(relay, filter)))
  return batches.flat().sort((a, b) => b.created_at - a.created_at)[0] || null
}

async function backupVault () {
  requireKey()
  const vault = createVault(state.pubkey, state.notes)
  const box = await encryptVaultPayload(vault, state.privateKey)
  const event = await signEvent(vaultEventTemplate(box))
  const published = await publishToRelays(event)
  toast(`Encrypted backup published to ${published.ok}/${published.total} relays`)
  return event
}

async function restoreVault (options = {}) {
  requireKey()
  const event = await fetchLatestVault()
  if (!event) {
    if (!options.silent) toast('No encrypted vault found on these relays')
    renderNotes()
    return
  }
  const vault = await decryptVaultPayload(JSON.parse(event.content), state.privateKey)
  state.notes = Array.isArray(vault.notes) ? vault.notes.map(normalizeNote) : []
  state.selectedId = state.notes[0] ? state.notes[0].id : null
  renderNotes()
  renderEditor()
  if (!options.silent) toast(`Restored ${state.notes.length} encrypted notes`)
}

function currentNoteFromForm () {
  const existing = state.notes.find(note => note.id === state.selectedId) || {}
  return normalizeNote({
    ...existing,
    title: dom.titleInput.value,
    content: dom.contentInput.value,
    visibility: dom.visibilityInput.value,
    slug: existing.slug || undefined
  })
}

function upsertCurrentNote () {
  const note = currentNoteFromForm()
  const index = state.notes.findIndex(candidate => candidate.id === note.id)
  if (index === -1) {
    state.notes.unshift(note)
  } else {
    state.notes[index] = note
  }
  state.selectedId = note.id
  renderNotes()
  return note
}

async function saveEncrypted () {
  upsertCurrentNote()
  await backupVault()
}

async function publishCurrent () {
  const note = {
    ...upsertCurrentNote(),
    visibility: 'public',
    publishedAt: new Date().toISOString()
  }
  state.notes = state.notes.map(candidate => candidate.id === note.id ? note : candidate)
  dom.visibilityInput.value = 'public'
  const article = await signEvent(articleEventTemplate(note))
  const published = await publishToRelays(article)
  await backupVault()
  toast(`Public post published to ${published.ok}/${published.total} relays`)
}

async function fetchPublicPosts () {
  const pubkey = state.blogPubkey
  if (!/^[0-9a-f]{64}$/i.test(pubkey)) {
    dom.postGrid.innerHTML = '<p class="empty">Enter a public key or sign in to load a blog.</p>'
    return
  }
  saveRelays()
  const filter = {
    kinds: [ARTICLE_KIND],
    authors: [pubkey],
    limit: 50
  }
  const batches = await Promise.all(state.relays.map(relay => queryRelay(relay, filter)))
  const bySlug = new Map()
  batches.flat().forEach(event => {
    const slug = tagValue(event, 'd') || event.id
    const existing = bySlug.get(slug)
    if (!existing || event.created_at > existing.created_at) bySlug.set(slug, event)
  })
  state.posts = Array.from(bySlug.values())
    .sort((a, b) => b.created_at - a.created_at)
    .map(publicPostFromEvent)
  renderPosts()
}

function markdownToHtml (markdown) {
  const escaped = String(markdown || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
  const blocks = escaped.split(/\n{2,}/)
  return blocks.map(block => {
    if (/^#\s+/.test(block)) return '<h1>' + block.replace(/^#\s+/, '') + '</h1>'
    if (/^##\s+/.test(block)) return '<h2>' + block.replace(/^##\s+/, '') + '</h2>'
    if (/^###\s+/.test(block)) return '<h3>' + block.replace(/^###\s+/, '') + '</h3>'
    if (/^```/.test(block)) return '<pre><code>' + block.replace(/^```[a-z]*\n?/, '').replace(/```$/, '') + '</code></pre>'
    if (/^>\s+/.test(block)) return '<blockquote>' + block.replace(/^>\s+/gm, '') + '</blockquote>'
    return '<p>' + block.replace(/\n/g, '<br>') + '</p>'
  }).join('')
}

function showOnly (view) {
  dom.blogHero.classList.toggle('hidden', view !== 'blog')
  dom.blogView.classList.toggle('hidden', view !== 'blog')
  dom.postView.classList.toggle('hidden', view !== 'post')
  dom.studioView.classList.toggle('hidden', view !== 'studio')
}

function renderIdentity () {
  dom.identityLabel.textContent = state.pubkey || 'Not signed in'
  dom.signinButton.textContent = state.pubkey ? 'Unlocked' : 'Passkey'
}

function renderPosts () {
  if (!state.posts.length) {
    dom.postGrid.innerHTML = '<p class="empty">No public posts found on the configured relays.</p>'
    return
  }
  dom.postGrid.innerHTML = state.posts.map(post => `
    <a class="post-card" href="#/post/${state.blogPubkey}/${encodeURIComponent(post.slug)}">
      <h3>${escapeHtml(post.title)}</h3>
      <p>${escapeHtml(post.summary)}</p>
      <span class="post-meta">${formatDate(post.createdAt)}</span>
    </a>
  `).join('')
}

function renderPost (slug) {
  const post = state.posts.find(candidate => candidate.slug === slug)
  if (!post) {
    dom.postTitle.textContent = 'Post not loaded'
    dom.postDate.textContent = ''
    dom.postContent.innerHTML = '<p>Refresh the blog and try again.</p>'
    return
  }
  dom.postTitle.textContent = post.title
  dom.postDate.textContent = formatDate(post.createdAt)
  dom.postContent.innerHTML = markdownToHtml(post.content)
}

function renderNotes () {
  dom.noteList.innerHTML = state.notes.map(note => `
    <button class="note-item" data-note-id="${note.id}" type="button">
      <strong>${escapeHtml(note.title)}</strong>
      <span>${note.visibility} · ${formatDate(note.updatedAt)}</span>
    </button>
  `).join('')
}

function renderEditor () {
  const note = state.notes.find(candidate => candidate.id === state.selectedId)
  dom.titleInput.value = note ? note.title : ''
  dom.contentInput.value = note ? note.content : ''
  dom.visibilityInput.value = note ? note.visibility : 'private'
}

function newNote () {
  const note = normalizeNote({
    title: 'Untitled',
    content: '# Untitled\n\n',
    visibility: 'private'
  })
  state.notes.unshift(note)
  state.selectedId = note.id
  renderNotes()
  renderEditor()
}

function escapeHtml (value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function formatDate (value) {
  if (!value) return ''
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  }).format(new Date(value))
}

async function route () {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean)
  if (parts[0] === 'studio') {
    showOnly('studio')
    renderIdentity()
    renderNotes()
    renderEditor()
    return
  }

  if (parts[0] === 'post') {
    state.blogPubkey = parts[1] || state.blogPubkey
    const slug = decodeURIComponent(parts[2] || '')
    showOnly('post')
    if (!state.posts.length) await fetchPublicPosts()
    renderPost(slug)
    return
  }

  if (parts[0] === 'blog' && parts[1]) {
    state.blogPubkey = parts[1]
    localStorage.setItem(pubkeyStorageKey, state.blogPubkey)
  }

  dom.pubkeyInput.value = state.blogPubkey
  showOnly('blog')
  await fetchPublicPosts()
}

function bind () {
  dom.relaysInput.value = state.relays.join('\n')
  dom.pubkeyInput.value = state.blogPubkey
  renderIdentity()

  dom.signinButton.addEventListener('click', () => {
    signIn().catch(error => toast(error.message || String(error)))
  })
  dom.restoreButton.addEventListener('click', () => {
    restoreVault().catch(error => toast(error.message || String(error)))
  })
  dom.backupButton.addEventListener('click', () => {
    backupVault().catch(error => toast(error.message || String(error)))
  })
  dom.newNoteButton.addEventListener('click', newNote)
  dom.saveButton.addEventListener('click', () => {
    saveEncrypted().catch(error => toast(error.message || String(error)))
  })
  dom.publishButton.addEventListener('click', () => {
    publishCurrent().catch(error => toast(error.message || String(error)))
  })
  dom.noteList.addEventListener('click', event => {
    const button = event.target.closest('[data-note-id]')
    if (!button) return
    state.selectedId = button.dataset.noteId
    renderEditor()
  })
  dom.pubkeyForm.addEventListener('submit', event => {
    event.preventDefault()
    state.blogPubkey = dom.pubkeyInput.value.trim()
    localStorage.setItem(pubkeyStorageKey, state.blogPubkey)
    location.hash = '#/blog/' + state.blogPubkey
  })
  dom.refreshPublicButton.addEventListener('click', () => {
    fetchPublicPosts().catch(error => toast(error.message || String(error)))
  })
  window.addEventListener('hashchange', () => {
    route().catch(error => toast(error.message || String(error)))
  })
}

bind()
route().catch(error => toast(error.message || String(error)))
