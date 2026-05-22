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
const autosaveDelayMs = 1800

let autosaveTimer = null
let autosaveInFlight = false
let autosaveQueued = false
let codimdEditor = null
let editorHydrating = false
let markdownRenderer = null

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
  studioSigninButton: document.getElementById('studioSigninButton'),
  lockSigninButton: document.getElementById('lockSigninButton'),
  studioLock: document.getElementById('studioLock'),
  identityLabel: document.getElementById('identityLabel'),
  identityBlogLink: document.getElementById('identityBlogLink'),
  relaysInput: document.getElementById('relaysInput'),
  restoreButton: document.getElementById('restoreButton'),
  backupButton: document.getElementById('backupButton'),
  newNoteButton: document.getElementById('newNoteButton'),
  saveButton: document.getElementById('saveButton'),
  publishButton: document.getElementById('publishButton'),
  blogLink: document.getElementById('blogLink'),
  titleInput: document.getElementById('titleInput'),
  contentInput: document.getElementById('contentInput'),
  visibilityInput: document.getElementById('visibilityInput'),
  visibilityBadge: document.getElementById('visibilityBadge'),
  visibilityNavBadge: document.getElementById('visibilityNavBadge'),
  onlineCountLabel: document.getElementById('onlineCountLabel'),
  onlineIdentityLabel: document.getElementById('onlineIdentityLabel'),
  cursorStatus: document.getElementById('cursorStatus'),
  selectionStatus: document.getElementById('selectionStatus'),
  fileStatus: document.getElementById('fileStatus'),
  lengthStatus: document.getElementById('lengthStatus'),
  noteList: document.getElementById('noteList'),
  postGrid: document.getElementById('postGrid'),
  postView: document.getElementById('postView'),
  blogView: document.querySelector('[data-view="blog"]'),
  studioView: document.getElementById('studioView'),
  blogHero: document.getElementById('blogHero'),
  postTitle: document.getElementById('postTitle'),
  postExcerpt: document.getElementById('postExcerpt'),
  postDate: document.getElementById('postDate'),
  postContent: document.getElementById('postContent'),
  docPreview: document.getElementById('doc'),
  siteFooter: document.getElementById('siteFooter'),
  mobileMenuButton: document.getElementById('mobileMenuButton'),
  autosaveStatusLabel: document.getElementById('autosaveStatusLabel'),
  lastChangeLabel: document.getElementById('lastChangeLabel'),
  editModeButton: document.getElementById('editModeButton'),
  bothModeButton: document.getElementById('bothModeButton'),
  viewModeButton: document.getElementById('viewModeButton'),
  nightModeButton: document.getElementById('nightModeButton'),
  mobileModeButton: document.getElementById('mobileModeButton'),
  tocBackToTop: document.getElementById('tocBackToTop'),
  tocGoToBottom: document.getElementById('tocGoToBottom'),
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
  if (location.hash === '#/studio') {
    await route()
  } else {
    location.hash = '#/studio'
  }
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

async function backupVault (options = {}) {
  requireKey()
  const vault = createVault(state.pubkey, state.notes)
  const box = await encryptVaultPayload(vault, state.privateKey)
  const event = await signEvent(vaultEventTemplate(box))
  const published = await publishToRelays(event)
  if (!options.silent) toast(`Encrypted backup published to ${published.ok}/${published.total} relays`)
  return { event, published }
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
  const content = editorValue()
  return normalizeNote({
    ...existing,
    title: noteTitle(content, dom.titleInput.value || existing.title),
    content,
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
  clearTimeout(autosaveTimer)
  upsertCurrentNote()
  const { published } = await backupVault()
  setAutosaveStatus(`encrypted backup saved to ${published.ok}/${published.total} relays`, published.ok ? 'saved' : 'error')
}

async function publishCurrent () {
  clearTimeout(autosaveTimer)
  const note = {
    ...upsertCurrentNote(),
    visibility: 'public',
    publishedAt: new Date().toISOString()
  }
  state.notes = state.notes.map(candidate => candidate.id === note.id ? note : candidate)
  dom.visibilityInput.value = 'public'
  renderVisibilityState()
  renderNotes()
  const article = await signEvent(articleEventTemplate(note))
  const published = await publishToRelays(article)
  await backupVault({ silent: true })
  setAutosaveStatus('public post published, encrypted vault backed up', published.ok ? 'saved' : 'error')
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

function getMarkdownRenderer () {
  if (!markdownRenderer && typeof window.markdownit === 'function') {
    markdownRenderer = window.markdownit({
      html: false,
      linkify: true,
      typographer: true
    })
  }
  return markdownRenderer
}

function markdownToHtml (markdown) {
  const renderer = getMarkdownRenderer()
  if (renderer) return renderer.render(String(markdown || ''))
  return fallbackMarkdownToHtml(markdown)
}

function fallbackMarkdownToHtml (markdown) {
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
  document.body.className = view === 'studio'
    ? 'studio-template'
    : view === 'post'
      ? 'post-template has-serif-title has-sans-body is-dropdown-loaded'
      : 'home-template has-serif-title has-sans-body is-dropdown-loaded'
  dom.blogHero.classList.toggle('hidden', view !== 'blog')
  dom.blogView.classList.toggle('hidden', view !== 'blog')
  dom.postView.classList.toggle('hidden', view !== 'post')
  dom.studioView.classList.toggle('hidden', view !== 'studio')
  dom.siteFooter.classList.toggle('hidden', view === 'studio')
}

function renderIdentity () {
  dom.identityLabel.textContent = state.pubkey || 'Not signed in'
  dom.signinButton.textContent = state.pubkey ? 'Unlocked' : 'Passkey'
  dom.studioSigninButton.innerHTML = state.pubkey
    ? '<i class="fa fa-key fa-fw"></i> Passkey unlocked'
    : '<i class="fa fa-key fa-fw"></i> Unlock passkey'
  dom.onlineIdentityLabel.textContent = state.pubkey
    ? 'Passkey ' + state.pubkey.slice(0, 12) + '...'
    : 'Local browser'
  dom.onlineCountLabel.textContent = '1'
  const blogPubkey = state.pubkey || state.blogPubkey
  const blogHref = /^[0-9a-f]{64}$/i.test(blogPubkey) ? '#/blog/' + blogPubkey : '#/'
  dom.blogLink.href = blogHref
  dom.identityBlogLink.href = blogHref
  dom.identityBlogLink.textContent = /^[0-9a-f]{64}$/i.test(blogPubkey)
    ? 'Open Nostr blog'
    : 'Unlock passkey to open blog'
}

function hasUnlockedPasskey () {
  return Boolean(state.privateKey && state.pubkey)
}

function renderStudioAccess () {
  const locked = !hasUnlockedPasskey()
  dom.studioView.classList.toggle('is-locked', locked)
  dom.studioView.classList.toggle('is-unlocked', !locked)
  const lockedButtons = [dom.newNoteButton, dom.publishButton, dom.backupButton, dom.restoreButton, dom.saveButton]
  lockedButtons.forEach(button => {
    if (button) button.disabled = locked
  })
}

function renderPosts () {
  if (!state.posts.length) {
    dom.postGrid.innerHTML = '<p class="empty">No public posts found on the configured relays.</p>'
    return
  }
  dom.postGrid.innerHTML = state.posts.map((post, index) => `
    <article class="post-card no-image${index === 0 ? ' post-card-large' : ''}">
      <div class="post-card-content">
        <a class="post-card-content-link" href="#/post/${state.blogPubkey}/${encodeURIComponent(post.slug)}">
          <header class="post-card-header">
            <div class="post-card-tags">
              <span class="post-card-primary-tag">Nostr</span>
            </div>
            <h2 class="post-card-title">${escapeHtml(post.title)}</h2>
          </header>
          <div class="post-card-excerpt">${escapeHtml(post.summary)}</div>
        </a>
        <footer class="post-card-meta">
          <time class="post-card-meta-date" datetime="${escapeHtml(post.createdAt.slice(0, 10))}">${formatDate(post.createdAt)}</time>
          <span class="post-card-meta-length">${readingTime(post.content)}</span>
        </footer>
      </div>
    </article>
  `).join('')
}

function renderPost (slug) {
  const post = state.posts.find(candidate => candidate.slug === slug)
  if (!post) {
    dom.postTitle.textContent = 'Post not loaded'
    dom.postExcerpt.textContent = ''
    dom.postDate.textContent = ''
    dom.postContent.innerHTML = '<p>Refresh the blog and try again.</p>'
    return
  }
  dom.postTitle.textContent = post.title
  dom.postExcerpt.textContent = post.summary
  dom.postDate.textContent = formatDate(post.createdAt)
  dom.postDate.setAttribute('datetime', post.createdAt.slice(0, 10))
  dom.postContent.innerHTML = markdownToHtml(post.content)
}

function renderNotes () {
  dom.noteList.innerHTML = state.notes.map(note => `
    <button class="note-item visibility-${note.visibility}${note.id === state.selectedId ? ' active' : ''}" data-note-id="${note.id}" type="button">
      <strong>${escapeHtml(note.title)}</strong>
      <span>${visibilityLabel(note.visibility)} &middot; ${formatDate(note.updatedAt)}</span>
    </button>
  `).join('')
}

function updateEditorStatus () {
  const value = editorValue()
  const lines = value ? value.split('\n').length : 1
  let line = 1
  let column = 1
  let selection = ''

  if (codimdEditor) {
    const cursor = codimdEditor.getCursor()
    line = cursor.line + 1
    column = cursor.ch + 1
    const selected = codimdEditor.getSelection()
    selection = selected ? ' - ' + selected.length + ' selected' : ''
  } else if (dom.contentInput) {
    const prefix = dom.contentInput.value.slice(0, dom.contentInput.selectionStart || 0)
    line = prefix.split('\n').length
    column = prefix.split('\n').pop().length + 1
  }

  dom.cursorStatus.textContent = `Line ${line}, Column ${column}`
  dom.selectionStatus.textContent = selection
  dom.fileStatus.textContent = ` - ${lines} Lines`
  dom.lengthStatus.textContent = `Length ${value.length}`
}

function initCodimdEditor () {
  if (codimdEditor || typeof window.CodeMirror !== 'function') return
  codimdEditor = window.CodeMirror.fromTextArea(dom.contentInput, {
    mode: 'gfm',
    theme: 'default',
    lineNumbers: true,
    lineWrapping: true,
    styleActiveLine: true,
    matchBrackets: true,
    autoCloseBrackets: true,
    tabSize: 4,
    indentUnit: 4,
    indentWithTabs: false,
    inputStyle: 'textarea',
    extraKeys: {
      Enter: 'newlineAndIndentContinueMarkdownList'
    }
  })
  codimdEditor.setSize('100%', '100%')
  codimdEditor.on('change', () => {
    if (!editorHydrating) handleEditorChange()
    updateEditorStatus()
  })
  codimdEditor.on('cursorActivity', updateEditorStatus)
  updateEditorStatus()
}

function editorValue () {
  return codimdEditor ? codimdEditor.getValue() : dom.contentInput.value
}

function setEditorValue (value) {
  editorHydrating = true
  if (codimdEditor) {
    codimdEditor.setValue(value)
    codimdEditor.refresh()
  } else {
    dom.contentInput.value = value
  }
  editorHydrating = false
  updateEditorStatus()
}

function noteTitle (content, fallback) {
  const heading = String(content || '').match(/^#\s+(.+)$/m)
  if (heading && heading[1].trim()) return heading[1].trim()
  const firstLine = String(content || '').split('\n').map(line => line.trim()).find(Boolean)
  return firstLine
    ? firstLine.replace(/^[#>*\-\d.\s]+/, '').replace(/[*_`[\]()]/g, '').slice(0, 80) || fallback || 'Untitled'
    : fallback || 'Untitled'
}

function wrapSelection (before, after = '', placeholder = 'text') {
  if (codimdEditor) {
    const selection = codimdEditor.getSelection() || placeholder
    codimdEditor.replaceSelection(before + selection + after, 'around')
    codimdEditor.focus()
    return
  }
  const start = dom.contentInput.selectionStart
  const end = dom.contentInput.selectionEnd
  const selection = dom.contentInput.value.slice(start, end) || placeholder
  dom.contentInput.setRangeText(before + selection + after, start, end, 'end')
  dom.contentInput.focus()
  handleEditorChange()
}

function prefixSelectionLines (prefix) {
  if (codimdEditor) {
    const selection = codimdEditor.getSelection() || 'text'
    codimdEditor.replaceSelection(selection.split('\n').map(line => prefix + line).join('\n'))
    codimdEditor.focus()
    return
  }
  const start = dom.contentInput.selectionStart
  const end = dom.contentInput.selectionEnd
  const selection = dom.contentInput.value.slice(start, end) || 'text'
  dom.contentInput.setRangeText(selection.split('\n').map(line => prefix + line).join('\n'), start, end, 'end')
  dom.contentInput.focus()
  handleEditorChange()
}

function insertMarkdown (markdown) {
  if (codimdEditor) {
    codimdEditor.replaceSelection(markdown)
    codimdEditor.focus()
    return
  }
  const start = dom.contentInput.selectionStart
  const end = dom.contentInput.selectionEnd
  dom.contentInput.setRangeText(markdown, start, end, 'end')
  dom.contentInput.focus()
  handleEditorChange()
}

function bindCodimdToolbar () {
  const bindButton = (id, action) => {
    const button = document.getElementById(id)
    if (!button) return
    button.addEventListener('click', action)
  }
  bindButton('makeBold', () => wrapSelection('**', '**', 'bold text'))
  bindButton('makeItalic', () => wrapSelection('*', '*', 'italic text'))
  bindButton('makeStrike', () => wrapSelection('~~', '~~', 'struck text'))
  bindButton('makeHeader', () => prefixSelectionLines('### '))
  bindButton('makeCode', () => wrapSelection('`', '`', 'code'))
  bindButton('makeQuote', () => prefixSelectionLines('> '))
  bindButton('makeGenericList', () => prefixSelectionLines('- '))
  bindButton('makeOrderedList', () => prefixSelectionLines('1. '))
  bindButton('makeCheckList', () => prefixSelectionLines('- [ ] '))
  bindButton('makeLink', () => wrapSelection('[', '](https://)', 'link text'))
  bindButton('makeImage', () => insertMarkdown('![alt text](https://)\n'))
  bindButton('makeTable', () => insertMarkdown('\n| Column | Column |\n| --- | --- |\n| Cell | Cell |\n'))
  bindButton('makeLine', () => insertMarkdown('\n---\n'))
  bindButton('makeComment', () => wrapSelection('<!-- ', ' -->', 'comment'))
}

function updatePreview () {
  dom.docPreview.innerHTML = markdownToHtml(editorValue())
  renderVisibilityState()
}

function currentVisibility () {
  return dom.visibilityInput.value === 'public' ? 'public' : 'private'
}

function visibilityLabel (visibility) {
  return visibility === 'public' ? 'Public draft' : 'Private encrypted'
}

function visibilityIcon (visibility) {
  return visibility === 'public' ? 'fa-globe' : 'fa-lock'
}

function renderVisibilityBadge (element, visibility) {
  if (!element) return
  element.className = `visibility-badge visibility-badge-${visibility}`
  element.innerHTML = `<i class="fa ${visibilityIcon(visibility)}"></i> ${visibilityLabel(visibility)}`
}

function renderVisibilityState () {
  const visibility = currentVisibility()
  dom.studioView.classList.toggle('visibility-private', visibility === 'private')
  dom.studioView.classList.toggle('visibility-public', visibility === 'public')
  dom.visibilityInput.classList.toggle('visibility-input-private', visibility === 'private')
  dom.visibilityInput.classList.toggle('visibility-input-public', visibility === 'public')
  renderVisibilityBadge(dom.visibilityBadge, visibility)
  renderVisibilityBadge(dom.visibilityNavBadge, visibility)
}

function setAutosaveStatus (message, mode = 'idle') {
  dom.autosaveStatusLabel.textContent = message
  dom.autosaveStatusLabel.dataset.autosave = mode
}

function autosaveLabel () {
  return currentVisibility() === 'public'
    ? 'encrypted draft autosaved, not published'
    : 'encrypted autosaved'
}

function handleEditorChange () {
  updateEditorStatus()
  updatePreview()
  dom.titleInput.value = noteTitle(editorValue(), dom.titleInput.value)
  upsertCurrentNote()
  scheduleEncryptedAutosave()
}

function scheduleEncryptedAutosave () {
  if (!state.selectedId) return
  if (!state.privateKey || !state.pubkey) {
    clearTimeout(autosaveTimer)
    setAutosaveStatus('unlock passkey to enable encrypted autosave', 'blocked')
    return
  }

  clearTimeout(autosaveTimer)
  setAutosaveStatus(currentVisibility() === 'public'
    ? 'encrypted draft autosave pending'
    : 'encrypted autosave pending',
  'pending')
  autosaveTimer = setTimeout(() => {
    encryptedAutosave().catch(error => {
      setAutosaveStatus('encrypted autosave failed', 'error')
      toast(error.message || String(error))
    })
  }, autosaveDelayMs)
}

async function encryptedAutosave () {
  clearTimeout(autosaveTimer)
  if (autosaveInFlight) {
    autosaveQueued = true
    return
  }
  if (!state.privateKey || !state.pubkey) {
    setAutosaveStatus('unlock passkey to enable encrypted autosave', 'blocked')
    return
  }

  autosaveInFlight = true
  setAutosaveStatus('encrypting autosave to nostr', 'saving')
  try {
    const { published } = await backupVault({ silent: true })
    const mode = published.ok ? 'saved' : 'error'
    setAutosaveStatus(`${autosaveLabel()} to ${published.ok}/${published.total} relays`, mode)
  } finally {
    autosaveInFlight = false
    if (autosaveQueued) {
      autosaveQueued = false
      scheduleEncryptedAutosave()
    }
  }
}

function renderEditor () {
  if (!hasUnlockedPasskey()) return
  initCodimdEditor()
  const note = state.notes.find(candidate => candidate.id === state.selectedId)
  dom.titleInput.value = note ? note.title : ''
  setEditorValue(note ? note.content : '')
  dom.visibilityInput.value = note ? note.visibility : 'private'
  dom.lastChangeLabel.textContent = note ? formatDate(note.updatedAt) : ''
  updatePreview()
  if (codimdEditor) codimdEditor.refresh()
}

function newNote () {
  if (!hasUnlockedPasskey()) {
    toast('Unlock passkey first')
    return
  }
  const note = normalizeNote({
    title: 'Untitled',
    content: '# Untitled\n\n',
    visibility: 'private'
  })
  state.notes.unshift(note)
  state.selectedId = note.id
  renderNotes()
  renderEditor()
  scheduleEncryptedAutosave()
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

function readingTime (content) {
  const words = String(content || '').trim().split(/\s+/).filter(Boolean).length
  const minutes = Math.max(1, Math.ceil(words / 220))
  return minutes + ' min read'
}

function setEditorMode (mode) {
  dom.studioView.classList.toggle('mode-edit', mode === 'edit')
  dom.studioView.classList.toggle('mode-both', mode === 'both')
  dom.studioView.classList.toggle('mode-view', mode === 'view')
  dom.editModeButton.classList.toggle('active', mode === 'edit')
  dom.bothModeButton.classList.toggle('active', mode === 'both')
  dom.viewModeButton.classList.toggle('active', mode === 'view')
}

async function route () {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean)
  if (parts[0] === 'studio') {
    showOnly('studio')
    renderIdentity()
    renderStudioAccess()
    if (!hasUnlockedPasskey()) return
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
  bindCodimdToolbar()
  dom.relaysInput.value = state.relays.join('\n')
  dom.pubkeyInput.value = state.blogPubkey
  renderIdentity()
  renderStudioAccess()

  const bindClick = (element, action) => {
    if (!element) return
    element.addEventListener('click', event => {
      event.preventDefault()
      action(event)
    })
  }

  const unlockPasskey = () => {
    signIn().catch(error => toast(error.message || String(error)))
  }

  bindClick(dom.signinButton, unlockPasskey)
  bindClick(dom.studioSigninButton, unlockPasskey)
  bindClick(dom.lockSigninButton, unlockPasskey)
  dom.mobileMenuButton.addEventListener('click', () => {
    document.body.classList.toggle('gh-head-open')
  })
  bindClick(dom.restoreButton, () => {
    restoreVault().catch(error => toast(error.message || String(error)))
  })
  bindClick(dom.backupButton, () => {
    backupVault().catch(error => toast(error.message || String(error)))
  })
  bindClick(dom.newNoteButton, newNote)
  bindClick(dom.saveButton, () => {
    saveEncrypted().catch(error => toast(error.message || String(error)))
  })
  bindClick(dom.publishButton, () => {
    publishCurrent().catch(error => toast(error.message || String(error)))
  })
  dom.noteList.addEventListener('click', event => {
    const button = event.target.closest('[data-note-id]')
    if (!button) return
    state.selectedId = button.dataset.noteId
    renderEditor()
  })
  dom.titleInput.addEventListener('input', handleEditorChange)
  dom.contentInput.addEventListener('input', handleEditorChange)
  dom.visibilityInput.addEventListener('change', handleEditorChange)
  dom.editModeButton.addEventListener('click', () => setEditorMode('edit'))
  dom.bothModeButton.addEventListener('click', () => setEditorMode('both'))
  dom.viewModeButton.addEventListener('click', () => setEditorMode('view'))
  dom.nightModeButton.addEventListener('click', () => {
    document.body.classList.toggle('studio-night')
    dom.nightModeButton.classList.toggle('active', document.body.classList.contains('studio-night'))
  })
  if (dom.mobileModeButton) {
    dom.mobileModeButton.addEventListener('click', () => setEditorMode(
      dom.studioView.classList.contains('mode-view') ? 'edit' : 'view'
    ))
  }
  bindClick(dom.tocBackToTop, () => {
    document.querySelector('.studio-preview').scrollTo({ top: 0, behavior: 'smooth' })
  })
  bindClick(dom.tocGoToBottom, () => {
    const preview = document.querySelector('.studio-preview')
    preview.scrollTo({ top: preview.scrollHeight, behavior: 'smooth' })
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
  setEditorMode('both')
}

bind()
route().catch(error => toast(error.message || String(error)))
