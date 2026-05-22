import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  ARTICLE_KIND,
  VAULT_IDENTIFIER,
  VAULT_KIND,
  articleEventTemplate,
  bytesToBase64URL,
  base64URLToBytes,
  createVault,
  decryptVaultPayload,
  encryptVaultPayload,
  hashEvent,
  publicPostFromEvent,
  vaultEventTemplate
} from '../public/core.js'

if (!globalThis.crypto) {
  const { webcrypto } = await import('node:crypto')
  globalThis.crypto = webcrypto
}

const root = join(fileURLToPath(new URL('..', import.meta.url)), 'public')

async function testBase64URL () {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
  assert.deepEqual(Array.from(base64URLToBytes(bytesToBase64URL(bytes))), Array.from(bytes))
}

async function testVaultEncryption () {
  const privateKey = '1'.repeat(64)
  const vault = createVault('a'.repeat(64), [{
    title: 'Private',
    content: '# Secret\n\nhidden marker',
    visibility: 'private'
  }])
  const box = await encryptVaultPayload(vault, privateKey)
  const serialized = JSON.stringify(box)
  assert.equal(serialized.includes('hidden marker'), false)
  const opened = await decryptVaultPayload(box, privateKey)
  assert.equal(opened.notes[0].content.includes('hidden marker'), true)
}

async function testEvents () {
  const post = articleEventTemplate({
    title: 'Hello Nostr',
    content: '# Hello Nostr\n\nPublic markdown with #Nostr',
    visibility: 'public',
    publishedAt: '2026-05-22T00:00:00.000Z'
  })
  assert.equal(post.kind, ARTICLE_KIND)
  assert(post.tags.some(tag => tag[0] === 't' && tag[1] === 'nostr'))

  const event = {
    pubkey: 'b'.repeat(64),
    created_at: 1,
    kind: post.kind,
    tags: post.tags,
    content: post.content
  }
  event.id = await hashEvent(event)
  const publicPost = publicPostFromEvent(event)
  assert.equal(publicPost.title, 'Hello Nostr')

  const vaultEvent = vaultEventTemplate({ version: 1 })
  assert.equal(vaultEvent.kind, VAULT_KIND)
  assert(vaultEvent.tags.some(tag => tag[0] === 'd' && tag[1] === VAULT_IDENTIFIER))
}

async function testNoBackendRuntime () {
  const app = await readFile(join(root, 'app.js'), 'utf8')
  const html = await readFile(join(root, 'index.html'), 'utf8')
  const casper = await readFile(join(root, 'casper-screen.css'), 'utf8')
  const wrangler = await readFile(join(root, '..', 'wrangler.toml'), 'utf8')
  assert.equal(app.includes('/api/'), false)
  assert.equal(app.includes('sqlite'), false)
  assert.equal(app.includes('mysql'), false)
  assert(html.includes('script type="module"'), true)
  assert(html.includes('fork-awesome/css/fork-awesome.min.css'), true)
  assert(html.includes('class="gh-head outer"'), true)
  assert(html.includes('class="navbar navbar-default navbar-fixed-top'), true)
  assert(html.includes('fa fa-file-text'), true)
  assert(casper.includes('.post-card'), true)
  assert(casper.includes('.article-title'), true)
  assert(wrangler.includes('pages_build_output_dir = "public"'), true)
}

async function testStaticServer () {
  const server = createServer(async (req, res) => {
    const pathname = req.url === '/' ? '/index.html' : req.url
    const file = join(root, pathname.replace(/^\//, ''))
    const type = {
      '.html': 'text/html',
      '.js': 'text/javascript',
      '.css': 'text/css'
    }[extname(file)] || 'text/plain'
    try {
      const body = await readFile(file)
      res.writeHead(200, { 'content-type': type })
      res.end(body)
    } catch (err) {
      res.writeHead(404)
      res.end('not found')
    }
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  const response = await fetch(`http://127.0.0.1:${port}/`)
  const body = await response.text()
  await new Promise(resolve => server.close(resolve))
  assert.equal(response.status, 200)
  assert(body.includes('Nostr Ghost'), true)
  assert(body.includes('Private studio'), true)
  assert(body.includes('CodiMD'), true)
}

await testBase64URL()
await testVaultEncryption()
await testEvents()
await testNoBackendRuntime()
await testStaticServer()

console.log('nostr-ghost tests passed')
