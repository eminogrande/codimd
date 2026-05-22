/* eslint-env node, mocha */
'use strict'

const assert = require('assert')
const WebSocket = require('ws')

const { derivePrivateKey, generatePrivateKey, getPublicKey } = require('../../lib/nostr/keys')
const { signEvent, verifyEvent } = require('../../lib/nostr/events')
const {
  ARTICLE_KIND,
  VAULT_KIND,
  buildArticleEvent,
  buildVaultEvent,
  createVault,
  openVaultEvent
} = require('../../lib/nostr/vault')
const { exportUserVault, restoreUserVault, vaultFilter } = require('../../lib/nostr/codimd')
const { fetchLatestReplaceable, publishToRelays } = require('../../lib/nostr/relay')

function startServer () {
  const server = new WebSocket.Server({ host: '127.0.0.1', port: 0 })
  return new Promise(resolve => {
    server.on('listening', () => {
      resolve({
        server: server,
        relay: 'ws://127.0.0.1:' + server.address().port
      })
    })
  })
}

describe('nostr keys and events', function () {
  it('derives stable private and public keys', function () {
    const first = derivePrivateKey('passkey-prf-output')
    const second = derivePrivateKey('passkey-prf-output')

    assert.strictEqual(first, second)
    assert.strictEqual(first.length, 64)
    assert.strictEqual(getPublicKey(first).length, 64)
  })

  it('signs and verifies nostr events', function () {
    const privateKey = generatePrivateKey()
    const event = signEvent({
      kind: 1,
      tags: [],
      content: 'hello nostr'
    }, privateKey)

    assert.strictEqual(event.pubkey, getPublicKey(privateKey))
    assert.strictEqual(event.id.length, 64)
    assert.strictEqual(event.sig.length, 128)
    assert.strictEqual(verifyEvent(event), true)
  })
})

describe('nostr vault', function () {
  it('encrypts a CodiMD user vault and opens it with the same key', function () {
    const privateKey = generatePrivateKey()
    const vault = createVault(
      { id: 'user-1', email: 'user@example.com', password: 'not exported' },
      [{
        id: 'note-1',
        shortid: 'short-1',
        title: 'Private title',
        content: '# Secret note\n\nbody',
        permission: 'private',
        createdAt: new Date('2024-01-01T00:00:00Z')
      }],
      { exportedAt: '2024-01-02T00:00:00.000Z' }
    )
    const event = buildVaultEvent(vault, privateKey, { createdAt: 100 })

    assert.strictEqual(event.kind, VAULT_KIND)
    assert.strictEqual(event.pubkey, getPublicKey(privateKey))
    assert.strictEqual(event.content.includes('Secret note'), false)
    assert.strictEqual(event.content.includes('Private title'), false)

    const opened = openVaultEvent(event, privateKey)
    assert.strictEqual(opened.user.id, 'user-1')
    assert.strictEqual(opened.user.password, undefined)
    assert.strictEqual(opened.notes[0].content, '# Secret note\n\nbody')
  })

  it('builds a public long-form article event for publishing', function () {
    const privateKey = generatePrivateKey()
    const event = buildArticleEvent({
      id: 'note-1',
      shortid: 'short-1',
      title: 'Published title',
      content: '# Published title\n\nPublic #Nostr content'
    }, privateKey, { createdAt: 200, publishedAt: 200 })

    assert.strictEqual(event.kind, ARTICLE_KIND)
    assert.strictEqual(event.content.includes('Public #Nostr content'), true)
    assert.deepStrictEqual(event.tags.find(tag => tag[0] === 'd'), ['d', 'short-1'])
    assert.deepStrictEqual(event.tags.find(tag => tag[0] === 'title'), ['title', 'Published title'])
    assert(event.tags.some(tag => tag[0] === 't' && tag[1] === 'nostr'))
    assert.strictEqual(verifyEvent(event), true)
  })
})

describe('nostr relay client', function () {
  let server

  afterEach(function (done) {
    if (!server) return done()
    server.close(done)
    server = null
  })

  it('publishes an event to a relay and reads the OK response', async function () {
    const privateKey = generatePrivateKey()
    const event = signEvent({ kind: 1, content: 'relay publish' }, privateKey)

    const started = await startServer()
    server = started.server
    server.on('connection', ws => {
      ws.on('message', data => {
        const message = JSON.parse(data.toString())
        assert.strictEqual(message[0], 'EVENT')
        assert.strictEqual(message[1].id, event.id)
        ws.send(JSON.stringify(['OK', event.id, true, 'saved']))
      })
    })

    const relay = started.relay
    const results = await publishToRelays([relay], event, { timeout: 1000 })

    assert.deepStrictEqual(results, [{
      relay: relay,
      ok: true,
      message: 'saved'
    }])
  })

  it('fetches the newest replaceable event from a relay', async function () {
    const privateKey = generatePrivateKey()
    const event = buildVaultEvent(createVault({ id: 'user-1' }, []), privateKey, { createdAt: 300 })

    const started = await startServer()
    server = started.server
    server.on('connection', ws => {
      ws.on('message', data => {
        const message = JSON.parse(data.toString())
        assert.strictEqual(message[0], 'REQ')
        ws.send(JSON.stringify(['EVENT', message[1], event]))
        ws.send(JSON.stringify(['EOSE', message[1]]))
      })
    })

    const relay = started.relay
    const fetched = await fetchLatestReplaceable(
      [relay],
      vaultFilter(getPublicKey(privateKey)),
      { timeout: 1000 }
    )

    assert.strictEqual(fetched.id, event.id)
  })
})

describe('codimd nostr vault helpers', function () {
  it('exports a user vault from model methods', async function () {
    const models = {
      User: {
        findOne: async () => ({ id: 'user-1', email: 'user@example.com' })
      },
      Note: {
        findAll: async () => [{
          id: 'note-1',
          shortid: 'short-1',
          title: 'A note',
          content: 'Body'
        }]
      }
    }

    const vault = await exportUserVault(models, 'user-1', {
      exportedAt: '2024-01-02T00:00:00.000Z'
    })

    assert.strictEqual(vault.user.id, 'user-1')
    assert.strictEqual(vault.notes.length, 1)
    assert.strictEqual(vault.notes[0].content, 'Body')
  })

  it('restores notes by updating existing rows and creating missing rows', async function () {
    let created
    let updated
    const existing = {
      update: async values => {
        updated = values
      }
    }
    const models = {
      User: {
        findOne: async () => ({ id: 'target-user' })
      },
      Note: {
        findOne: async query => query.where.id === 'existing-note' ? existing : null,
        create: async values => {
          created = values
        }
      }
    }

    const result = await restoreUserVault(models, {
      app: 'codimd',
      notes: [{
        id: 'existing-note',
        shortid: 'short-existing',
        title: 'Updated',
        content: 'Updated content'
      }, {
        id: 'new-note',
        shortid: 'short-new',
        title: 'Created',
        content: 'Created content'
      }]
    }, 'target-user')

    assert.strictEqual(result.updated, 1)
    assert.strictEqual(result.created, 1)
    assert.strictEqual(updated.ownerId, 'target-user')
    assert.strictEqual(updated.content, 'Updated content')
    assert.strictEqual(created.id, 'new-note')
    assert.strictEqual(created.ownerId, 'target-user')
    assert.strictEqual(created.content, 'Created content')
  })
})
