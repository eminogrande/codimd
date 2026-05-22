/* eslint-env node, mocha */
'use strict'

const assert = require('assert')
const mock = require('mock-require')
const sinon = require('sinon')

const { createFakeLogger } = require('../testDoubles/loggerFake')
const { removeLibModuleCache } = require('../realtime/utils')
const { generatePrivateKey } = require('../../lib/nostr/keys')
const { signEvent } = require('../../lib/nostr/events')

describe('nostr auth helpers', function () {
  let models
  let nostrAuth

  beforeEach(function () {
    removeLibModuleCache()
    models = {
      User: {
        findOne: sinon.stub(),
        create: sinon.stub()
      }
    }
    mock('../../lib/models', models)
    mock('../../lib/logger', createFakeLogger())
    nostrAuth = mock.reRequire('../../lib/auth/nostr')
  })

  afterEach(function () {
    mock.stopAll()
    sinon.restore()
    removeLibModuleCache()
  })

  it('builds a stable 32-byte PRF salt', function () {
    const salt = nostrAuth._private.buildPRFSalt()
    assert.strictEqual(salt, nostrAuth._private.buildPRFSalt())
    assert.strictEqual(Buffer.from(salt.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length, 32)
  })

  it('verifies the signed Nostr login challenge event', function () {
    const privateKey = generatePrivateKey()
    const event = signEvent({
      kind: 22242,
      tags: [
        ['challenge', 'challenge-1']
      ],
      content: 'CodiMD Nostr passkey login'
    }, privateKey)

    assert.strictEqual(nostrAuth._private.verifyLoginEvent(event, 'challenge-1'), true)
    assert.strictEqual(nostrAuth._private.verifyLoginEvent(event, 'challenge-2'), false)
  })

  it('creates a Nostr-backed user when one does not exist', async function () {
    const created = {
      id: 'user-1'
    }
    models.User.findOne.returns(Promise.resolve(null))
    models.User.create.returns(Promise.resolve(created))

    const user = await nostrAuth._private.findOrCreateNostrUser('a'.repeat(64))

    assert.strictEqual(user, created)
    assert.strictEqual(models.User.create.lastCall.args[0].profileid, 'nostr:' + 'a'.repeat(64))
  })
})

describe('nostr route helpers', function () {
  let nostrRoutes

  beforeEach(function () {
    removeLibModuleCache()
    mock('../../lib/models', {})
    mock('../../lib/logger', createFakeLogger())
    mock('../../lib/response', {})
    nostrRoutes = mock.reRequire('../../lib/nostr/routes')
  })

  afterEach(function () {
    mock.stopAll()
    removeLibModuleCache()
  })

  it('normalizes relay inputs from request bodies', function () {
    assert.deepStrictEqual(nostrRoutes._private.relaysFromBody({
      relay: ' wss://relay.example.com '
    }), ['wss://relay.example.com'])

    assert.deepStrictEqual(nostrRoutes._private.relaysFromBody({
      relays: ['wss://a.example', '', 7, ' wss://b.example ']
    }), ['wss://a.example', 'wss://b.example'])
  })
})
