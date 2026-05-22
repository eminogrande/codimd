'use strict'

const Router = require('express').Router
const bodyParser = require('body-parser')

const logger = require('../logger')
const models = require('../models')
const response = require('../response')
const { buildArticleEvent, buildVaultEvent, openVaultEvent } = require('./vault')
const { exportUserVault, restoreUserVault, vaultFilter } = require('./codimd')
const { fetchLatestReplaceable, publishToRelays } = require('./relay')
const { getPublicKey, normalizePrivateKey } = require('./keys')

const nostrRouter = module.exports = Router()
const jsonParser = bodyParser.json({ limit: '2mb' })

function requireAuth (req, res) {
  if (!req.isAuthenticated()) {
    response.errorForbidden(req, res)
    return false
  }
  return true
}

function relaysFromBody (body) {
  const relays = Array.isArray(body.relays) ? body.relays : [body.relay]
  return relays.filter(relay => typeof relay === 'string' && relay.trim()).map(relay => relay.trim())
}

function getSessionPrivateKey (req) {
  return normalizePrivateKey(req.session.nostrPrivateKey)
}

async function publishIfRequested (relays, event) {
  if (relays.length === 0) return []
  return publishToRelays(relays, event)
}

nostrRouter.get('/api/nostr/status', function (req, res) {
  if (!requireAuth(req, res)) return

  res.send({
    status: 'ok',
    pubkey: req.session.nostrPubkey || null,
    hasSessionKey: !!req.session.nostrPrivateKey
  })
})

nostrRouter.post('/api/nostr/backup', jsonParser, async function (req, res) {
  if (!requireAuth(req, res)) return

  try {
    const privateKey = getSessionPrivateKey(req)
    const vault = await exportUserVault(models, req.user.id)
    const event = buildVaultEvent(vault, privateKey)
    const relays = relaysFromBody(req.body)
    const publish = await publishIfRequested(relays, event)

    res.send({
      status: 'ok',
      eventId: event.id,
      pubkey: event.pubkey,
      notes: vault.notes.length,
      publish: publish,
      event: event
    })
  } catch (err) {
    logger.error('nostr backup failed: ' + err.message)
    res.status(400).send({
      status: 'error',
      message: err.message
    })
  }
})

nostrRouter.post('/api/nostr/restore', jsonParser, async function (req, res) {
  if (!requireAuth(req, res)) return

  try {
    const privateKey = getSessionPrivateKey(req)
    const event = req.body.event || await fetchLatestReplaceable(
      relaysFromBody(req.body),
      vaultFilter(getPublicKey(privateKey))
    )

    if (!event) {
      return res.status(404).send({
        status: 'error',
        message: 'No Nostr vault backup found'
      })
    }

    const vault = openVaultEvent(event, privateKey)
    const result = await restoreUserVault(models, vault, req.user.id)

    res.send(Object.assign({
      status: 'ok',
      eventId: event.id
    }, result))
  } catch (err) {
    logger.error('nostr restore failed: ' + err.message)
    res.status(400).send({
      status: 'error',
      message: err.message
    })
  }
})

nostrRouter.post('/api/nostr/publish/:noteId', jsonParser, async function (req, res) {
  if (!requireAuth(req, res)) return

  try {
    const noteId = await models.Note.parseNoteIdAsync(req.params.noteId)
    const note = await models.Note.findOne({
      where: {
        id: noteId
      }
    })

    if (!note) return response.errorNotFound(req, res)
    if (note.ownerId !== req.user.id) return response.errorForbidden(req, res)

    const event = buildArticleEvent(note, getSessionPrivateKey(req), {
      identifier: req.body.identifier,
      title: req.body.title,
      summary: req.body.summary
    })
    const relays = relaysFromBody(req.body)
    const publish = await publishIfRequested(relays, event)

    res.send({
      status: 'ok',
      eventId: event.id,
      pubkey: event.pubkey,
      kind: event.kind,
      publish: publish,
      event: event
    })
  } catch (err) {
    logger.error('nostr publish failed: ' + err.message)
    res.status(400).send({
      status: 'error',
      message: err.message
    })
  }
})

nostrRouter._private = {
  getSessionPrivateKey,
  relaysFromBody
}
