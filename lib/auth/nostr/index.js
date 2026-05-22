'use strict'

const Router = require('express').Router
const bodyParser = require('body-parser')
const crypto = require('crypto')
const base64url = require('base64url')

const logger = require('../../logger')
const models = require('../../models')
const { verifyEvent } = require('../../nostr/events')
const { getPublicKey, normalizePrivateKey } = require('../../nostr/keys')

const nostrAuth = module.exports = Router()
const jsonParser = bodyParser.json({ limit: '128kb' })

function randomBase64URL (length) {
  return base64url.encode(crypto.randomBytes(length))
}

function buildPRFSalt () {
  return base64url.encode(
    crypto.createHash('sha256')
      .update('codimd-nostr-passkey-prf-v1')
      .digest()
  )
}

function isHexKey (key) {
  return typeof key === 'string' && /^[0-9a-f]{64}$/i.test(key)
}

function hasChallenge (event, challenge) {
  return Array.isArray(event.tags) && event.tags.some(tag => {
    return tag[0] === 'challenge' && tag[1] === challenge
  })
}

async function findOrCreateNostrUser (pubkey) {
  const profileid = 'nostr:' + pubkey
  let user = await models.User.findOne({
    where: {
      profileid: profileid
    }
  })

  const profile = JSON.stringify({
    provider: 'nostr',
    id: pubkey,
    username: 'nostr-' + pubkey.slice(0, 12),
    displayName: 'Nostr ' + pubkey.slice(0, 12)
  })

  if (!user) {
    user = await models.User.create({
      profileid: profileid,
      profile: profile
    })
  } else if (user.profile !== profile) {
    await user.update({
      profile: profile
    })
  }

  return user
}

function verifyLoginEvent (event, challenge) {
  if (!event || event.kind !== 22242 || event.content !== 'CodiMD Nostr passkey login') {
    return false
  }
  if (!isHexKey(event.pubkey) || !hasChallenge(event, challenge)) {
    return false
  }
  return verifyEvent(event)
}

nostrAuth.get('/auth/nostr/challenge', function (req, res) {
  const challenge = randomBase64URL(32)
  const prfSalt = buildPRFSalt()

  req.session.nostrAuth = {
    challenge: challenge,
    prfSalt: prfSalt,
    createdAt: Date.now()
  }

  res.send({
    status: 'ok',
    challenge: challenge,
    prfSalt: prfSalt
  })
})

nostrAuth.post('/auth/nostr/callback', jsonParser, async function (req, res, next) {
  try {
    const sessionAuth = req.session.nostrAuth
    if (!sessionAuth || !sessionAuth.challenge) {
      return res.status(400).send({
        status: 'error',
        message: 'Missing Nostr login challenge'
      })
    }

    if (Date.now() - sessionAuth.createdAt > 5 * 60 * 1000) {
      return res.status(400).send({
        status: 'error',
        message: 'Expired Nostr login challenge'
      })
    }

    const event = req.body.event
    const privateKey = normalizePrivateKey(req.body.privateKey)
    const pubkey = getPublicKey(privateKey)

    if (!verifyLoginEvent(event, sessionAuth.challenge) || event.pubkey !== pubkey) {
      return res.status(403).send({
        status: 'error',
        message: 'Invalid Nostr login signature'
      })
    }

    const user = await findOrCreateNostrUser(pubkey)

    req.login(user, function (err) {
      if (err) return next(err)
      req.session.nostrPrivateKey = privateKey
      req.session.nostrPubkey = pubkey
      req.session.nostrCredentialId = req.body.credentialId || null
      delete req.session.nostrAuth
      logger.info('nostr passkey login: ' + user.id)
      return res.send({
        status: 'ok',
        id: user.id,
        pubkey: pubkey
      })
    })
  } catch (err) {
    return res.status(400).send({
      status: 'error',
      message: err.message
    })
  }
})

nostrAuth._private = {
  buildPRFSalt,
  findOrCreateNostrUser,
  verifyLoginEvent
}
