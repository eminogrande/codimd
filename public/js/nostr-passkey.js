/* eslint-env browser, jquery */

import * as secp from '@noble/secp256k1'

import { serverurl } from './lib/config'
import { resetCheckAuth } from './lib/common/login'

const credentialStorageKey = 'codimd.nostrPasskeyCredentialId'

function bytesToHex (bytes) {
  return Array.from(new Uint8Array(bytes))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
}

function hexToBytes (hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function base64URLToBytes (value) {
  value = value.replace(/-/g, '+').replace(/_/g, '/')
  while (value.length % 4) value += '='
  return Uint8Array.from(atob(value), character => character.charCodeAt(0))
}

function bytesToBase64URL (bytes) {
  return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(bytes))))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

async function sha256 (data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}

async function hmacSha256 (keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  )

  return new Uint8Array(await crypto.subtle.sign('HMAC', key, messageBytes))
}

async function derivePrivateKey (secret) {
  const key = new TextEncoder().encode('codimd-nostr-private-key-v1')

  for (let counter = 0; counter < 256; counter++) {
    const message = new Uint8Array(secret.length + 1)
    message.set(secret)
    message[secret.length] = counter

    const candidate = await hmacSha256(key, message)
    if (secp.utils.isValidPrivateKey(candidate)) {
      return candidate
    }
  }

  throw new Error('Failed to derive a valid Nostr private key')
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

async function signLoginEvent (privateKey, challenge) {
  const pubkey = bytesToHex(secp.schnorr.getPublicKey(privateKey))
  const event = {
    pubkey: pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 22242,
    tags: [
      ['challenge', challenge],
      ['client', 'codimd-nostr-passkey']
    ],
    content: 'CodiMD Nostr passkey login'
  }

  event.id = bytesToHex(await sha256(new TextEncoder().encode(serializeEvent(event))))
  event.sig = bytesToHex(await secp.schnorr.sign(hexToBytes(event.id), privateKey))
  return event
}

async function getChallenge () {
  return $.get(`${serverurl}/auth/nostr/challenge`)
}

async function createCredential (challenge, prfSalt) {
  const userId = crypto.getRandomValues(new Uint8Array(32))
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: challenge,
      rp: {
        name: 'CodiMD Nostr'
      },
      user: {
        id: userId,
        name: 'nostr-passkey',
        displayName: 'Nostr Passkey'
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
            first: prfSalt
          }
        }
      }
    }
  })

  localStorage.setItem(credentialStorageKey, bytesToBase64URL(credential.rawId))
}

async function getPRFOutput (challenge, prfSalt, credentialId) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      allowCredentials: [{
        type: 'public-key',
        id: base64URLToBytes(credentialId)
      }],
      userVerification: 'required',
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: prfSalt
          }
        }
      }
    }
  })

  const extensionResults = assertion.getClientExtensionResults()
  if (!extensionResults.prf || !extensionResults.prf.results || !extensionResults.prf.results.first) {
    throw new Error('This browser or passkey did not return a WebAuthn PRF result')
  }

  return new Uint8Array(extensionResults.prf.results.first)
}

async function loginWithPasskey () {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('This browser does not support passkeys')
  }

  const options = await getChallenge()
  const challenge = base64URLToBytes(options.challenge)
  const prfSalt = base64URLToBytes(options.prfSalt)

  let credentialId = localStorage.getItem(credentialStorageKey)
  if (!credentialId) {
    await createCredential(challenge, prfSalt)
    credentialId = localStorage.getItem(credentialStorageKey)
  }

  const prfOutput = await getPRFOutput(challenge, prfSalt, credentialId)
  const privateKey = await derivePrivateKey(prfOutput)
  const event = await signLoginEvent(privateKey, options.challenge)

  return $.ajax({
    method: 'POST',
    url: `${serverurl}/auth/nostr/callback`,
    contentType: 'application/json',
    data: JSON.stringify({
      credentialId: credentialId,
      privateKey: bytesToHex(privateKey),
      event: event
    })
  })
}

function setStatus (selector, message, isError) {
  const status = $(selector)
  status
    .toggleClass('text-danger', !!isError)
    .toggleClass('text-success', !isError)
    .text(message)
}

function relayInput () {
  return $('.ui-nostr-relay').val() || 'wss://relay.damus.io'
}

function setupPasskeyButton () {
  $('.ui-nostr-passkey').click(async function (event) {
    event.preventDefault()
    const button = $(this)
    button.prop('disabled', true)
    setStatus('.ui-nostr-passkey-status', 'Waiting for passkey...', false)

    try {
      await loginWithPasskey()
      resetCheckAuth()
      window.location.reload()
    } catch (error) {
      setStatus('.ui-nostr-passkey-status', error.message || String(error), true)
      localStorage.removeItem(credentialStorageKey)
    } finally {
      button.prop('disabled', false)
    }
  })
}

function setupVaultButtons () {
  $('.ui-nostr-backup').click(function (event) {
    event.preventDefault()
    setStatus('.ui-nostr-vault-status', 'Publishing encrypted backup...', false)

    $.ajax({
      method: 'POST',
      url: `${serverurl}/api/nostr/backup`,
      contentType: 'application/json',
      data: JSON.stringify({
        relays: [relayInput()]
      })
    })
      .done(data => {
        const ok = data.publish.filter(result => result.ok).length
        setStatus('.ui-nostr-vault-status', `Encrypted ${data.notes} notes. Published to ${ok} relay(s).`, false)
      })
      .fail(xhr => {
        setStatus('.ui-nostr-vault-status', xhr.responseJSON ? xhr.responseJSON.message : 'Backup failed', true)
      })
  })

  $('.ui-nostr-restore').click(function (event) {
    event.preventDefault()
    setStatus('.ui-nostr-vault-status', 'Restoring encrypted backup...', false)

    $.ajax({
      method: 'POST',
      url: `${serverurl}/api/nostr/restore`,
      contentType: 'application/json',
      data: JSON.stringify({
        relays: [relayInput()]
      })
    })
      .done(data => {
        setStatus('.ui-nostr-vault-status', `Restored ${data.total} notes (${data.created} created, ${data.updated} updated).`, false)
      })
      .fail(xhr => {
        setStatus('.ui-nostr-vault-status', xhr.responseJSON ? xhr.responseJSON.message : 'Restore failed', true)
      })
  })
}

$(function () {
  setupPasskeyButton()
  setupVaultButtons()
})
