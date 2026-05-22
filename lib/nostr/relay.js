'use strict'

const WebSocket = require('ws')

function normalizeRelays (relays) {
  if (!Array.isArray(relays)) relays = [relays]
  return relays.filter(Boolean)
}

function publishEvent (relay, event, options) {
  options = options || {}
  const timeout = options.timeout || 8000

  return new Promise(resolve => {
    let settled = false
    const ws = new WebSocket(relay)
    const timer = setTimeout(() => finish({
      relay: relay,
      ok: false,
      message: 'timeout'
    }), timeout)

    function finish (result) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        ws.close()
      } catch (err) {}
      resolve(result)
    }

    ws.on('open', () => {
      ws.send(JSON.stringify(['EVENT', event]))
    })

    ws.on('message', data => {
      let message
      try {
        message = JSON.parse(data.toString())
      } catch (err) {
        return
      }

      if (message[0] === 'OK' && message[1] === event.id) {
        finish({
          relay: relay,
          ok: !!message[2],
          message: message[3] || ''
        })
      }
    })

    ws.on('error', err => finish({
      relay: relay,
      ok: false,
      message: err.message
    }))

    ws.on('close', () => finish({
      relay: relay,
      ok: false,
      message: 'closed before OK'
    }))
  })
}

function publishToRelays (relays, event, options) {
  return Promise.all(normalizeRelays(relays).map(relay => publishEvent(relay, event, options)))
}

function fetchLatestReplaceable (relays, filter, options) {
  options = options || {}
  const timeout = options.timeout || 8000
  const subscription = 'codimd-nostr-' + Math.random().toString(16).slice(2)
  const normalizedRelays = normalizeRelays(relays)

  return new Promise(resolve => {
    const events = []
    let pending = normalizedRelays.length

    if (pending === 0) return resolve(null)

    function done () {
      pending--
      if (pending > 0) return

      events.sort((a, b) => {
        if (a.created_at !== b.created_at) return b.created_at - a.created_at
        return String(b.id).localeCompare(String(a.id))
      })
      resolve(events[0] || null)
    }

    normalizedRelays.forEach(relay => {
      const ws = new WebSocket(relay)
      let settled = false
      const timer = setTimeout(finish, timeout)

      function finish () {
        if (settled) return
        settled = true
        clearTimeout(timer)
        try {
          ws.close()
        } catch (err) {}
        done()
      }

      ws.on('open', () => {
        ws.send(JSON.stringify(['REQ', subscription, filter]))
      })

      ws.on('message', data => {
        let message
        try {
          message = JSON.parse(data.toString())
        } catch (err) {
          return
        }

        if (message[0] === 'EVENT' && message[1] === subscription) {
          events.push(message[2])
        } else if (message[0] === 'EOSE' && message[1] === subscription) {
          finish()
        }
      })

      ws.on('error', finish)
      ws.on('close', finish)
    })
  })
}

module.exports = {
  fetchLatestReplaceable,
  publishEvent,
  publishToRelays
}
