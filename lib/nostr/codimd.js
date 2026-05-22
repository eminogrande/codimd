'use strict'

const { DEFAULT_VAULT_IDENTIFIER, VAULT_KIND, createVault } = require('./vault')

async function exportUserVault (models, userId, options) {
  options = options || {}
  const user = await models.User.findOne({
    where: {
      id: userId
    }
  })

  if (!user) {
    throw new Error('User not found')
  }

  const notes = await models.Note.findAll({
    where: {
      ownerId: userId
    },
    order: [['updatedAt', 'ASC']]
  })

  return createVault(user, notes, options)
}

async function restoreUserVault (models, vault, userId) {
  if (!vault || vault.app !== 'codimd' || !Array.isArray(vault.notes)) {
    throw new Error('Invalid CodiMD vault')
  }

  const user = await models.User.findOne({
    where: {
      id: userId
    }
  })

  if (!user) {
    throw new Error('Restore target user not found')
  }

  let created = 0
  let updated = 0

  for (const note of vault.notes) {
    const values = {
      ownerId: userId,
      shortid: note.shortid,
      alias: note.alias,
      permission: note.permission || 'private',
      title: note.title || '',
      content: note.content || '',
      authorship: note.authorship || [],
      lastchangeAt: note.lastchangeAt ? new Date(note.lastchangeAt) : null,
      savedAt: note.savedAt ? new Date(note.savedAt) : null,
      createdAt: note.createdAt ? new Date(note.createdAt) : undefined,
      updatedAt: note.updatedAt ? new Date(note.updatedAt) : undefined
    }

    const existing = await models.Note.findOne({
      where: {
        id: note.id
      }
    })

    if (existing) {
      await existing.update(values)
      updated++
    } else {
      await models.Note.create(Object.assign({ id: note.id }, values))
      created++
    }
  }

  return {
    created: created,
    updated: updated,
    total: vault.notes.length
  }
}

function vaultFilter (pubkey, identifier) {
  return {
    kinds: [VAULT_KIND],
    authors: [pubkey],
    '#d': [identifier || DEFAULT_VAULT_IDENTIFIER],
    limit: 5
  }
}

module.exports = {
  exportUserVault,
  restoreUserVault,
  vaultFilter
}
