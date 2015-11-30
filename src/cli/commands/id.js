import crypto from 'crypto'
import path   from 'path'

import * as minilock from '../../module'

import { die, home, logError, parseArgs } from '../../common/util'

import debug from '../../common/debug'

import { Profile } from '../objects/profile'

import { generateId } from '../helpers/id'
import { readPassphrase } from '../helpers/passphrase'
import { getProfile } from '../helpers/profile'
import { handleUnknownOption } from '../helpers/unknown'

function printId(id) {
  if (process.stdout.isTTY) {
    console.log()
    console.log(`Your miniLock ID: ${id}.`)
    console.log()
  } else {
    console.log(id)
  }
}

function saveId(email, id, keyPair) {
  const data = {}

  if (keyPair) {
    // Store only the secret key. If it's compromised, you have to get a new
    // one. No other information is leaked.
    data.secret = minilock.miniLockId(keyPair.secretKey)
  } else {
    data.email = email
    data.id = id
  }

  Profile.saveToFile(new Profile(data), path.resolve(home(), '.mlck',
        'profile.json'))
}

export default function () {
  const defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'secret':          null,
    'anonymous':       false,
    'save':            false,
    'save-key':        false,
  }

  const shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
  }

  const options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts)

  if (options['!?'].length > 0) {
    handleUnknownOption(options['!?'][0], Object.keys(defaultOptions))
  }

  let {
    'email':      email,
    'passphrase': passphrase,
    'secret':     secret,
    'anonymous':  anonymous,
    'save':       save,
    'save-key':   saveKey,
  } = options

  if (options['...'][0]) {
    email = options['...'][0]
  }

  if (anonymous) {
    // Generate a random passphrase.
    email = 'Anonymous'
    passphrase = crypto.randomBytes(32).toString('base64')
  }

  if (typeof email === 'string') {
    const promise = typeof passphrase === 'string'
      ? Promise.resolve(passphrase)
      : readPassphrase()

    promise.then(passphrase => {
      if (!anonymous) {
        debug(`Using passphrase ${passphrase}`)
      }

      debug(`Generating key pair with email ${email}` +
          ` and passphrase ${passphrase}`)

      return generateId(email, passphrase)

    }).then(([ id, keyPair ]) => {
      if (saveKey) {
        saveId(email, id, keyPair)
      } else if (save) {
        saveId(email, id)
      }

      printId(id)

    }).catch(error => {
      logError(error)

      die()
    })

  } else if (typeof secret === 'string') {
    const keyPair = minilock.keyPairFromSecret(secret)

    if (saveKey) {
      saveId(null, null, keyPair)
    }

    printId(minilock.miniLockId(keyPair.publicKey))

  } else {
    const profile = getProfile()

    if (profile && profile.id) {
      printId(profile.id)
    } else if (profile && profile.secret) {
      const keyPair = minilock.keyPairFromSecret(profile.secret)

      printId(minilock.miniLockId(keyPair.publicKey))
    } else {
      console.error('No profile data available.')
    }
  }
}

// vim: et ts=2 sw=2
