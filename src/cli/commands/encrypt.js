import crypto from 'crypto'
import fs     from 'fs'
import path   from 'path'

import * as miniLock from '../../module'

import { die, hex, logError, parseArgs } from '../../common/util'

import debug from '../../common/debug'

import { generateId } from '../helpers/id'
import { readPassphrase } from '../helpers/passphrase'
import { getProfile } from '../helpers/profile'
import { handleUnknownOption } from '../helpers/unknown'

function encryptFile(keyPair, file, outputFile, ids,
    { armor, includeSelf } = {}) {
  return new Promise((resolve, reject) => {
    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...')
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin

    const outputFilename = typeof outputFile === 'string' ? outputFile
      : typeof file === 'string' ? `${file}.minilock`
      : null

    if (typeof outputFilename === 'string') {
      debug(`Writing to file ${outputFilename}`)
    } else if (!process.stdout.isTTY) {
      debug('Writing to stdout')
    }

    if (!armor && typeof outputFilename !== 'string' && process.stdout.isTTY) {
      console.error('WARNING: Not writing output to terminal.')
    }

    const outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : armor || !process.stdout.isTTY
      ? process.stdout : null

    miniLock.encryptStream(keyPair, inputStream, outputStream, ids, {
      filename: typeof file === 'string' ? path.basename(file) : null,
      armor,
      includeSelf
    }, (error, outputByteCount) => {
      if (error) {
        reject(error)
      } else {
        resolve([ outputByteCount, outputFilename ])
      }
    })
  })
}

export function execute(args) {
  const defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'secret':          null,
    'file':            null,
    'output-file':     null,
    'armor':           false,
    'self':            false,
    'anonymous':       false,
  }

  const shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
    '-f': '--file=',
    '-o': '--output-file=',
    '-a': '--armor',
  }

  const options = parseArgs(args, defaultOptions, shortcuts)

  if (options['!?'].length > 0) {
    handleUnknownOption(options['!?'][0], Object.keys(defaultOptions))
  }

  let ids = options['...'].slice()

  let {
    'email':       email,
    'passphrase':  passphrase,
    'secret':      secret,
    'file':        file,
    'output-file': outputFile,
    'armor':       armor,
    'self':        includeSelf,
    'anonymous':   anonymous,
  } = options

  for (let id of ids) {
    if (!miniLock.validateId(id)) {
      die(`${id} doesn't look like a valid miniLock ID.`)
    }
  }

  let profile = null

  if (typeof secret !== 'string') {
    profile = getProfile()

    secret = profile && profile.secret || null
  }

  let keyPair = !anonymous && typeof email !== 'string' && secret &&
    miniLock.keyPairFromSecret(secret)

  if (!keyPair) {
    if (typeof email !== 'string' && profile) {
      email = profile.email
    }

    if (!anonymous && typeof email !== 'string') {
      die('Email required.')
    }

    if (!anonymous && typeof passphrase !== 'string' && !process.stdin.isTTY) {
      die('No passphrase given; no terminal available.')
    }
  }

  const checkId = !anonymous && !keyPair && profile &&
    email === profile.email && profile.id

  const promise = anonymous || keyPair ? Promise.resolve()
    : typeof passphrase === 'string' ? Promise.resolve(passphrase)
    : readPassphrase(0)

  promise.then(passphrase => {
    if (!anonymous && !keyPair) {
      debug(`Using passphrase ${passphrase}`)
    }

    if (anonymous || !keyPair) {
      let email_ = email
      let passphrase_ = passphrase

      if (anonymous) {
        // Generate a random passphrase.
        email_ = 'Anonymous'
        passphrase_ = crypto.randomBytes(32).toString('base64')
      }

      debug(`Generating key pair with email ${email_}` +
          ` and passphrase ${passphrase_}`)

      return generateId(email_, passphrase_)

    } else {
      return Promise.resolve([
        miniLock.miniLockId(keyPair.publicKey),
        keyPair
      ])
    }

  }).then(([ id, keyPair_ ]) => {
    keyPair = keyPair_

    debug(`Our public key is ${hex(keyPair.publicKey)}`)
    debug(`Our secret key is ${hex(keyPair.secretKey)}`)

    if (!anonymous && checkId && id !== checkId) {
      console.error(`Incorrect passphrase for ${email}`)

      die()
    }

    debug('Begin file encryption')

    return encryptFile(keyPair, file, outputFile, ids, { armor, includeSelf })

  }).then(([ outputByteCount, outputFilename ]) => {
    debug('File encryption complete')

    if (process.stdout.isTTY) {
      console.log()
      console.log(`Encrypted from` +
          ` ${miniLock.miniLockId(keyPair.publicKey)}.`)
      console.log()

      if (typeof outputFilename === 'string') {
        console.log(`Wrote ${outputByteCount} bytes to ${outputFilename}`)
        console.log()
      }
    }

  }).catch(error => {
    logError(error)

    die()
  })
}

// vim: et ts=2 sw=2
