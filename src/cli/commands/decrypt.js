import fs from 'fs'

import * as miniLock from '../../module'

import { die, hex, logError, parseArgs } from '../../common/util'

import debug from '../../common/debug'

import { generateId } from '../helpers/id'
import { readPassphrase } from '../helpers/passphrase'
import { getProfile } from '../helpers/profile'
import { handleUnknownOption } from '../helpers/unknown'

function decryptFile(keyPair, file, outputFile, { armor }={}) {
  return new Promise((resolve, reject) => {
    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...')
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin

    const outputFilename = typeof outputFile === 'string' ? outputFile
      : null

    if (typeof outputFilename === 'string') {
      debug(`Writing to file ${outputFilename}`)
    } else if (!process.stdout.isTTY) {
      debug('Writing to stdout')
    }

    const outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : process.stdout

    miniLock.decryptStream(keyPair, inputStream, outputStream, {
      armor,
      envelope: {
        before: '\n--- BEGIN MESSAGE ---\n',
        after:  '\n--- END MESSAGE ---\n'
      }
    }, (error, outputByteCount, { senderId, originalFilename }={}) => {
      if (error) {
        reject(error)
      } else {
        resolve([ outputByteCount, outputFilename,
              { senderId, originalFilename } ])
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

  let {
    'email':       email,
    'passphrase':  passphrase,
    'secret':      secret,
    'file':        file,
    'output-file': outputFile,
    'armor':       armor,
  } = options

  let profile = null

  if (typeof secret !== 'string') {
    profile = getProfile()

    secret = profile && profile.secret || null
  }

  let keyPair = typeof email !== 'string' && secret &&
    miniLock.keyPairFromSecret(secret)

  if (!keyPair) {
    if (typeof email !== 'string' && profile) {
      email = profile.email
    }

    if (typeof email !== 'string') {
      die('Email required.')
    }

    if (typeof passphrase !== 'string' && !process.stdin.isTTY) {
      die('No passphrase given; no terminal available.')
    }
  }

  const checkId = !keyPair && profile && email === profile.email && profile.id

  const promise = keyPair ? Promise.resolve()
    : typeof passphrase === 'string' ? Promise.resolve(passphrase)
    : readPassphrase(0)

  promise.then(passphrase => {
    if (!keyPair) {
      debug(`Using passphrase ${passphrase}`)
    }

    if (!keyPair) {
      debug(`Generating key pair with email ${email}` +
          ` and passphrase ${passphrase}`)

      return generateId(email, passphrase)

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

    if (checkId && id !== checkId) {
      console.error(`Incorrect passphrase for ${email}`)

      die()
    }

    debug('Begin file decryption')

    return decryptFile(keyPair, file, outputFile, { armor })

  }).then(([ outputByteCount, outputFilename,
        { senderId, originalFilename }={} ]) => {
    debug('File decryption complete')

    if (process.stdout.isTTY) {
      console.log()
      console.log(`Message from ${senderId}.`)
      console.log()

      if (originalFilename) {
        console.log(`Original filename: ${originalFilename}`)
        console.log()
      }

      if (typeof outputFilename === 'string') {
        console.log(`Wrote ${outputByteCount} bytes to ${outputFilename}`)
        console.log()
      }
    }

  }).catch(error => {
    if (error === miniLock.ERR_PARSE_ERROR) {
      console.error('The file appears corrupt.')
    } else if (error === miniLock.ERR_UNSUPPORTED_VERSION) {
      console.error('This miniLock version is not supported.')
    } else if (error === miniLock.ERR_NOT_A_RECIPIENT) {
      console.error(`The message is not intended for` +
          ` ${miniLock.miniLockId(keyPair.publicKey)}.`)
    } else if (error === miniLock.ERR_MESSAGE_INTEGRITY_CHECK_FAILED) {
      console.error('The message is corrupt.')
    } else {
      logError(error)
    }

    die()
  })
}

// vim: et ts=2 sw=2
