import fs   from 'fs'
import path from 'path'

import test from 'tape'

import * as minilock from '../module'

import { arrayCompare, streamHash } from '../build/util'

import { BufferStream } from '../build/stream'

const aliceEmail = 'alice@example.com'
const alicePassphrase = 'hello'

const aliceKeyPair = {
  secretKey: new Uint8Array([
    105, 153, 192,  70,  95, 105, 180, 199,
    169, 151,  67, 224, 178, 224, 209,  69,
    234, 147, 238,  66, 127, 152,  14,  32,
     55, 171,  14, 191,   7, 133,  47, 255
  ]),
  publicKey: new Uint8Array([
     65,  94,   4,  73,  20, 126, 121, 243,
    226,  39, 222,  88,   2, 148, 174,  15,
     86,   5,  90, 172, 113, 187, 237, 122,
      2,  20, 169,  43, 215,  95,  95,   0
  ])
}

const aliceId = 'LRFbCrhCeN2uVCdDXd2bagoCM1fVcGvUzwhfVdqfyVuhi'

const aliceSecret = 'YNTSLs54CD6bDBku65anRRbZDRUbQmhVifKjd9roWidCW'

const bobEmail = 'bob@example.com'
const bobPassphrase = 'puff magic dragon sea frolic autumn mist lee'

const bobKeyPair = {
  secretKey: new Uint8Array([
    227,  80, 170,  57,  30,  98, 123, 180,
      6,  29, 163,  64,  78, 131, 236, 241,
    251,  99, 238,  12, 101, 147, 250, 187,
     64, 114,  65, 232, 207,  81,  40, 116
  ]),
  publicKey: new Uint8Array([
    132, 203, 156,  65,  68, 203, 196, 170,
    132, 106, 255, 242,  87, 133,  19, 253,
     86,  60,  32, 106,  98, 164,  96, 229,
    192, 193,  93, 203, 173,  41, 155, 117
  ])
}

const bobId = 'gT1csvpmQDNRQSMkqc1Sz7ZWYzGZkmedPKEpgqjdNTy7Y'

const bobSecret = '2AXYnJ54waq3c1wxpGJoVqrWDN1j1HHbDfbp7HSkDyfj2A'

test('Generate a key pair from an email address and a passphrase', t => {
  minilock.getKeyPair(alicePassphrase, aliceEmail, keyPair => {
    t.ok(arrayCompare(keyPair.secretKey, aliceKeyPair.secretKey),
        'Secret key should be correct')
    t.ok(arrayCompare(keyPair.publicKey, aliceKeyPair.publicKey),
        'Public key should be correct')

    t.end()
  })
})

test('Convert a public key into a miniLock ID', t => {
  const id = minilock.miniLockId(aliceKeyPair.publicKey)

  t.ok(id === aliceId, 'ID should be correct')

  t.end()
})

test('Convert a miniLock ID into a key', t => {
  const key = minilock.keyFromId(aliceId)

  t.ok(arrayCompare(key, aliceKeyPair.publicKey), 'Key should be correct')

  t.end()
})

test('Convert a secret into a key pair', t => {
  const keyPair = minilock.keyPairFromSecret(aliceSecret)

  t.ok(arrayCompare(keyPair.secretKey, aliceKeyPair.secretKey),
      'Secret key should be correct')
  t.ok(arrayCompare(keyPair.publicKey, aliceKeyPair.publicKey),
      'Public key should be correct')

  t.end()
})

test('Encrypt a message to self and decrypt it', t => {
  const message = 'This is a secret.'

  const encrypted = new BufferStream()

  minilock.encryptStream(aliceKeyPair, new BufferStream(message), encrypted,
      [], { includeSelf: true },
      (error, outputByteCount) => {
    if (error) {
      t.comment(`ERROR: ${error.toString()}`)

      t.fail('There should be no error')

      t.end()
      return
    }

    t.ok(outputByteCount === 979, 'Output byte count should be correct')

    const decrypted = new BufferStream()

    decrypted.setEncoding('utf8')

    minilock.decryptStream(aliceKeyPair, encrypted, decrypted, {},
        (error, outputByteCount, { senderId }={}) => {
      if (error) {
        t.comment(`ERROR: ${error.toString()}`)

        t.fail('There should be no error')

        t.end()
        return
      }

      t.ok(senderId === aliceId, 'Sender ID should be correct')
      t.ok(decrypted.read() === message, 'Decrypted should match message')

      t.end()
    })
  })
})

test('Encrypt a message with the armor option and decrypt it', t => {
  const message = 'This is a secret.'

  const encrypted = new BufferStream()

  minilock.encryptStream(aliceKeyPair, new BufferStream(message), encrypted,
      [ bobId ], { armor: true },
      (error, outputByteCount) => {
    if (error) {
      t.comment(`ERROR: ${error.toString()}`)

      t.fail('There should be no error')

      t.end()
      return
    }

    t.ok(outputByteCount === 1418, 'Output byte count should be correct')

    const decrypted = new BufferStream()

    decrypted.setEncoding('utf8')

    minilock.decryptStream(bobKeyPair, encrypted, decrypted, { armor: true },
        (error, outputByteCount, { senderId }={}) => {
      if (error) {
        t.comment(`ERROR: ${error.toString()}`)

        t.fail('There should be no error')

        t.end()
        return
      }

      t.ok(senderId === aliceId, 'Sender ID should be correct')
      t.ok(decrypted.read() === message, 'Decrypted should match message')

      t.end()
    })
  })
})

test('Encrypt a file and decrypt it', t => {
  const filename = 'pg1661.txt'

  const fileDigest = '242ec73a70f0a03dcbe007e32038e7deeaee004aaec9a09a07fa322743440fa8'

  const encrypted = new BufferStream(null, null, { highWaterMark: 0x100000 })

  minilock.encryptStream(aliceKeyPair,
      fs.createReadStream(path.resolve('files', filename)), encrypted,
      [ bobId ], { filename },
      (error, outputByteCount) => {
    if (error) {
      t.comment(`ERROR: ${error.toString()}`)

      t.fail('There should be no error')

      t.end()
      return
    }

    t.ok(outputByteCount === 642355, 'Output byte count should be correct')

    const decrypted = new BufferStream(null, null, { highWaterMark: 0x100000 })

    minilock.decryptStream(bobKeyPair, encrypted, decrypted, {},
        (error, outputByteCount, { senderId, originalFilename }={}) => {
      if (error) {
        t.comment(`ERROR: ${error.toString()}`)

        t.fail('There should be no error')

        t.end()
        return
      }

      t.ok(senderId === aliceId, 'Sender ID should be correct')
      t.ok(originalFilename === filename,
          'Original filename should match filename')

      streamHash(decrypted, 'sha256', { encoding: 'hex' }).then(digest => {
        t.ok(digest === fileDigest, 'Digest should match file digest')

        t.end()
      }).catch(error => {
        t.comment(`ERROR: ${error.toString()}`)

        t.fail('There should be no error')

        t.end()
      })
    })
  })
})

// vim: et ts=2 sw=2
