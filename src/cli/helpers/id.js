import * as minilock from '../../module'

export function generateId(email, passphrase) {
  return new Promise(resolve => {
    minilock.getKeyPair(passphrase, email, keyPair => {
      resolve([ minilock.miniLockId(keyPair.publicKey), keyPair ])
    })
  })
}

// vim: et ts=2 sw=2
