import * as miniLock from '../../module'

export function generateId(email, passphrase) {
  return new Promise(resolve => {
    miniLock.getKeyPair(passphrase, email, keyPair => {
      resolve([ miniLock.miniLockId(keyPair.publicKey), keyPair ])
    })
  })
}

// vim: et ts=2 sw=2
