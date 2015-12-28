import path from 'path'

import zxcvbn from 'zxcvbn'

import { prompt } from '../../common/util'

import Dictionary from '../objects/dictionary'

let dictionary = null

function loadDictionary() {
  try {
    dictionary = Dictionary.loadFromFile(path.resolve(__dirname, '..', '..',
          '..', 'dictionary'))
  } catch (error) {
    dictionary = new Dictionary()
  }
}

function randomPassphrase(entropy) {
  if (!dictionary) {
    loadDictionary()
  }

  if (dictionary.wordCount === 0) {
    return null
  }

  let passphrase = ''

  while (zxcvbn(passphrase).entropy < entropy) {
    // Pick a random word from the dictionary and add it to the passphrase.
    passphrase += (passphrase && ' ' || '') + dictionary.randomWord()
  }

  return passphrase
}

export function readPassphrase(minEntropy = 100) {
  return new Promise((resolve, reject) => {
    if (minEntropy) {
      // Display a dictionary-based random passphrase as a hint/suggestion.
      const example = randomPassphrase(minEntropy)

      if (example) {
        console.log(example)
        console.log()
      }
    }

    prompt('Passphrase (leave blank to quit): ', true)
    .then(passphrase => {
      if (passphrase === '') {
        die()
      }

      const entropy = zxcvbn(passphrase).entropy

      if (entropy < minEntropy) {
        console.log()
        console.log(`Entropy: ${entropy}/${minEntropy}`)
        console.log()
        console.log('Let\'s try once more ...')
        console.log()

        resolve(readPassphrase(minEntropy))
      } else {
        resolve(passphrase)
      }
    }).catch(error => {
      reject(error)
    })
  })
}

// vim: et ts=2 sw=2
