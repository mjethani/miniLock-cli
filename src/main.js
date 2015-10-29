import crypto   from 'crypto';
import fs       from 'fs';
import path     from 'path';

import zxcvbn   from 'zxcvbn';

import * as minilock from './minilock';

import {
  async, asyncThen, die, hex, home, logError, parseArgs, promisify, prompt
} from './util';

import Dictionary from './dictionary';
import Profile    from './profile';

import debug from './debug';

import { setDebugFunc } from './debug';

import version from './version';

const encryptStream = promisify(null, minilock.encryptStream);
const decryptStream = promisify(null, minilock.decryptStream);

let profile = null;

let dictionary = null;

function loadProfile() {
  try {
    profile = Profile.loadFromFile(path.resolve(home(), '.mlck',
          'profile.json'));
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error('WARNING: Profile data is corrupt.');
    }
  }
}

function loadDictionary() {
  try {
    dictionary = Dictionary.loadFromFile(path.resolve(__dirname, '..',
          'dictionary'));
  } catch (error) {
    dictionary = new Dictionary();
  }
}

function randomPassphrase(entropy) {
  if (!dictionary) {
    loadDictionary();
  }

  if (dictionary.wordCount === 0) {
    return null;
  }

  let passphrase = '';

  while (zxcvbn(passphrase).entropy < entropy) {
    // Pick a random word from the dictionary and add it to the passphrase.
    passphrase += (passphrase && ' ' || '') + dictionary.randomWord();
  }

  return passphrase;
}

function printUsage() {
  try {
    let help = fs.readFileSync(path.resolve(__dirname, '..', 'help',
          'default.help'), 'utf8');
    process.stderr.write(help.split('\n\n')[0] + '\n\n');
  } catch (error) {
  }
}

function printHelp(topic) {
  try {
    let help = fs.readFileSync(path.resolve(__dirname, '..', 'help',
          `${topic || 'default'}.help`), 'utf8');
    process.stdout.write(help);
  } catch (error) {
    printUsage();
  }
}

function readPassphrase(minEntropy=100) {
  return new Promise((resolve, reject) => {
    if (minEntropy) {
      // Display a dictionary-based random passphrase as a hint/suggestion.
      const example = randomPassphrase(minEntropy);

      if (example) {
        console.log(example);
        console.log();
      }
    }

    prompt('Passphrase (leave blank to quit): ', true)
    .then(passphrase => {
      if (passphrase === '') {
        die();
      }

      const entropy = zxcvbn(passphrase).entropy;

      if (entropy < minEntropy) {
        console.log();
        console.log(`Entropy: ${entropy}/${minEntropy}`);
        console.log();
        console.log("Let's try once more ...");
        console.log();

        resolve(readPassphrase(minEntropy));
      } else {
        resolve(passphrase);
      }
    }).catch(error => {
      reject(error);
    });
  });
}

function generateId(email, passphrase) {
  return new Promise(resolve => {
    minilock.getKeyPair(passphrase, email, keyPair => {
      resolve([ minilock.miniLockId(keyPair.publicKey), keyPair ]);
    });
  });
}

function printId(id) {
  if (process.stdout.isTTY) {
    console.log();
    console.log(`Your miniLock ID: ${id}.`);
    console.log();
  } else {
    console.log(id);
  }
}

function saveId(email, id, keyPair) {
  const data = {};

  if (keyPair) {
    // Store only the secret key. If it's compromised, you have to get a new
    // one. No other information is leaked.
    data.secret = minilock.miniLockId(keyPair.secretKey);
  } else {
    data.email = email;
    data.id = id;
  }

  Profile.saveToFile(new Profile(data), path.resolve(home(), '.mlck',
        'profile.json'));
}

function encryptFile(keyPair, file, outputFile, ids,
    { armor, includeSelf }={}) {
  return new Promise((resolve, reject) => {
    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    const outputFilename = typeof outputFile === 'string' ? outputFile
      : typeof file === 'string' ? `${file}.minilock`
      : null;

    if (typeof outputFilename === 'string') {
      debug(`Writing to file ${outputFilename}`);
    } else if (!process.stdout.isTTY) {
      debug("Writing to stdout");
    }

    if (!armor && typeof outputFilename !== 'string' && process.stdout.isTTY) {
      console.error('WARNING: Not writing output to terminal.');
    }

    const outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : armor || !process.stdout.isTTY
      ? process.stdout : null;

    encryptStream(keyPair, inputStream, outputStream, ids, {
      filename: typeof file === 'string' ? file : null,
      armor,
      includeSelf
    }).then(([ outputByteCount ]) => {
      resolve([ outputByteCount, outputFilename ]);
    }, error => {
      reject(error);
    });
  });
}

function decryptFile(keyPair, file, outputFile, { armor }={}) {
  return new Promise((resolve, reject) => {
    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    const outputFilename = typeof outputFile === 'string' ? outputFile
      : null;

    if (typeof outputFilename === 'string') {
      debug(`Writing to file ${outputFilename}`);
    } else if (!process.stdout.isTTY) {
      debug("Writing to stdout");
    }

    const outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : process.stdout;

    decryptStream(keyPair, inputStream, outputStream, {
      armor,
      envelope: {
        before: '\n--- BEGIN MESSAGE ---\n',
        after:  '\n--- END MESSAGE ---\n'
      }
    }).then(([ outputByteCount, { senderId, originalFilename }={} ]) => {
      resolve([ outputByteCount, outputFilename,
            { senderId, originalFilename } ]);
    }, error => {
      reject(error);
    });
  });
}

function handleIdCommand() {
  const defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'secret':          null,
    'anonymous':       false,
    'save':            false,
    'save-key':        false,
  };

  const shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
  };

  const options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die(`Unknown option '${options['!?'][0]}'.`);
  }

  let {
    'email':      email,
    'passphrase': passphrase,
    'secret':     secret,
    'anonymous':  anonymous,
    'save':       save,
    'save-key':   saveKey,
  } = options;

  if (options['...'][0]) {
    email = options['...'][0];
  }

  if (anonymous) {
    // Generate a random passphrase.
    email = 'Anonymous';
    passphrase = crypto.randomBytes(32).toString('base64');
  }

  if (typeof email === 'string') {
    const promise = typeof passphrase === 'string' ? asyncThen(passphrase)
      : readPassphrase();

    promise.then(passphrase => {
      if (!anonymous) {
        debug(`Using passphrase ${passphrase}`);
      }

      debug(`Generating key pair with email ${email}`
          + ` and passphrase ${passphrase}`);

      return generateId(email, passphrase);

    }).then(([ id, keyPair ]) => {
      if (saveKey) {
        saveId(email, id, keyPair);
      } else if (save) {
        saveId(email, id);
      }

      printId(id);

    }).catch(error => {
      logError(error);

      die();
    });

  } else if (typeof secret === 'string') {
    const keyPair = minilock.keyPairFromSecret(secret);

    if (saveKey) {
      saveId(null, null, keyPair);
    }

    printId(minilock.miniLockId(keyPair.publicKey));

  } else {
    loadProfile();

    if (profile && profile.id) {
      printId(profile.id);
    } else if (profile && profile.secret) {
      const keyPair = minilock.keyPairFromSecret(profile.secret);

      printId(minilock.miniLockId(keyPair.publicKey));
    } else {
      console.error('No profile data available.');
    }
  }
}

function handleEncryptCommand() {
  const defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'secret':          null,
    'file':            null,
    'output-file':     null,
    'armor':           false,
    'self':            false,
    'anonymous':       false,
  };

  const shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
    '-f': '--file=',
    '-o': '--output-file=',
    '-a': '--armor',
  };

  const options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die(`Unknown option '${options['!?'][0]}'.`);
  }

  let ids = options['...'].slice();

  let {
    'email':       email,
    'passphrase':  passphrase,
    'secret':      secret,
    'file':        file,
    'output-file': outputFile,
    'armor':       armor,
    'self':        includeSelf,
    'anonymous':   anonymous,
  } = options;

  for (let id of ids) {
    if (!minilock.validateId(id)) {
      die(`${id} doesn't look like a valid miniLock ID.`);
    }
  }

  if (typeof secret !== 'string') {
    loadProfile();

    secret = profile && profile.secret || null;
  }

  let keyPair = !anonymous && typeof email !== 'string' && secret
    && minilock.keyPairFromSecret(secret);

  if (!keyPair) {
    if (typeof email !== 'string' && profile) {
      email = profile.email;
    }

    if (!anonymous && typeof email !== 'string') {
      die('Email required.');
    }

    if (!anonymous && typeof passphrase !== 'string' && !process.stdin.isTTY) {
      die('No passphrase given; no terminal available.');
    }
  }

  const checkId = !anonymous && !keyPair && profile && email === profile.email
    && profile.id;

  const promise = anonymous || keyPair ? asyncThen()
    : typeof passphrase === 'string' ? asyncThen(passphrase)
    : readPassphrase(0);

  promise.then(passphrase => {
    if (!anonymous && !keyPair) {
      debug(`Using passphrase ${passphrase}`);
    }

    if (anonymous || !keyPair) {
      let email_ = email;
      let passphrase_ = passphrase;

      if (anonymous) {
        // Generate a random passphrase.
        email_ = 'Anonymous';
        passphrase_ = crypto.randomBytes(32).toString('base64');
      }

      debug(`Generating key pair with email ${email_}`
          + ` and passphrase ${passphrase_}`);

      return generateId(email_, passphrase_);

    } else {
      return asyncThen(minilock.miniLockId(keyPair.publicKey), keyPair);
    }

  }).then(([ id, keyPair_ ]) => {
    keyPair = keyPair_;

    debug(`Our public key is ${hex(keyPair.publicKey)}`);
    debug(`Our secret key is ${hex(keyPair.secretKey)}`);

    if (!anonymous && checkId && id !== checkId) {
      console.error(`Incorrect passphrase for ${email}`);

      die();
    }

    debug("Begin file encryption");

    return encryptFile(keyPair, file, outputFile, ids, { armor, includeSelf });

  }).then(([ outputByteCount, outputFilename ]) => {
    debug("File encryption complete");

    if (process.stdout.isTTY) {
      console.log();
      console.log(`Encrypted from`
          + ` ${minilock.miniLockId(keyPair.publicKey)}.`);
      console.log();

      if (typeof outputFilename === 'string') {
        console.log(`Wrote ${outputByteCount} bytes to ${outputFilename}`);
        console.log();
      }
    }

  }).catch(error => {
    logError(error);

    die();
  });
}

function handleDecryptCommand() {
  const defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'secret':          null,
    'file':            null,
    'output-file':     null,
    'armor':           false,
  };

  const shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
    '-f': '--file=',
    '-o': '--output-file=',
    '-a': '--armor',
  };

  const options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die(`Unknown option '${options['!?'][0]}'.`);
  }

  let {
    'email':       email,
    'passphrase':  passphrase,
    'secret':      secret,
    'file':        file,
    'output-file': outputFile,
    'armor':       armor,
  } = options;

  if (typeof secret !== 'string') {
    loadProfile();

    secret = profile && profile.secret || null;
  }

  let keyPair = typeof email !== 'string' && secret
    && minilock.keyPairFromSecret(secret);

  if (!keyPair) {
    if (typeof email !== 'string' && profile) {
      email = profile.email;
    }

    if (typeof email !== 'string') {
      die('Email required.');
    }

    if (typeof passphrase !== 'string' && !process.stdin.isTTY) {
      die('No passphrase given; no terminal available.');
    }
  }

  const checkId = !keyPair && profile && email === profile.email && profile.id;

  const promise = keyPair ? asyncThen()
    : typeof passphrase === 'string' ? asyncThen(passphrase)
    : readPassphrase(0);

  promise.then(passphrase => {
    if (!keyPair) {
      debug(`Using passphrase ${passphrase}`);
    }

    if (!keyPair) {
      debug(`Generating key pair with email ${email}`
          + ` and passphrase ${passphrase}`);

      return generateId(email, passphrase);

    } else {
      return asyncThen(minilock.miniLockId(keyPair.publicKey), keyPair);
    }

  }).then(([ id, keyPair_ ]) => {
    keyPair = keyPair_;

    debug(`Our public key is ${hex(keyPair.publicKey)}`);
    debug(`Our secret key is ${hex(keyPair.secretKey)}`);

    if (checkId && id !== checkId) {
      console.error(`Incorrect passphrase for ${email}`);

      die();
    }

    debug("Begin file decryption");

    return decryptFile(keyPair, file, outputFile, { armor });

  }).then(([ outputByteCount, outputFilename,
        { senderId, originalFilename }={} ]) => {
    debug("File decryption complete");

    if (process.stdout.isTTY) {
      console.log();
      console.log(`Message from ${senderId}.`);
      console.log();

      if (originalFilename) {
        console.log(`Original filename: ${originalFilename}`);
        console.log();
      }

      if (typeof outputFilename === 'string') {
        console.log(`Wrote ${outputByteCount} bytes to ${outputFilename}`);
        console.log();
      }
    }

  }).catch(error => {
    if (error === minilock.ERR_PARSE_ERROR) {
      console.error('The file appears corrupt.');
    } else if (error === minilock.ERR_UNSUPPORTED_VERSION) {
      console.error('This miniLock version is not supported.');
    } else if (error === minilock.ERR_NOT_A_RECIPIENT) {
      console.error(`The message is not intended for`
          + ` ${minilock.miniLockId(keyPair.publicKey)}.`);
    } else if (error === minilock.ERR_MESSAGE_INTEGRITY_CHECK_FAILED) {
      console.error('The message is corrupt.');
    } else {
      logError(error);
    }

    die();
  });
}

function handleHelpCommand() {
  printHelp(process.argv[2] === 'help' && process.argv[3]);
}

function handleVersionCommand() {
  console.log(`miniLock-cli v${version}`);
}

function handleLicenseCommand() {
  process.stdout.write(fs.readFileSync(path.resolve(__dirname, '..',
          'LICENSE')));
}

export function run() {
  if (process.argv[2] === '--debug') {
    process.argv.splice(2, 1);

    setDebugFunc((...rest) => {
      console.error(...rest);
    });
  }

  const command = process.argv[2];

  switch (command) {
  case 'id':
    handleIdCommand();
    break;
  case 'encrypt':
    handleEncryptCommand();
    break;
  case 'decrypt':
    handleDecryptCommand();
    break;
  case 'help':
  case '--help':
  case '-h':
  case '-?':
    handleHelpCommand();
    break;
  case 'version':
  case '--version':
  case '-V':
    handleVersionCommand();
    break;
  case 'license':
  case '--license':
    handleLicenseCommand();
    break;
  default:
    printUsage();
    die();
  }
}

function main() {
  run();
}

if (require.main === module) {
  main();
}

// vim: et ts=2 sw=2
