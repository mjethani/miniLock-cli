import fs       from 'fs';
import path     from 'path';

import nacl     from 'tweetnacl';
import zxcvbn   from 'zxcvbn';

import * as minilock from './minilock';

import { async, die, hex, home, logError, parseArgs, prompt } from './util';

import debug from './debug';

import { setDebugFunc } from './debug';

import version from './version';

let profile = null;

let dictionary = null;

function loadProfile() {
  const profileDirectory = path.resolve(home(), '.mlck');

  let data = null;

  try {
    data = fs.readFileSync(path.resolve(profileDirectory, 'profile.json'),
        { encoding: 'utf8' });
  } catch (error) {
  }

  if (data) {
    try {
      profile = JSON.parse(data);
    } catch (error) {
      console.error('WARNING: Profile data is corrupt.');
    }
  }
}

function loadDictionary() {
  try {
    let data = fs.readFileSync(path.resolve(__dirname, '..', 'dictionary'),
        { encoding: 'utf8' });

    dictionary = data.split('\n').map(line =>
      // Trim spaces and strip out comments.
      line.replace(/^\s*|\s*$/g, '').replace(/^#.*/, '')
    ).filter(line =>
      // Skip blank lines.
      line !== ''
    );
  } catch (error) {
    dictionary = [];
  }
}

function randomPassphrase(entropy) {
  if (!dictionary) {
    loadDictionary();
  }

  if (dictionary.length === 0) {
    return null;
  }

  let passphrase = '';

  while (zxcvbn(passphrase).entropy < entropy) {
    // Pick a random word from the dictionary and add it to the passphrase.
    const randomNumber = new Buffer(nacl.randomBytes(2)).readUInt16BE();
    const index = Math.floor((randomNumber / 0x10000) * dictionary.length);

    passphrase += (passphrase && ' ' || '') + dictionary[index];
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

function readPassphrase(passphrase, minEntropy, callback) {
  const defaultMinEntropy = 100;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    minEntropy = defaultMinEntropy;
    passphrase = null;
  } else if (typeof minEntropy === 'function') {
    callback = minEntropy;
    minEntropy = defaultMinEntropy;
  }

  if (typeof passphrase === 'string') {
    async(() => {
      callback(null, passphrase)
    });
  } else {
    if (minEntropy) {
      // Display a dictionary-based random passphrase as a hint/suggestion.
      const example = randomPassphrase(minEntropy);
      if (example) {
        console.log(example);
        console.log();
      }
    }

    prompt('Passphrase (leave blank to quit): ', true,
        (error, passphrase) => {
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

        readPassphrase(null, callback);
      } else {
        callback(error, passphrase);
      }
    });
  }
}

function generateId(email, passphrase, callback) {
  minilock.getKeyPair(passphrase, email,
      keyPair => callback(null, minilock.miniLockId(keyPair.publicKey),
          keyPair));
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
  const profileDirectory = path.resolve(home(), '.mlck');

  try {
    fs.mkdirSync(profileDirectory);
  } catch (error) {
    if (error.code !== 'EEXIST') {
      throw error;
    }
  }

  const profile = { version: '0.1' };

  if (keyPair) {
    // Store only the secret key. If it's compromised, you have to get a new
    // one. No other information is leaked.
    profile.secret = minilock.miniLockId(keyPair.secretKey);
  } else {
    profile.email = email;
    profile.id = id;
  }

  fs.writeFileSync(path.resolve(profileDirectory, 'profile.json'),
      JSON.stringify(profile));
}

function encryptFile(ids, email, passphrase, file, outputFile, armor,
    includeSelf, anonymous, checkId, keyPair, callback) {
  debug("Begin file encryption");

  let keyPairFunc = null;

  if (anonymous || !keyPair) {
    if (anonymous) {
      // Generate a random passphrase.
      email = 'Anonymous';
      passphrase = new Buffer(nacl.randomBytes(32)).toString('base64');
    }

    debug(`Generating key pair with email ${email}`
        + ` and passphrase ${passphrase}`);

    keyPairFunc = callback => {
      minilock.getKeyPair(passphrase, email, callback);
    };
  } else {
    keyPairFunc = callback => {
      async(() => {
        callback(keyPair);
      });
    };
  }

  keyPairFunc(keyPair => {
    debug(`Our public key is ${hex(keyPair.publicKey)}`);
    debug(`Our secret key is ${hex(keyPair.secretKey)}`);

    if (!anonymous && checkId
        && minilock.miniLockId(keyPair.publicKey) !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

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

    minilock.encryptStream(keyPair, inputStream, outputStream, ids, {
      filename: typeof file === 'string' ? file : null,
      armor,
      includeSelf
    }, (error, outputByteCount) => {
      if (!error) {
        debug("File encryption complete");
      }

      callback(error, keyPair, outputByteCount, outputFilename);
    });
  });
}

function decryptFile(email, passphrase, file, outputFile, armor, checkId,
    keyPair, callback) {
  debug("Begin file decryption");

  let keyPairFunc = null;

  if (!keyPair) {
    debug(`Generating key pair with email ${email}`
        + ` and passphrase ${passphrase}`);

    keyPairFunc = callback => {
      minilock.getKeyPair(passphrase, email, callback);
    };
  } else {
    keyPairFunc = callback => {
      async(() => {
        callback(keyPair);
      });
    };
  }

  keyPairFunc(keyPair => {
    debug(`Our public key is ${hex(keyPair.publicKey)}`);
    debug(`Our secret key is ${hex(keyPair.secretKey)}`);

    if (checkId && minilock.miniLockId(keyPair.publicKey) !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

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

    minilock.decryptStream(keyPair, inputStream, outputStream, {
      armor
    }, (error, outputByteCount, { senderId, originalFilename }={}) => {
      if (!error) {
        debug("File decryption complete");
      }

      callback(error, keyPair, outputByteCount, outputFilename, senderId,
          originalFilename);
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
    '-P': '--passphrase='
  };

  const options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die(`Unknown option '${options['!?'][0]}'.`);
  }

  let email = options['...'][0] || options.email;
  let passphrase = options.passphrase;

  let secret = options.secret;

  let anonymous = options.anonymous;

  let save = options.save;
  let saveKey = options['save-key'];

  let keyPair = null;

  if (anonymous) {
    // Generate a random passphrase.
    email = 'Anonymous';
    passphrase = new Buffer(nacl.randomBytes(32)).toString('base64');
  }

  if (typeof email !== 'string' || (!anonymous && typeof secret === 'string')) {
    if (typeof secret !== 'string') {
      loadProfile();

      secret = profile && profile.secret || null;
    }

    if (profile && profile.id) {
      printId(profile.id);
    } else if (secret) {
      keyPair = minilock.keyPairFromSecret(secret);

      if (saveKey) {
        saveId(null, null, keyPair);
      }

      printId(minilock.miniLockId(keyPair.publicKey));
    } else {
      console.error('No profile data available.');
    }

    return;
  }

  readPassphrase(passphrase, (error, passphrase) => {
    if (error) {
      logError(error);
      die();
    }

    debug(`Using passphrase ${passphrase}`);

    generateId(email, passphrase, (error, id, keyPair) => {
      if (error) {
        logError(error);
        die();
      }

      if (saveKey) {
        saveId(email, id, keyPair);
      } else if (save) {
        saveId(email, id);
      }

      printId(id);
    });
  });
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

  let email = options.email;
  let passphrase = options.passphrase;

  let secret = options.secret;

  let file = options.file;
  let outputFile = options['output-file'];

  let armor = options.armor;

  let includeSelf = options['self'];

  let anonymous = options.anonymous;

  ids.forEach(id => {
    if (!minilock.validateId(id)) {
      die(`${id} doesn't look like a valid miniLock ID.`);
    }
  });

  if (typeof secret !== 'string') {
    loadProfile();

    secret = profile && profile.secret || null;
  }

  let keyPair = !anonymous && typeof email !== 'string'
    && secret && minilock.keyPairFromSecret(secret);

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

  readPassphrase(anonymous || keyPair ? '' : passphrase, 0,
      (error, passphrase) => {
    if (error) {
      logError(error);
      die();
    }

    if (!anonymous && !keyPair) {
      debug(`Using passphrase ${passphrase}`);
    }

    encryptFile(ids, email, passphrase, file, outputFile, armor, includeSelf,
        anonymous, checkId, keyPair,
        (error, keyPair, length, filename) => {
      if (error) {
        if (error === minilock.ERR_ID_CHECK_FAILED) {
          console.error(`Incorrect passphrase for ${email}`);
        } else {
          logError(error);
        }
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log(`Encrypted from`
            + ` ${minilock.miniLockId(keyPair.publicKey)}.`);
        console.log();

        if (typeof filename === 'string') {
          console.log(`Wrote ${length} bytes to ${filename}`);
          console.log();
        }
      }
    });
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

  let email = options.email;
  let passphrase = options.passphrase;

  let secret = options.secret;

  let file = options.file;
  let outputFile = options['output-file'];

  let armor = options.armor;

  if (typeof secret !== 'string') {
    loadProfile();

    secret = profile && profile.secret || null;
  }

  let keyPair = typeof email !== 'string'
    && secret && minilock.keyPairFromSecret(secret);

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

  readPassphrase(keyPair ? '' : passphrase, 0, (error, passphrase) => {
    if (error) {
      logError(error);
      die();
    }

    debug(`Using passphrase ${passphrase}`);

    decryptFile(email, passphrase, file, outputFile, armor, checkId, keyPair,
        (error, keyPair, length, filename, senderId, originalFilename) => {
      if (error) {
        if (error === minilock.ERR_ID_CHECK_FAILED) {
          console.error(`Incorrect passphrase for ${email}`);
        } else if (error === minilock.ERR_PARSE_ERROR) {
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
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log(`Message from ${senderId}.`);
        console.log();

        if (originalFilename) {
          console.log(`Original filename: ${originalFilename}`);
          console.log();
        }

        if (typeof filename === 'string') {
          console.log(`Wrote ${length} bytes to ${filename}`);
          console.log();
        }
      }
    });
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