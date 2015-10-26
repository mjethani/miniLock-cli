/*  ----------------------------------------------------------------------------
 *  miniLock-cli v0.2.9
 *  
 *  A command line version of miniLock
 *  
 *  Author:  Manish Jethani (manish.jethani@gmail.com)
 *  Date:    August 6, 2015
 *  
 *  See 'mlck --help'
 *  
 *  PGP: 57F8 9653 7461 1F9C EEF9 578B FBDC 955C E6B7 4303
 *  
 *  Bitcoin: 1NxChtv1R6q6STF9rq1BZsZ4jUKDh5MsQg
 *  
 *  http://manishjethani.com/
 *  
 *  Copyright (c) 2015 Manish Jethani
 *  
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *  SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 *  IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *  ------------------------------------------------------------------------- */

import fs       from 'fs';
import os       from 'os';
import path     from 'path';
import readline from 'readline';
import stream   from 'stream';

import BLAKE2s  from 'blake2s-js';
import Base58   from 'bs58';
import nacl     from 'tweetnacl';
import nacl_    from 'nacl-stream';
import scrypt   from 'scrypt-async';
import zxcvbn   from 'zxcvbn';

const _version = require('./package.json').version;

const ERR_ID_CHECK_FAILED = 'ID check failed';
const ERR_PARSE_ERROR = 'Parse error';
const ERR_UNSUPPORTED_VERSION = 'Unsupported version';
const ERR_NOT_A_RECIPIENT = 'Not a recipient';
const ERR_MESSAGE_INTEGRITY_CHECK_FAILED = 'Message integrity check failed';

const ENCRYPTION_CHUNK_SIZE = 256;
const ARMOR_WIDTH = 64;

let profile = null;

let dictionary = null;

let debug = () => {};

function hex(data) {
  return new Buffer(data).toString('hex');
}

function async(func, ...args) {
  process.nextTick(() => {
    func.apply(null, args);
  });
}

function die() {
  if (arguments.length > 0) {
    console.error.apply(console, arguments);
  }

  process.exit(1);
}

function logError(error) {
  if (error) {
    console.error(error.toString());
  }
}

function parseArgs(args, ...rest) {
  // This is another cool function. It parses command line arguments of two
  // kinds: '--long-name[=<value>]' and '-n [<value>]'
  // 
  // If the value is omitted, it's assumed to be a boolean true.
  // 
  // You can pass in default values and a mapping of short names to long names
  // as the first and second arguments respectively.

  const defaultOptions  = typeof rest[0] === 'object' && rest.shift()
      || Object.create(null);
  const shortcuts       = typeof rest[0] === 'object' && rest.shift()
      || Object.create(null);

  let expect = null;
  let stop = false;

  let obj = Object.create(defaultOptions);

  obj = Object.defineProperty(obj, '...', { value: [] });
  obj = Object.defineProperty(obj, '!?',  { value: [] });

  // Preprocessing.
  args = args.reduce((newArgs, arg) => {
    if (!stop) {
      if (arg === '--') {
        stop = true;

      // Split '-xyz' into '-x', '-y', '-z'.
      } else if (arg.length > 2 && arg[0] === '-' && arg[1] !== '-') {
        arg = arg.slice(1).split('').map(v => '-' + v);
      }
    }

    return newArgs.concat(arg);
  },
  []);

  stop = false;

  return args.reduce((obj, arg, index) => {
    const single = !stop && arg[0] === '-' && arg[1] !== '-';

    if (!(single && !(arg = shortcuts[arg]))) {
      if (!stop && arg.slice(0, 2) === '--') {
        if (arg.length > 2) {
          let eq = arg.indexOf('=');

          if (eq === -1) {
            eq = arg.length;
          }

          const name = arg.slice(2, eq);

          if (!single && !Object.prototype.hasOwnProperty.call(defaultOptions,
                name)) {
            obj['!?'].push(arg.slice(0, eq));

            return obj;
          }

          if (single && eq === arg.length - 1) {
            obj[expect = name] = '';

            return obj;
          }

          obj[name] = typeof defaultOptions[name] === 'boolean'
              && eq === arg.length
              || arg.slice(eq + 1);

        } else {
          stop = true;
        }
      } else if (expect) {
        obj[expect] = arg;

      } else if (rest.length > 0) {
        obj[rest.shift()] = arg;

      } else {
        obj['...'].push(arg);
      }

    } else if (single) {
      obj['!?'].push(args[index]);
    }

    expect = null;

    return obj;
  },
  obj);
}

function prompt(label, quiet, callback) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('No TTY.');
  }

  if (arguments.length > 0) {
    callback = arguments[arguments.length - 1];
    if (typeof callback !== 'function') {
      callback = null;
    }
  }

  if (typeof quiet !== 'boolean') {
    quiet = false;
  }

  if (typeof label === 'string') {
    process.stdout.write(label);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    // The quiet argument is for things like passwords. It turns off standard
    // output so nothing is displayed.
    output: !quiet && process.stdout || null,
    terminal: true
  });

  rl.on('line', line => {
    rl.close();

    if (quiet) {
      process.stdout.write(os.EOL);
    }

    if (callback) {
      callback(null, line);
    }
  });
}

function temporaryFilename() {
  return path.resolve(os.tmpdir(),
      '.mlck-' + hex(nacl.randomBytes(32)) + '.tmp');
}

function home() {
  return process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME'];
}

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
    let data = fs.readFileSync(path.resolve(__dirname, 'dictionary'),
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
    let help = fs.readFileSync(path.resolve(__dirname, 'help',
          'default.help'), 'utf8');
    process.stderr.write(help.split('\n\n')[0] + '\n\n');
  } catch (error) {
  }
}

function printHelp(topic) {
  try {
    let help = fs.readFileSync(path.resolve(__dirname, 'help',
          (topic || 'default') + '.help'), 'utf8');
    process.stdout.write(help);
  } catch (error) {
    printUsage();
  }
}

function getScryptKey(key, salt, callback) {
  scrypt(key, salt, 17, 8, 32, 1000,
      keyBytes => callback(nacl.util.decodeBase64(keyBytes)),
      'base64');
}

function getKeyPair(key, salt, callback) {
  const keyHash = new BLAKE2s(32);
  keyHash.update(nacl.util.decodeUTF8(key));

  getScryptKey(keyHash.digest(), nacl.util.decodeUTF8(salt),
      keyBytes => callback(nacl.box.keyPair.fromSecretKey(keyBytes)));
}

function miniLockId(publicKey) {
  const id = new Uint8Array(33);

  id.set(publicKey);

  const hash = new BLAKE2s(1);
  hash.update(publicKey);

  // The last byte is the checksum.
  id[32] = hash.digest()[0];

  return Base58.encode(id);
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
        console.log('Entropy: ' + entropy + '/' + minEntropy);
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

function keyFromId(id) {
  return new Uint8Array(Base58.decode(id).slice(0, 32));
}

function keyPairFromSecret(secret) {
  return nacl.box.keyPair.fromSecretKey(keyFromId(secret));
}

function validateKey(key) {
  if (!key || !(key.length >= 40 && key.length <= 50)
      || !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
      .test(key)) {
    return false;
  }

  return nacl.util.decodeBase64(key).length === 32;
}

function validateId(id) {
  if (!/^[1-9ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{40,55}$/
      .test(id)) {
    return false;
  }

  const bytes = Base58.decode(id);
  if (bytes.length !== 33) {
    return false;
  }

  const hash = new BLAKE2s(1);
  hash.update(bytes.slice(0, 32));

  return hash.digest()[0] === bytes[32];
}

function generateId(email, passphrase, callback) {
  getKeyPair(passphrase, email,
      keyPair => callback(null, miniLockId(keyPair.publicKey), keyPair));
}

function printId(id) {
  if (process.stdout.isTTY) {
    console.log();
    console.log('Your miniLock ID: ' + id + '.');
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
    profile.secret = miniLockId(keyPair.secretKey);
  } else {
    profile.email = email;
    profile.id = id;
  }

  fs.writeFileSync(path.resolve(profileDirectory, 'profile.json'),
      JSON.stringify(profile));
}

function readableArray(array) {
  const fakeReadable = {};

  fakeReadable.on = (event, listener) => {
    if (event === 'readable') {
      async(() => {
        array.slice().forEach(() => {
          listener();
        });
      });
    } else if (event === 'end') {
      async(listener);
    }
  };

  fakeReadable.read = () => array.shift();

  return fakeReadable;
}

function asciiArmor(data, indent) {
  let ascii = new Buffer(data).toString('base64');

  const lines = [];

  if ((indent = Math.max(0, indent | 0)) > 0) {
    // Indent first line.
    lines.push(ascii.slice(0, ARMOR_WIDTH - indent));

    ascii = ascii.slice(ARMOR_WIDTH - indent);
  }

  while (ascii.length > 0) {
    lines.push(ascii.slice(0, ARMOR_WIDTH));

    ascii = ascii.slice(ARMOR_WIDTH);
  }

  return lines.join('\n');
}

function makeHeader(ids, senderInfo, fileInfo) {
  const ephemeral = nacl.box.keyPair();
  const header = {
    version: 1,
    ephemeral: nacl.util.encodeBase64(ephemeral.publicKey),
    decryptInfo: {}
  };

  debug("Ephemeral public key is " + hex(ephemeral.publicKey));
  debug("Ephemeral secret key is " + hex(ephemeral.secretKey));

  ids.forEach((id, index) => {
    debug("Adding recipient " + id);

    const nonce = nacl.randomBytes(24);
    const publicKey = keyFromId(id);

    debug("Using nonce " + hex(nonce));

    let decryptInfo = {
      senderID: senderInfo.id,
      recipientID: id,
      fileInfo: fileInfo
    };

    decryptInfo.fileInfo = nacl.util.encodeBase64(nacl.box(
      nacl.util.decodeUTF8(JSON.stringify(decryptInfo.fileInfo)),
      nonce,
      publicKey,
      senderInfo.secretKey
    ));

    decryptInfo = nacl.util.encodeBase64(nacl.box(
      nacl.util.decodeUTF8(JSON.stringify(decryptInfo)),
      nonce,
      publicKey,
      ephemeral.secretKey
    ));

    header.decryptInfo[nacl.util.encodeBase64(nonce)] = decryptInfo;
  });

  return JSON.stringify(header);
}

function extractDecryptInfo(header, secretKey) {
  let decryptInfo = null;

  const ephemeral = nacl.util.decodeBase64(header.ephemeral);

  for (let i in header.decryptInfo) {
    const nonce = nacl.util.decodeBase64(i);

    debug("Trying nonce " + hex(nonce));

    decryptInfo = nacl.util.decodeBase64(header.decryptInfo[i]);
    decryptInfo = nacl.box.open(decryptInfo, nonce, ephemeral, secretKey);

    if (decryptInfo) {
      decryptInfo = JSON.parse(nacl.util.encodeUTF8(decryptInfo));

      debug("Recipient ID is " + decryptInfo.recipientID);
      debug("Sender ID is " + decryptInfo.senderID);

      decryptInfo.fileInfo = nacl.util.decodeBase64(decryptInfo.fileInfo);
      decryptInfo.fileInfo = nacl.box.open(decryptInfo.fileInfo, nonce,
          keyFromId(decryptInfo.senderID), secretKey);

      decryptInfo.fileInfo = JSON.parse(
          nacl.util.encodeUTF8(decryptInfo.fileInfo)
          );

      debug("File key is " + hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileKey)));
      debug("File nonce is " + hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileNonce)));
      debug("File hash is " + hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileHash)));
      break;
    }
  }

  return decryptInfo;
}

function encryptChunk(chunk, encryptor, output, hash) {
  if (chunk && chunk.length > ENCRYPTION_CHUNK_SIZE) {
    for (let i = 0; i < chunk.length; i += ENCRYPTION_CHUNK_SIZE) {
      encryptChunk(chunk.slice(i, i + ENCRYPTION_CHUNK_SIZE),
          encryptor, output, hash);
    }
  } else {
    chunk = encryptor.encryptChunk(new Uint8Array(chunk || []), !chunk);

    debug("Encrypted chunk " + hex(chunk));

    if (Array.isArray(output)) {
      output.push(new Buffer(chunk));
    } else {
      output.write(new Buffer(chunk));
    }

    if (hash) {
      hash.update(chunk);
    }
  }
}

function decryptChunk(chunk, decryptor, output, hash) {
  while (true) {
    const length = chunk.length >= 4 ? chunk.readUIntLE(0, 4, true) : 0;

    if (chunk.length < 4 + 16 + length) {
      break;
    }

    const encrypted = new Uint8Array(chunk.slice(0, 4 + 16 + length));
    const decrypted = decryptor.decryptChunk(encrypted, false);

    chunk = chunk.slice(4 + 16 + length);

    if (decrypted) {
      debug("Decrypted chunk " + hex(decrypted));

      if (Array.isArray(output)) {
        output.push(new Buffer(decrypted));
      } else {
        output.write(new Buffer(decrypted));
      }
    }

    if (hash) {
      hash.update(encrypted);
    }
  }

  return chunk;
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

    debug("Generating key pair with email " + email
        + " and passphrase " + passphrase);

    keyPairFunc = callback => {
      getKeyPair(passphrase, email, callback);
    };
  } else {
    keyPairFunc = callback => {
      async(() => {
        callback(keyPair);
      });
    };
  }

  keyPairFunc(keyPair => {
    debug("Our public key is " + hex(keyPair.publicKey));
    debug("Our secret key is " + hex(keyPair.secretKey));

    const fromId = miniLockId(keyPair.publicKey);

    debug("Our miniLock ID is " + fromId);

    if (!anonymous && checkId && fromId !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

    const senderInfo = {
      id: fromId,
      secretKey: keyPair.secretKey
    };

    const fileKey   = nacl.randomBytes(32);
    const fileNonce = nacl.randomBytes(16);

    debug("Using file key " + hex(fileKey));
    debug("Using file nonce " + hex(fileNonce));

    const encryptor = nacl_.stream.createEncryptor(fileKey, fileNonce,
        ENCRYPTION_CHUNK_SIZE);
    const hash = new BLAKE2s(32);

    // Generate a random filename for writing encrypted chunks to instead of
    // keeping everything in memory.
    const encryptedDataFile = temporaryFilename();

    // This is where the encrypted chunks go.
    let encrypted = [];

    const filenameBuffer = new Buffer(256).fill(0);

    if (typeof file === 'string') {
      if (new Buffer(path.basename(file)).length > 256) {
        console.error('WARNING: Filename is too long and will be truncated.');
      }

      filenameBuffer.write(path.basename(file));
    }

    // The first chunk is the 256-byte null-padded filename. If input is stdin,
    // filename is blank. If the UTF-8-encoded filename is greater than 256
    // bytes, it is truncated.
    encryptChunk(filenameBuffer, encryptor, encrypted, hash);

    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    let inputByteCount = 0;

    inputStream.on('error', error => {
      fs.unlink(encryptedDataFile, () => {});

      callback(error, keyPair);
    });

    inputStream.on('readable', () => {
      const chunk = inputStream.read();
      if (chunk !== null) {
        inputByteCount += chunk.length;

        // If input exceeds the 4K threshold (picked arbitrarily), switch from
        // writing to an array to writing to a file. This way we can do
        // extremely large files.
        if (inputByteCount > 4 * 1024 && Array.isArray(encrypted)) {
          const stream = fs.createWriteStream(encryptedDataFile);

          encrypted.forEach(chunk => {
            stream.write(chunk);
          });

          encrypted = stream;
        }

        // Encrypt this chunk.
        encryptChunk(chunk, encryptor, encrypted, hash);
      }
    });

    inputStream.on('end', () => {
      // Finish up with the encryption.
      encryptChunk(null, encryptor, encrypted, hash);

      encryptor.clean();

      // This is the 32-byte BLAKE2 hash of all the ciphertext.
      const fileHash = hash.digest();

      debug("File hash is " + hex(fileHash));

      const fileInfo = {
        fileKey: nacl.util.encodeBase64(fileKey),
        fileNonce: nacl.util.encodeBase64(fileNonce),
        fileHash: nacl.util.encodeBase64(fileHash)
      };

      // Pack the sender and file information into a header.
      const header = makeHeader(includeSelf ? ids.concat(fromId) : ids,
          senderInfo, fileInfo);

      const headerLength = new Buffer(4);
      headerLength.writeUInt32LE(header.length);

      debug("Header length is " + hex(headerLength));

      const filename = typeof outputFile === 'string' ? outputFile
        : typeof file === 'string' ? file + '.minilock'
        : null;

      if (typeof filename === 'string') {
        debug("Writing to file " + filename);
      } else if (!process.stdout.isTTY) {
        debug("Writing to stdout");
      }

      if (!armor && typeof filename !== 'string' && process.stdout.isTTY) {
        console.error('WARNING: Not writing output to terminal.');
      }

      const outputStream = typeof filename === 'string'
        ? fs.createWriteStream(filename) : armor || !process.stdout.isTTY
        ? process.stdout : null;

      let outputByteCount = 0;

      let buffer = new Buffer(0);

      let asciiIndent = 0;

      let outputHeader = Buffer.concat([
        // The file always begins with the magic bytes 0x6d696e694c6f636b.
        new Buffer('miniLock'), headerLength, new Buffer(header)
      ]);

      if (armor) {
        // https://tools.ietf.org/html/rfc4880#section-6

        buffer = outputHeader.slice(outputHeader.length
              - outputHeader.length % 3);
        outputHeader = asciiArmor(outputHeader.slice(0, outputHeader.length
                - outputHeader.length % 3));

        asciiIndent = outputHeader.length % (ARMOR_WIDTH + 1);

        outputHeader = '-----BEGIN MINILOCK FILE-----\n'
          + 'Version: miniLock-cli v' + _version + '\n'
          + '\n'
          + outputHeader;
      }

      if (outputStream) {
        outputStream.write(outputHeader);
      }

      outputByteCount += outputHeader.length;

      if (Array.isArray(encrypted)) {
        encrypted.end = async;
      }

      encrypted.end(() => {
        if (Array.isArray(encrypted)) {
          // Wrap array into a stream-like interface.
          encrypted = readableArray(encrypted);
        } else {
          encrypted = fs.createReadStream(encryptedDataFile);
        }

        encrypted.on('error', error => {
          async(() => {
            fs.unlink(encryptedDataFile, () => {});

            callback(error, keyPair);
          });
        });

        encrypted.on('readable', () => {
          let chunk = encrypted.read();
          if (chunk !== null) {
            if (armor) {
              chunk = Buffer.concat([ buffer, chunk ]);

              const index = chunk.length - chunk.length % 3;

              buffer = chunk.slice(index);
              chunk = asciiArmor(chunk.slice(0, index), asciiIndent);

              asciiIndent = (chunk.length + asciiIndent) % (ARMOR_WIDTH + 1);
            }

            if (outputStream) {
              outputStream.write(chunk);
            }

            outputByteCount += chunk.length;
          }
        });

        encrypted.on('end', () => {
          if (armor) {
            const chunk = asciiArmor(buffer, asciiIndent)
              + '\n-----END MINILOCK FILE-----\n';

            if (outputStream) {
              outputStream.write(chunk);
            }

            outputByteCount += chunk.length;
          }

          debug("File encryption complete");

          async(() => {
            // Attempt to delete the temporary file, but ignore any error.
            fs.unlink(encryptedDataFile, () => {});

            callback(null, keyPair, outputByteCount, filename);
          });
        });
      });
    });
  });
}

function decryptFile(email, passphrase, file, outputFile, armor, checkId,
    keyPair, callback) {
  debug("Begin file decryption");

  let keyPairFunc = null;

  if (!keyPair) {
    debug("Generating key pair with email " + email
        + " and passphrase " + passphrase);

    keyPairFunc = callback => {
      getKeyPair(passphrase, email, callback);
    };
  } else {
    keyPairFunc = callback => {
      async(() => {
        callback(keyPair);
      });
    };
  }

  keyPairFunc(keyPair => {
    debug("Our public key is " + hex(keyPair.publicKey));
    debug("Our secret key is " + hex(keyPair.secretKey));

    const toId = miniLockId(keyPair.publicKey);

    debug("Our miniLock ID is " + toId);

    if (checkId && toId !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

    let asciiBuffer = '';

    let armorHeaders = null;

    let headerLength = NaN;
    let header = null;

    let decryptInfo = null;

    let decryptor = null;

    const hash = new BLAKE2s(32);

    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    const inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    let buffer = new Buffer(0);

    let error_ = null;

    const outputFilename = typeof outputFile === 'string' ? outputFile
      : null;

    if (typeof outputFilename === 'string') {
      debug("Writing to file " + outputFilename);
    } else if (!process.stdout.isTTY) {
      debug("Writing to stdout");
    }

    let originalFilename = null;

    const outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : process.stdout;

    let outputByteCount = 0;

    inputStream.on('error', error => {
      callback(error, keyPair);
    });

    inputStream.on('readable', () => {
      let chunk = inputStream.read();

      if (error_ !== null) {
        return;
      }

      if (chunk !== null) {
        if (armor) {
          asciiBuffer += chunk.toString();

          chunk = new Buffer(0);

          let index = -1;

          if (!armorHeaders && asciiBuffer.slice(0, 30)
              === '-----BEGIN MINILOCK FILE-----\n'
              && (index = asciiBuffer.indexOf('\n\n')) !== -1) {
            armorHeaders = asciiBuffer.slice(30, index).toString().split('\n');

            asciiBuffer = asciiBuffer.slice(index + 2);
          }

          if (armorHeaders) {
            // Strip out newlines and other whitespace.
            asciiBuffer = asciiBuffer.replace(/\s+/g, '');

            // Decode as many 32-bit groups as possible now and leave the
            // balance for later.
            index = asciiBuffer.length - asciiBuffer.length % 4;

            chunk = new Buffer(asciiBuffer.slice(0, index), 'base64');
            asciiBuffer = asciiBuffer.slice(index);
          }
        }

        try {
          // Read chunk into buffer.
          buffer = Buffer.concat([ buffer, chunk ]);
        } catch (error) {
          // If the buffer length exceeds 0x3fffffff, it'll throw a RangeError.
          callback(error_ = error.name === 'RangeError'
              ? ERR_PARSE_ERROR : error, keyPair);
          return;
        }

        if (!header) {
          try {
            if (isNaN(headerLength) && buffer.length >= 12) {
              if (buffer[0] !== 0x6d
                  || buffer[1] !== 0x69
                  || buffer[2] !== 0x6e
                  || buffer[3] !== 0x69
                  || buffer[4] !== 0x4c
                  || buffer[5] !== 0x6f
                  || buffer[6] !== 0x63
                  || buffer[7] !== 0x6b
                 ) {
                throw ERR_PARSE_ERROR;
              }

              // Read the 4-byte header length, which is after the initial 8
              // magic bytes of 'miniLock'.
              headerLength = buffer.readUIntLE(8, 4, true);

              if (headerLength > 0x3fffffff) {
                throw ERR_PARSE_ERROR;
              }

              buffer = new Buffer(buffer.slice(12));
            }

            if (!isNaN(headerLength)) {
              // Look for the JSON opening brace.
              if (buffer.length > 0 && buffer[0] !== 0x7b) {
                throw ERR_PARSE_ERROR;
              }

              if (buffer.length >= headerLength) {
                // Read the header and parse the JSON object.
                header = JSON.parse(buffer.slice(0, headerLength).toString());

                if (header.version !== 1) {
                  throw ERR_UNSUPPORTED_VERSION;
                }

                if (!validateKey(header.ephemeral)) {
                  throw ERR_PARSE_ERROR;
                }

                if (!(decryptInfo = extractDecryptInfo(header,
                          keyPair.secretKey))
                    || decryptInfo.recipientID !== toId) {
                  throw ERR_NOT_A_RECIPIENT;
                }

                // Shift the buffer pointer.
                buffer = buffer.slice(headerLength);
              }
            }
          } catch (error) {
            callback(error_ = error.name === 'SyntaxError'
                ? ERR_PARSE_ERROR : error, keyPair);
            return;
          }
        }

        if (decryptInfo) {
          if (!decryptor) {
            // Time to deal with the ciphertext.
            decryptor = nacl_.stream.createDecryptor(
                nacl.util.decodeBase64(decryptInfo.fileInfo.fileKey),
                nacl.util.decodeBase64(decryptInfo.fileInfo.fileNonce),
                0x100000);

            if (outputStream === process.stdout && process.stdout.isTTY) {
              console.log('--- BEGIN MESSAGE ---');
            }
          }

          const array = [];

          // Decrypt as many chunks as possible.
          buffer = decryptChunk(buffer, decryptor, array, hash);

          if (!originalFilename && array.length > 0) {
            // The very first chunk is the original filename.
            originalFilename = array.shift().toString();
          }

          // Write each decrypted chunk to the output stream.
          array.forEach(chunk => {
            outputStream.write(chunk);

            outputByteCount += chunk.length;
          });
        }
      }
    });

    inputStream.on('end', () => {
      if (error_ !== null) {
        return;
      }

      if (outputStream === process.stdout && process.stdout.isTTY) {
        console.log('--- END MESSAGE ---');
      }

      if (nacl.util.encodeBase64(hash.digest())
          !== decryptInfo.fileInfo.fileHash) {
        // The 32-byte BLAKE2 hash of the ciphertext must match the value in
        // the header.
        callback(ERR_MESSAGE_INTEGRITY_CHECK_FAILED, keyPair);
      } else {
        debug("File decryption complete");

        callback(null, keyPair, outputByteCount, outputFilename,
            decryptInfo.senderID,
            // Strip out any trailing null characters.
            (originalFilename + '\0').slice(0, originalFilename.indexOf('\0'))
          );
      }
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
    die("Unknown option '" + options['!?'][0] + "'.");
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
      keyPair = keyPairFromSecret(secret);

      if (saveKey) {
        saveId(null, null, keyPair);
      }

      printId(miniLockId(keyPair.publicKey));
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

    debug("Using passphrase " + passphrase);

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
    die("Unknown option '" + options['!?'][0] + "'.");
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
    if (!validateId(id)) {
      die(id + " doesn't look like a valid miniLock ID.");
    }
  });

  if (typeof secret !== 'string') {
    loadProfile();

    secret = profile && profile.secret || null;
  }

  let keyPair = !anonymous && typeof email !== 'string'
    && secret && keyPairFromSecret(secret);

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
      debug("Using passphrase " + passphrase);
    }

    encryptFile(ids, email, passphrase, file, outputFile, armor, includeSelf,
        anonymous, checkId, keyPair,
        (error, keyPair, length, filename) => {
      if (error) {
        if (error === ERR_ID_CHECK_FAILED) {
          console.error('Incorrect passphrase for ' + email);
        } else {
          logError(error);
        }
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log('Encrypted from ' + miniLockId(keyPair.publicKey) + '.');
        console.log();

        if (typeof filename === 'string') {
          console.log('Wrote ' + length + ' bytes to ' + filename);
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
    die("Unknown option '" + options['!?'][0] + "'.");
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
    && secret && keyPairFromSecret(secret);

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

    debug("Using passphrase " + passphrase);

    decryptFile(email, passphrase, file, outputFile, armor, checkId, keyPair,
        (error, keyPair, length, filename, senderId, originalFilename) => {
      if (error) {
        if (error === ERR_ID_CHECK_FAILED) {
          console.error('Incorrect passphrase for ' + email);
        } else if (error === ERR_PARSE_ERROR) {
          console.error('The file appears corrupt.');
        } else if (error === ERR_UNSUPPORTED_VERSION) {
          console.error('This miniLock version is not supported.');
        } else if (error === ERR_NOT_A_RECIPIENT) {
          console.error('The message is not intended for '
              + miniLockId(keyPair.publicKey) + '.');
        } else if (error === ERR_MESSAGE_INTEGRITY_CHECK_FAILED) {
          console.error('The message is corrupt.');
        } else {
          logError(error);
        }
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log('Message from ' + senderId + '.');
        console.log();

        if (originalFilename) {
          console.log('Original filename: ' + originalFilename);
          console.log();
        }

        if (typeof filename === 'string') {
          console.log('Wrote ' + length + ' bytes to ' + filename);
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
  console.log('miniLock-cli v' + _version);
}

function handleLicenseCommand() {
  process.stdout.write(fs.readFileSync(path.resolve(__dirname, 'LICENSE')));
}

function run() {
  if (process.argv[2] === '--debug') {
    process.argv.splice(2, 1);

    debug = () => {
      console.error.apply(console, arguments);
    }
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

exports.run = run;

// vim: et ts=2 sw=2
