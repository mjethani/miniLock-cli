/*  ----------------------------------------------------------------------------
 *  mlck v0.1.12
 *  
 *  Author:  Manish Jethani (manish.jethani@gmail.com)
 *  Date:    April 24, 2015
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

var fs        = require('fs');
var os        = require('os');
var path      = require('path');
var readline  = require('readline');
var stream    = require('stream');

var BLAKE2s   = require('blake2s-js');
var Base58    = require('bs58');
var nacl      = require('tweetnacl');
var nacl_     = require('nacl-stream');
var scrypt    = require('scrypt-async');
var zxcvbn    = require('zxcvbn');

var debug = function () {};

var ERR_ID_CHECK_FAILED = 'ID check failed';
var ERR_PARSE_ERROR = 'Parse error';
var ERR_UNSUPPORTED_VERSION = 'Unsupported version';
var ERR_NOT_A_RECIPIENT = 'Not a recipient';
var ERR_MESSAGE_INTEGRITY_CHECK_FAILED = 'Message integrity check failed';

var help = 'usage: mlck id      [<email>] [--passphrase=<passphrase>] [--save]\n'
         + '       mlck encrypt [<id> ...] [--self] [--email=<email>]\n'
         + '                    [--file=<file>] [--output-file=<output-file>]\n'
         + '                    [--passphrase=<passphrase>]\n'
         + '                    [--anonymous]\n'
         + '       mlck decrypt [--email=<email>]\n'
         + '                    [--file=<file>] [--output-file=<output-file>]\n'
         + '                    [--passphrase=<passphrase>]\n';

var ENCRYPTION_CHUNK_SIZE = 256;

var profile = null;

var dictionary = null;

function isArray(value) {
  return Object.prototype.toString.call(value) === '[object Array]';
}

function hex(data) {
  return new Buffer(data).toString('hex');
}

function sliceArguments(begin, end) {
  return Array.prototype.slice.call(sliceArguments.caller.arguments,
      begin, end);
}

function async(func) {
  var args = sliceArguments(1);
  process.nextTick(function () {
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

function parseArgs(args) {
  // This is another cool function. It parses command line arguments of two
  // kinds: '--long-name[=<value>]' and '-n [<value>]'
  // 
  // If the value is omitted, it's assumed to be a boolean true.
  // 
  // You can pass in default values and a mapping of short names to long names
  // as the first and second arguments respectively.

  var rest = sliceArguments(1);

  var defaultOptions  = typeof rest[0] === 'object' && rest.shift() || {};
  var shortcuts       = typeof rest[0] === 'object' && rest.shift() || {};

  var expect = null;
  var stop = false;

  var obj = Object.create(defaultOptions);

  obj = Object.defineProperty(obj, '...', { value: [] });
  obj = Object.defineProperty(obj, '!?',  { value: [] });

  // Preprocessing.
  args = args.reduce(function (newArgs, arg) {
    if (!stop) {
      if (arg === '--') {
        stop = true;

      // Split '-xyz' into '-x', '-y', '-z'.
      } else if (arg.length > 2 && arg[0] === '-' && arg[1] !== '-') {
        arg = arg.slice(1).split('').map(function (v) { return '-' + v });
      }
    }

    return newArgs.concat(arg);
  },
  []);

  stop = false;

  return args.reduce(function (obj, arg, index) {
    var single = !stop && arg[0] === '-' && arg[1] !== '-';

    if (!(single && !(arg = shortcuts[arg]))) {
      if (!stop && arg.slice(0, 2) === '--') {
        if (arg.length > 2) {
          var eq = arg.indexOf('=');

          if (eq === -1) {
            eq = arg.length;
          }

          var name = arg.slice(2, eq);

          if (!single && !defaultOptions.hasOwnProperty(name)) {
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

  var rl = readline.createInterface({
    input: process.stdin,
    // The quiet argument is for things like passwords. It turns off standard
    // output so nothing is displayed.
    output: !quiet && process.stdout || null,
    terminal: true
  });

  rl.on('line', function (line) {
    rl.close();

    if (quiet) {
      process.stdout.write(os.EOL);
    }

    if (callback) {
      callback(null, line);
    }
  });
}

function home() {
  return process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME'];
}

function loadProfile() {
  var profileDirectory = path.resolve(home(), '.mlck');

  var data = null;

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
    var data = fs.readFileSync(path.resolve(__dirname, 'dictionary'),
        { encoding: 'utf8' });

    dictionary = data.split('\n').map(function (line) {
      return line.replace(/^\s*|\s*$/g, '').replace(/^#.*/, '');
    }).filter(function (line) {
      return line !== '';
    });
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

  var passphrase = '';

  while (zxcvbn(passphrase).entropy < entropy) {
    var randomNumber = new Buffer(nacl.randomBytes(2)).readUInt16BE();
    var index = Math.floor((randomNumber / 0x10000) * dictionary.length);

    passphrase += (passphrase && ' ' || '') + dictionary[index];
  }

  return passphrase;
}

function printUsage() {
  console.error(help);
}

function getScryptKey(key, salt, callback) {
  scrypt(key, salt, 17, 8, 32, 1000, function (keyBytes) {
    return callback(nacl.util.decodeBase64(keyBytes));
  },
  'base64');
}

function getKeyPair(key, salt, callback) {
  var keyHash = new BLAKE2s(32);
  keyHash.update(nacl.util.decodeUTF8(key));

  getScryptKey(keyHash.digest(), nacl.util.decodeUTF8(salt),
      function(keyBytes) {
    callback(nacl.box.keyPair.fromSecretKey(keyBytes));
  });
}

function miniLockId(publicKey) {
  var id = new Uint8Array(33);

  for (var i = 0; i < publicKey.length; i++) {
    id[i] = publicKey[i];
  }

  var hash = new BLAKE2s(1);
  hash.update(publicKey);

  id[32] = hash.digest()[0];

  return Base58.encode(id);
}

function readPassphrase(passphrase, minEntropy, callback) {
  var defaultMinEntropy = 100;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    minEntropy = defaultMinEntropy;
    passphrase = null;
  } else if (typeof minEntropy === 'function') {
    callback = minEntropy;
    minEntropy = defaultMinEntropy;
  }

  if (typeof passphrase === 'string') {
    async(function () {
      callback(null, passphrase);
    });
  } else {
    if (minEntropy) {
      var example = randomPassphrase(minEntropy);
      if (example) {
        console.log(example);
        console.log();
      }
    }

    prompt('Passphrase (leave blank to quit): ', true,
        function (error, passphrase) {
      if (passphrase === '') {
        die();
      }

      var entropy = zxcvbn(passphrase).entropy;

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

function publicKeyFromId(id) {
  return new Uint8Array(Base58.decode(id).slice(0, 32));
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

  var bytes = Base58.decode(id);
  if (bytes.length !== 33) {
    return false;
  }

  var hash = new BLAKE2s(1);
  hash.update(bytes.slice(0, 32));

  return hash.digest()[0] === bytes[32];
}

function generateId(email, passphrase, callback) {
  getKeyPair(passphrase, email, function (keyPair) {
    callback(null, miniLockId(keyPair.publicKey), keyPair);
  });
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

function saveId(email, id) {
  var profileDirectory = path.resolve(home(), '.mlck');

  try {
    fs.mkdirSync(profileDirectory);
  } catch (error) {
    if (error.code !== 'EEXIST') {
      throw error;
    }
  }

  var profile = {
    version: '0.1',
    email: email,
    id: id
  };

  fs.writeFileSync(path.resolve(profileDirectory, 'profile.json'),
      JSON.stringify(profile));
}

function readableArray(array) {
  var fakeReadable = {};

  fakeReadable.on = function (event, listener) {
    if (event === 'readable') {
      async(function () {
        array.slice().forEach(function () {
          listener();
        });
      });
    } else if (event === 'end') {
      async(listener);
    }
  };

  fakeReadable.read = function () {
    return array.shift();
  };

  return fakeReadable;
}

function makeHeader(ids, senderInfo, fileInfo) {
  var ephemeral = nacl.box.keyPair();
  var header = {
    version: 1,
    ephemeral: nacl.util.encodeBase64(ephemeral.publicKey),
    decryptInfo: {}
  };

  debug("Ephemeral public key is " + hex(ephemeral.publicKey));
  debug("Ephemeral secret key is " + hex(ephemeral.secretKey));

  ids.forEach(function (id, index) {
    debug("Adding recipient " + id);

    var nonce = nacl.randomBytes(24);
    var publicKey = publicKeyFromId(id);

    debug("Using nonce " + hex(nonce));

    var decryptInfo = {
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
  var decryptInfo = null;

  var ephemeral = nacl.util.decodeBase64(header.ephemeral);

  for (var i in header.decryptInfo) {
    var nonce = nacl.util.decodeBase64(i);

    debug("Trying nonce " + hex(nonce));

    decryptInfo = nacl.util.decodeBase64(header.decryptInfo[i]);
    decryptInfo = nacl.box.open(decryptInfo, nonce, ephemeral, secretKey);

    if (decryptInfo) {
      decryptInfo = JSON.parse(nacl.util.encodeUTF8(decryptInfo));

      debug("Recipient ID is " + decryptInfo.recipientID);
      debug("Sender ID is " + decryptInfo.senderID);

      decryptInfo.fileInfo = nacl.util.decodeBase64(decryptInfo.fileInfo);
      decryptInfo.fileInfo = nacl.box.open(decryptInfo.fileInfo, nonce,
          publicKeyFromId(decryptInfo.senderID), secretKey);

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
    for (var i = 0; i < chunk.length; i += ENCRYPTION_CHUNK_SIZE) {
      encryptChunk(chunk.slice(i, i + ENCRYPTION_CHUNK_SIZE),
          encryptor, output, hash);
    }
  } else {
    chunk = encryptor.encryptChunk(new Uint8Array(chunk || []), !chunk);

    debug("Encrypted chunk " + hex(chunk));

    if (isArray(output)) {
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
    var length = chunk.length >= 4 ? chunk.readUIntLE(0, 4, true) : 0;

    if (chunk.length < 4 + 16 + length) {
      break;
    }

    var encrypted = new Uint8Array(chunk.slice(0, 4 + 16 + length));
    var decrypted = decryptor.decryptChunk(encrypted, false);

    chunk = chunk.slice(4 + 16 + length);

    if (decrypted) {
      debug("Decrypted chunk " + hex(decrypted));

      if (isArray(output)) {
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

function encryptFile(ids, email, passphrase, file, outputFile, includeSelf,
    anonymous, checkId, callback) {
  debug("Begin file encryption");

  if (anonymous) {
    email = 'Anonymous';
    passphrase = new Buffer(nacl.randomBytes(32)).toString('base64');
  }

  debug("Generating key pair with email " + email
      + " and passphrase " + passphrase);

  getKeyPair(passphrase, email, function (keyPair) {
    debug("Our public key is " + hex(keyPair.publicKey));
    debug("Our secret key is " + hex(keyPair.secretKey));

    var fromId = miniLockId(keyPair.publicKey);

    debug("Our miniLock ID is " + fromId);

    if (!anonymous && checkId && fromId !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

    var senderInfo = {
      id: fromId,
      secretKey: keyPair.secretKey
    };

    var fileKey   = nacl.randomBytes(32);
    var fileNonce = nacl.randomBytes(16);

    debug("Using file key " + hex(fileKey));
    debug("Using file nonce " + hex(fileNonce));

    var encryptor = nacl_.stream.createEncryptor(fileKey, fileNonce,
        ENCRYPTION_CHUNK_SIZE);
    var hash = new BLAKE2s(32);

    var encryptedDataFile = path.resolve(os.tmpdir(),
        '.mlck-' + hex(nacl.randomBytes(32)) + '.tmp');

    var encrypted = [];

    var filenameBuffer = new Buffer(256).fill(0);

    if (typeof file === 'string') {
      if (file.length > 256) {
        console.error('WARNING: Filename is too long and will be truncated.');
      }

      filenameBuffer.write(path.basename(file));
    }

    encryptChunk(filenameBuffer, encryptor, encrypted, hash);

    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    var inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    var inputByteCount = 0;

    inputStream.on('error', function (error) {
      fs.unlink(encryptedDataFile, function () {});

      callback(error, keyPair);
    });

    inputStream.on('readable', function () {
      var chunk = inputStream.read();
      if (chunk !== null) {
        inputByteCount += chunk.length;

        if (inputByteCount > 4 * 1024 && isArray(encrypted)) {
          var stream = fs.createWriteStream(encryptedDataFile);

          encrypted.forEach(function (chunk) {
            stream.write(chunk);
          });

          encrypted = stream;
        }

        encryptChunk(chunk, encryptor, encrypted, hash);
      }
    });

    inputStream.on('end', function () {
      encryptChunk(null, encryptor, encrypted, hash);

      encryptor.clean();

      var fileHash = hash.digest();

      debug("File hash is " + hex(fileHash));

      var fileInfo = {
        fileKey: nacl.util.encodeBase64(fileKey),
        fileNonce: nacl.util.encodeBase64(fileNonce),
        fileHash: nacl.util.encodeBase64(fileHash)
      };

      var header = makeHeader(includeSelf ? ids.concat(fromId) : ids,
          senderInfo, fileInfo);

      var headerLength = new Buffer(4);
      headerLength.writeUInt32LE(header.length);

      debug("Header length is " + hex(headerLength));

      var filename = typeof outputFile === 'string' ? outputFile
        : typeof file === 'string' ? file + '.minilock'
        : null;

      if (typeof filename === 'string') {
        debug("Writing to file " + filename);
      } else if (!process.stdout.isTTY) {
        debug("Writing to stdout");
      }

      if (typeof filename !== 'string' && process.stdout.isTTY) {
        console.error('WARNING: Not writing output to terminal.');
      }

      var outputStream = typeof filename === 'string'
        ? fs.createWriteStream(filename) : !process.stdout.isTTY
        ? process.stdout : null;

      var outputByteCount = 0;

      var outputHeader = Buffer.concat([
        new Buffer('miniLock'), headerLength, new Buffer(header)
      ]);

      if (outputStream) {
        outputStream.write(outputHeader);
      }

      outputByteCount += outputHeader.length;

      if (isArray(encrypted)) {
        encrypted.end = async;
      }

      encrypted.end(function () {
        if (isArray(encrypted)) {
          encrypted = readableArray(encrypted);
        } else {
          encrypted = fs.createReadStream(encryptedDataFile);
        }

        encrypted.on('error', function (error) {
          async(function () {
            fs.unlink(encryptedDataFile, function () {});

            callback(error, keyPair);
          });
        });

        encrypted.on('readable', function () {
          var chunk = encrypted.read();
          if (chunk !== null) {
            if (outputStream) {
              outputStream.write(chunk);
            }

            outputByteCount += chunk.length;
          }
        });

        encrypted.on('end', function () {
          debug("File encryption complete");

          async(function () {
            fs.unlink(encryptedDataFile, function () {});

            callback(null, keyPair, outputByteCount, filename);
          });
        });
      });
    });
  });
}

function decryptFile(email, passphrase, file, outputFile, checkId, callback) {
  debug("Begin file decryption");

  debug("Generating key pair with email " + email
      + " and passphrase " + passphrase);

  getKeyPair(passphrase, email, function (keyPair) {
    debug("Our public key is " + hex(keyPair.publicKey));
    debug("Our secret key is " + hex(keyPair.secretKey));

    var toId = miniLockId(keyPair.publicKey);

    debug("Our miniLock ID is " + toId);

    if (checkId && toId !== checkId) {
      callback(ERR_ID_CHECK_FAILED, keyPair);
      return;
    }

    var headerLength = 0;
    var header = null;

    var decryptInfo = null;

    var decryptor = null;

    var hash = new BLAKE2s(32);

    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    var inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    var buffer = new Buffer(0);

    var error_ = null;

    var outputFilename = typeof outputFile === 'string' ? outputFile
      : null;

    if (typeof outputFilename === 'string') {
      debug("Writing to file " + outputFilename);
    } else if (!process.stdout.isTTY) {
      debug("Writing to stdout");
    }

    var originalFilename = null;

    var outputStream = typeof outputFilename === 'string'
      ? fs.createWriteStream(outputFilename) : process.stdout;

    var outputByteCount = 0;

    inputStream.on('error', function (error) {
      callback(error, keyPair);
    });

    inputStream.on('readable', function () {
      var chunk = inputStream.read();

      if (error_ !== null) {
        return;
      }

      if (chunk !== null) {
        buffer = Buffer.concat([ buffer, chunk ]);

        if (!header) {
          try {
            if (buffer.length >= 12) {
              headerLength = buffer.readUIntLE(8, 4, true);

              if (buffer.length >= 12 + headerLength) {
                header = JSON.parse(buffer.slice(12, 12 + headerLength)
                  .toString());

                if (header.version !== 1) {
                  throw ERR_UNSUPPORTED_VERSION;
                }

                if (!validateKey(header.ephemeral)) {
                  throw ERR_PARSE_ERROR;
                }

                if (!(decryptInfo = extractDecryptInfo(header, keyPair.secretKey))
                    || decryptInfo.recipientID !== toId) {
                  throw ERR_NOT_A_RECIPIENT;
                }

                buffer = buffer.slice(12 + headerLength);
              }
            }
          } catch (error) {
            callback(error_ = error.name === 'SyntaxError' ? ERR_PARSE_ERROR : error,
                keyPair);
            return;
          }
        }

        if (decryptInfo) {
          if (!decryptor) {
            decryptor = nacl_.stream.createDecryptor(
                nacl.util.decodeBase64(decryptInfo.fileInfo.fileKey),
                nacl.util.decodeBase64(decryptInfo.fileInfo.fileNonce),
                0x100000);

            if (outputStream === process.stdout && process.stdout.isTTY) {
              console.log('--- BEGIN MESSAGE ---');
            }
          }

          var array = [];

          buffer = decryptChunk(buffer, decryptor, array, hash);

          if (!originalFilename && array.length > 0) {
            originalFilename = array.shift().toString();
          }

          array.forEach(function (chunk) {
            outputStream.write(chunk);

            outputByteCount += chunk.length;
          });
        }
      }
    });

    inputStream.on('end', function () {
      if (error_ !== null) {
        return;
      }

      if (outputStream === process.stdout && process.stdout.isTTY) {
        console.log('--- END MESSAGE ---');
      }

      if (nacl.util.encodeBase64(hash.digest()) !== decryptInfo.fileInfo.fileHash) {
        callback(ERR_MESSAGE_INTEGRITY_CHECK_FAILED, keyPair);
      } else {
        debug("File decryption complete");

        callback(null, keyPair, outputByteCount, outputFilename,
            decryptInfo.senderID,
            originalFilename !== Array(256 + 1).join('\0')
              ? originalFilename : null);
      }
    });
  });
}

function handleIdCommand() {
  var defaultOptions = {
    'passphrase':      null,
    'save':            false,
  };

  var shortcuts = {
    '-P': '--passphrase='
  };

  var options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die("Unknown option '" + options['!?'][0] + "'.");
  }

  var email = options['...'][0];
  var passphrase = options.passphrase;

  var save = options.save;

  if (email === undefined) {
    loadProfile();

    if (profile) {
      printId(profile.id);
    } else {
      console.error('No profile data available.');
    }

    return;
  }

  readPassphrase(passphrase, function (error, passphrase) {
    if (error) {
      logError(error);
      die();
    }

    debug("Using passphrase " + passphrase);

    generateId(email, passphrase, function (error, id) {
      if (error) {
        logError(error);
        die();
      }

      if (save) {
        saveId(email, id);
      }

      printId(id);
    });
  });
}

function handleEncryptCommand() {
  var defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'file':            null,
    'output-file':     null,
    'self':            false,
    'anonymous':       false,
  };

  var shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
    '-f': '--file=',
    '-o': '--output-file='
  };

  var options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die("Unknown option '" + options['!?'][0] + "'.");
  }

  var ids = options['...'].slice();

  var email = options.email;
  var passphrase = options.passphrase;

  var file = options.file;
  var outputFile = options['output-file'];

  var includeSelf = options['self'];

  var anonymous = options.anonymous;

  ids.forEach(function (id) {
    if (!validateId(id)) {
      die(id + " doesn't look like a valid miniLock ID.");
    }
  });

  loadProfile();

  if (typeof email !== 'string' && profile) {
    email = profile.email;
  }

  if (!anonymous && typeof email !== 'string') {
    die('Email required.');
  }

  if (!anonymous && typeof passphrase !== 'string' && !process.stdin.isTTY) {
    die('No passphrase given; no terminal available.');
  }

  var checkId = !anonymous && profile && email === profile.email && profile.id;

  readPassphrase(anonymous ? '' : passphrase, 0, function (error, passphrase) {
    if (error) {
      logError(error);
      die();
    }

    if (!anonymous) {
      debug("Using passphrase " + passphrase);
    }

    encryptFile(ids, email, passphrase, file, outputFile, includeSelf,
        anonymous, checkId, function (error, keyPair, length, filename) {
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
  var defaultOptions = {
    'email':           null,
    'passphrase':      null,
    'file':            null,
    'output-file':     null,
  };

  var shortcuts = {
    '-e': '--email=',
    '-P': '--passphrase=',
    '-f': '--file=',
    '-o': '--output-file='
  };

  var options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die("Unknown option '" + options['!?'][0] + "'.");
  }

  var email = options.email;
  var passphrase = options.passphrase;

  var file = options.file;
  var outputFile = options['output-file'];

  loadProfile();

  if (typeof email !== 'string' && profile) {
    email = profile.email;
  }

  if (typeof email !== 'string') {
    die('Email required.');
  }

  if (typeof passphrase !== 'string' && !process.stdin.isTTY) {
    die('No passphrase given; no terminal available.');
  }

  var checkId = profile && email === profile.email && profile.id;

  readPassphrase(passphrase, 0, function (error, passphrase) {
    if (error) {
      logError(error);
      die();
    }

    debug("Using passphrase " + passphrase);

    decryptFile(email, passphrase, file, outputFile, checkId,
        function (error, keyPair, length, filename, senderId,
          originalFilename) {
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

function run() {
  if (process.argv[2] === '--debug') {
    process.argv.splice(2, 1);

    debug = function () {
      console.error.apply(console, arguments);
    }
  }

  var command = process.argv[2];

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
