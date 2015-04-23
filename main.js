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

var debug = require('debug')('mlck');

var help = 'usage: mlck id      [<email>] [--passphrase=<passphrase>] [--save]\n'
         + '       mlck encrypt [<id> ...] [--self] [--email=<email>]\n'
         + '                    [--file=<file>] [--output-file=<output-file>]\n'
         + '                    [--passphrase=<passphrase>]\n'
         + '                    [--anonymous]\n';

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
  var data = fs.readFileSync(path.resolve(__dirname, 'dictionary'),
      { encoding: 'utf8' });

  dictionary = data.split('\n').map(function (line) {
    return line.replace(/^\s*|\s*$/g, '').replace(/^#.*/, '');
  }).filter(function (line) {
    return line !== '';
  });
}

function randomPassphrase(entropy) {
  if (!dictionary) {
    loadDictionary();
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
      console.log(randomPassphrase(minEntropy), os.EOL);
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
    var publicKey = new Uint8Array(Base58.decode(id).slice(0, 32));

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
      output.push(chunk);
    } else if (output instanceof stream.Writable) {
      output.write(new Buffer(chunk));
    }

    hash.update(chunk);
  }
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
      callback('ID check failed', fromId);
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
        '.mlck-' + hex(fileKey) + '.tmp');
    var encryptedDataFileStream = fs.createWriteStream(encryptedDataFile);

    if (typeof file !== 'string' && process.stdin.isTTY) {
      console.error('Reading from stdin ...');
    }

    var inputStream = typeof file === 'string' ? fs.createReadStream(file)
      : process.stdin;

    inputStream.on('error', function (error) {
      callback(error);
    });

    inputStream.on('readable', function () {
      var chunk = inputStream.read();
      if (chunk !== null) {
        encryptChunk(chunk, encryptor, encryptedDataFileStream, hash);
      }
    });

    inputStream.on('end', function () {
      encryptChunk(null, encryptor, encryptedDataFileStream, hash);

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

      encryptedDataFileStream.end(function () {
        encryptedDataFileStream = fs.createReadStream(encryptedDataFile);

        encryptedDataFileStream.on('error', function (error) {
          callback(error);
        });

        encryptedDataFileStream.on('readable', function () {
          var chunk = encryptedDataFileStream.read();
          if (chunk !== null) {
            if (outputStream) {
              outputStream.write(chunk);
            }

            outputByteCount += chunk.length;
          }
        });

        encryptedDataFileStream.on('end', function () {
          debug("File encryption complete");

          async(function () {
            fs.unlink(encryptedDataFile);

            callback(null, fromId, outputByteCount, filename);
          });
        });
      });
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
        anonymous, checkId, function (error, fromId, length, filename) {
      if (error) {
        if (checkId && fromId && fromId !== checkId) {
          console.error('Incorrect passphrase for ' + email);
        } else {
          logError(error);
        }
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log('Encrypted from ' + fromId + '.');
        console.log();

        if (typeof filename === 'string') {
          console.log('Wrote ' + length + ' bytes to ' + filename);
          console.log();
        }
      }
    });
  });
}

function run() {
  var command = process.argv[2];

  switch (command) {
  case 'id':
    handleIdCommand();
    break;
  case 'encrypt':
    handleEncryptCommand();
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
