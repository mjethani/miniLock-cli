var fs        = require('fs');
var os        = require('os');
var path      = require('path');
var readline  = require('readline');

var BLAKE2s   = require('blake2s-js');
var Base58    = require('bs58');
var nacl      = require('tweetnacl');
var nacl_     = require('nacl-stream');
var scrypt    = require('scrypt-async');
var zxcvbn    = require('zxcvbn');

var help = 'usage: mlck id <email> [--passphrase=<passphrase>]\n'
         + '       mlck encrypt [<id> ...] [--self]\n'
         + '                    --email=<email> [--passphrase=<passphrase>]\n'
         + '                    --file=<file> [--output-file=<output-file>]\n'
         + '                    [--anonymous]\n';

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

function slurpFile(filename, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding;
    encoding = null;
  }

  fs.readFile(filename, { encoding: encoding }, callback);
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

function printUsage() {
  console.error(help);
}

function checkKeyStrength(key) {
  return zxcvbn(key).entropy > 100;
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

function readInput(filename, callback) {
  slurpFile(filename, callback);
}

function writeOutput(contents, filename) {
  if (contents != null) {
    fs.writeFileSync(filename, contents);
  }
}

function readPassphrase(passphrase, callback) {
  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  if (typeof passphrase === 'string') {
    async(function () {
      callback(null, passphrase);
    });
  } else {
    prompt('Passphrase: ', true, function (error, passphrase) {
      callback(error, passphrase);
    });
  }
}

function generateId(email, passphrase, callback) {
  if (!checkKeyStrength(passphrase)) {
    async(function () {
      callback('Passphrase too weak!');
    });
  }

  getKeyPair(passphrase, email, function (keyPair) {
    callback(null, miniLockId(keyPair.publicKey), keyPair);
  });
}

function makeHeader(ids, senderInfo, fileInfo) {
  var ephemeral = nacl.box.keyPair();
  var header = {
    version: 1,
    ephemeral: nacl.util.encodeBase64(ephemeral.publicKey),
    decryptInfo: {}
  };

  ids.forEach(function (id, index) {
    var nonce = nacl.randomBytes(24);
    var publicKey = new Uint8Array(Base58.decode(id).slice(0, 32));

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

function encryptFile(ids, email, passphrase, file, outputFile, includeSelf,
    anonymous, callback) {
  if (anonymous) {
    email = 'Anonymous';
    passphrase = new Buffer(nacl.randomBytes(32)).toString('base64');
  }

  getKeyPair(passphrase, email, function (keyPair) {
    var fromId = miniLockId(keyPair.publicKey);

    var senderInfo = {
      id: fromId,
      secretKey: keyPair.secretKey
    };

    readInput(file, function (error, contents) {
      if (error) {
        callback(error);
        return;
      }

      var fileKey   = nacl.randomBytes(32);
      var fileNonce = nacl.randomBytes(16);

      var chunkSize = Math.max(256, contents.length);

      var encryptor = nacl_.stream.createEncryptor(fileKey, fileNonce,
          chunkSize);
      var hashObject = new BLAKE2s(32);

      var encryptedChunk = encryptor.encryptChunk(new Uint8Array(contents),
          true);
      encryptor.clean();

      hashObject.update(encryptedChunk);

      var fileInfo = {
        fileKey: nacl.util.encodeBase64(fileKey),
        fileNonce: nacl.util.encodeBase64(fileNonce),
        fileHash: nacl.util.encodeBase64(hashObject.digest())
      };

      var header = makeHeader(includeSelf ? ids.concat(fromId) : ids,
          senderInfo, fileInfo);

      var headerLength = new Buffer(4);
      headerLength.writeUInt32LE(header.length);

      var output = [
        'miniLock',
        headerLength,
        header,
        encryptedChunk
      ].reduce(function (output, chunk) {
        return Buffer.concat([ output, new Buffer(chunk, 'utf8') ]);
      },
      new Buffer(0));

      var filename = typeof outputFile === 'string' ? outputFile
        : file + '.minilock';

      try {
        writeOutput(output, filename);
      } catch (error) {
        callback(error);
        return;
      }

      callback(null, fromId, output.length, filename);
    });
  });
}

function handleIdCommand() {
  var defaultOptions = {
    'passphrase':      null,
  };

  var shortcuts = {};

  var options = parseArgs(process.argv.slice(3), defaultOptions, shortcuts);

  if (options['!?'].length > 0) {
    die("Unknown option '" + options['!?'][0] + "'.");
  }

  var email = options['...'][0];
  var passphrase = options.passphrase;

  if (email === undefined) {
    printUsage();
    die();
  }

  readPassphrase(passphrase, function (error, passphrase) {
    if (error) {
      logError(error);
      die();
    }

    generateId(email, passphrase, function (error, id) {
      if (error) {
        logError(error);
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log('Your miniLock ID: ' + id + '.');
        console.log();
      } else {
        console.log(id);
      }
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

  var shortcuts = {};

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

  if ((!anonymous && typeof email !== 'string') || typeof file !== 'string') {
    printUsage();
    die();
  }

  readPassphrase(anonymous ? '' : passphrase, function (error, passphrase) {
    if (error) {
      logError(error);
      die();
    }

    encryptFile(ids, email, passphrase, file, outputFile, includeSelf,
        anonymous, function (error, fromId, length, filename) {
      if (error) {
        logError(error);
        die();
      }

      if (process.stdout.isTTY) {
        console.log();
        console.log('Encrypted from ' + fromId + '.');
        console.log();
        console.log('Wrote ' + length + ' bytes to ' + filename);
        console.log();
      }
    });
  });
}

function run() {
  switch (process.argv[2]) {
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
