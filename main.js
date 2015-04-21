var fs        = require('fs');
var os        = require('os');
var path      = require('path');
var readline  = require('readline');

var BLAKE2s   = require('blake2s-js');
var Base58    = require('bs58');
var nacl      = require('tweetnacl');
var scrypt    = require('scrypt-async');

var zxcvbn    = require('./lib/zxcvbn').zxcvbn;

var help = 'usage: mlck id <email> [--passphrase=<passphrase>]\n';

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
    callback(null, miniLockId(keyPair.publicKey));
  });
}

function handleId() {
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

      console.log(id);
    });
  });
}

function run() {
  switch (process.argv[2]) {
  case 'id':
    handleId();
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
