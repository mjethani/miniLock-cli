var fs        = require('fs');
var os        = require('os');
var path      = require('path');
var readline  = require('readline');

var BLAKE2s   = require('blake2s-js');
var Base58    = require('bs58');
var nacl      = require('tweetnacl');
var scrypt    = require('scrypt-async');

var zxcvbn    = require('./lib/zxcvbn').zxcvbn;

var help = 'usage: mlck id <email>\n';

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
  salt = nacl.util.decodeUTF8(salt);
  getScryptKey(keyHash.digest(), salt, function(keyBytes) {
    if (typeof(callback) === 'function') {
      callback(nacl.box.keyPair.fromSecretKey(keyBytes));
    }
  });
}

function getMiniLockId(publicKey) {
  var id = new Uint8Array(33);
  for (var i = 0; i < publicKey.length; i++) {
    id[i] = publicKey[i];
  }
  var hash = new BLAKE2s(1);
  hash.update(publicKey);
  id[32] = hash.digest()[0];
  return Base58.encode(id);
}

function generateId(email, passphrase) {
  if (email === undefined) {
    printUsage();
    die();
  }

  if (passphrase === undefined) {
    prompt('Passphrase: ', true, function (error, passphrase) {
      if (error) {
        logError(error);
        die();
      }

      generateId(email, passphrase);
    });
  } else {
    if (!checkKeyStrength(passphrase)) {
      die('Passphrase too weak!');
    }

    getKeyPair(passphrase, email, function (keyPair) {
      console.log(getMiniLockId(keyPair.publicKey));
    });
  }
}

function run() {
  switch (process.argv[2]) {
  case 'id':
    generateId(process.argv[3]);
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
