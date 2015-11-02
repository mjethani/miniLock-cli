[![GitHub version](https://badge.fury.io/gh/mjethani%2FminiLock-cli.svg)](http://badge.fury.io/gh/mjethani%2FminiLock-cli)

miniLock-cli is a Node.js command line version of the miniLock encryption software.

You can read about miniLock here:

https://minilock.io/

The CLI version is written from scratch using the same crypto libraries as the original Google Chrome app.

## Installation

Install [Node.js](https://nodejs.org/).

Then run the following command:

```console
$ npm install -g minilock-cli@0.2.10
/usr/local/bin/mlck -> /usr/local/lib/node_modules/minilock-cli/mlck
minilock-cli@0.2.10 /usr/local/lib/node_modules/minilock-cli
├── bs58@2.0.1
├── nacl-stream@0.3.3
├── scrypt-async@1.0.1
├── blake2s-js@1.0.3
├── tweetnacl@0.13.1
└── zxcvbn@1.0.0
$ 
```

Verify the installation:

```console
$ mlck --version
miniLock-cli v0.2.10
$ 
```

## Tutorial

Let's get started!

### Generate an ID

First, you need a miniLock ID.

```console
$ mlck id alice@example.com --save
period dry million besides usually wild everybody

Passphrase (leave blank to quit): 
```

Enter a good passphrase, such as the one shown before the prompt. You need [~100 bits of entropy](https://xkcd.com/936/). Any 7-8 _randomly selected_ words out of the English lexicon should be fine.

If you insist on using a simple passphrase like "hello" (not recommended at all!), you must use the `--passphrase` option.

```console
$ mlck id alice@example.com --save --passphrase='hello'

Your miniLock ID: LRFbCrhCeN2uVCdDXd2bagoCM1fVcGvUzwhfVdqfyVuhi.

$ 
```

You can look up your miniLock ID any time.

```console
$ mlck id

Your miniLock ID: LRFbCrhCeN2uVCdDXd2bagoCM1fVcGvUzwhfVdqfyVuhi.

$ 
```

Once you're sure about it (i.e. you've picked a good passphrase that is also easy to remember), you can publish it [on Twitter](https://twitter.com/100101010000/status/589422009534164992), [on your website](https://blog.manishjethani.com/minilock.txt.asc), and on various other channels. If people know your miniLock ID they can encrypt information to you even anonymously.

### Encrypt a file

Let's say you have a text file called `message.txt` containing the following message:

```
The PIN code is 1337.

Withdraw 10,100 euros and meet me at Frederick Street at 5pm.

Don't forget my chocolate!
```

Now you can encrypt it to the miniLock ID gT1csvpmQDNRQSMkqc1Sz7ZWYzGZkmedPKEpgqjdNTy7Y using the following command:

```console
$ mlck encrypt -f message.txt gT1csvpmQDNRQSMkqc1Sz7ZWYzGZkmedPKEpgqjdNTy7Y
Passphrase (leave blank to quit): 
```

Once again, it asks you for your passphrase. This time it's to identify you as the sender. If you wish to send anonymously (using a randomly generated sender ID), use the `--anonymous` option.

Note that you _can_ send anonymously even if the message itself contains identifying information.

Here's the full interaction:

```console
$ mlck encrypt -f message.txt gT1csvpmQDNRQSMkqc1Sz7ZWYzGZkmedPKEpgqjdNTy7Y
Passphrase (leave blank to quit): 

Encrypted from LRFbCrhCeN2uVCdDXd2bagoCM1fVcGvUzwhfVdqfyVuhi.

Wrote 1075 bytes to message.txt.minilock

$ 
```

Now you can send the file `message.txt.minilock` to its intended recipient.

### Decrypt a file

Your friend Bob receives a file called `message.txt.minilock` in the mail. Luckily he has miniLock-cli installed. He proceeds to decrypt the file using his email address and his passphrase.

```console
$ mlck decrypt -f message.txt.minilock -e bob@example.com --passphrase='puff magic dragon sea frolic autumn mist lee'
--- BEGIN MESSAGE ---
The PIN code is 1337.

Withdraw 10,100 euros and meet me at Frederick Street at 5pm.

Don't forget my chocolate!
--- END MESSAGE ---

Message from LRFbCrhCeN2uVCdDXd2bagoCM1fVcGvUzwhfVdqfyVuhi.

Original filename: message.txt

$ 
```

Bob knows exactly what you mean by "Don't forget my chocolate!"

## Links

Here are some useful links:

 *  [miniLock README.md](https://github.com/kaepora/miniLock/blob/master/README.md)
 *  [Usable Crypto: Introducing miniLock (HOPE X)](https://vimeo.com/101237413)
 *  [The Ultra-Simple App That Lets Anyone Encrypt Anything](http://www.wired.com/2014/07/minilock-simple-encryption/)
 *  [A Few Thoughts on Cryptographic Engineering: What's the matter with PGP?](http://blog.cryptographyengineering.com/2014/08/whats-matter-with-pgp.html)

