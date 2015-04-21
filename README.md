```console
$ npm install -g mlck
mlck@0.1.6 /usr/local/lib/node_modules/mlck
$ mlck
usage: mlck id <email> [--passphrase=<passphrase>]
       mlck encrypt [<id> ...] [--self]
                    --email=<email> [--passphrase=<passphrase>]
                    --file=<file> [--output-file=<output-file>]

$ mlck id alice@example.com --passphrase='The brown fox jumped over the dog'
Passphrase too weak!
$ mlck id alice@example.com --passphrase='The quick brown fox jumped over the lazy dog'
DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW
$ echo 'This is a secret between you and me.' > message.txt
$ mlck encrypt psciyAZ9aqFPqS5c27k4VYkNSnbt5ACfMpUB5tnQme9Px --email=alice@example.com --passphrase='The quick brown fox jumped over the lazy dog' --file=message.txt
Wrote 703 bytes to message.txt.minilock
$ 
```

This is under development.

https://minilock.io/
