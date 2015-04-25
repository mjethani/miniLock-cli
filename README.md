```console
$ npm install -g minilock-cli
minilock-cli@0.2.1 /usr/local/lib/node_modules/minilock-cli
$ mlck
usage: mlck id      [<email>] [--passphrase=<passphrase>] [--save]
       mlck encrypt [<id> ...] [--self] [--email=<email>]
                    [--file=<file>] [--output-file=<output-file>]
                    [--passphrase=<passphrase>]
                    [--anonymous]
       mlck decrypt [--email=<email>]
                    [--file=<file>] [--output-file=<output-file>]
                    [--passphrase=<passphrase>]
       mlck --version
       mlck --license

$ mlck id alice@example.com --passphrase='The quick brown fox jumped over the lazy dog' --save

Your miniLock ID: DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW.

$ echo 'This is a secret between you and me.' > message.txt
$ mlck encrypt psciyAZ9aqFPqS5c27k4VYkNSnbt5ACfMpUB5tnQme9Px -f message.txt --passphrase='The quick brown fox jumped over the lazy dog'

Encrypted from DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW.

Wrote 999 bytes to message.txt.minilock

$ mlck decrypt --email=bob@example.com --passphrase='The quick brown fox jumped over the lazy dog' < message.txt.minilock
--- BEGIN MESSAGE ---
This is a secret between you and me.
--- END MESSAGE ---

Message from DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW.

Original filename: message.txt

```

This is under development.

https://minilock.io/
