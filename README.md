```console
$ npm install -g mlck
mlck@0.1.8 /usr/local/lib/node_modules/mlck
$ mlck
usage: mlck id      [<email>] [--passphrase=<passphrase>] [--save]
       mlck encrypt [<id> ...] [--self] [--email=<email>]
                    [--file=<file>] [--output-file=<output-file>]
                    [--passphrase=<passphrase>]
                    [--anonymous]

$ mlck id alice@example.com --passphrase='The quick brown fox jumped over the lazy dog' --save

Your miniLock ID: DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW.

$ echo 'This is a secret between you and me.' > message.txt
$ mlck encrypt psciyAZ9aqFPqS5c27k4VYkNSnbt5ACfMpUB5tnQme9Px --passphrase='The quick brown fox jumped over the lazy dog' --file=message.txt

Encrypted from DtgoeFAZv34x9UXLdW6XuZaZeAmqV2WdSuTQXvWFm59QW.

Wrote 703 bytes to message.txt.minilock

$ 
```

This is under development.

https://minilock.io/
