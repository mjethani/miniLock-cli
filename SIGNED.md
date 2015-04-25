##### Signed by https://keybase.io/mj
```
-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

iQIcBAABCgAGBQJVOvMGAAoJEPvclVzmt0MDcPkP/0sPZvPc6V5ddrtXsP9YBcmp
R4n7cUalFMXCaPY+NPDV3DTyA+f+Uz2TVugiP69eSfRS9FGWmtzCHAqsMzuHc8N/
OrhVG9FsjxtbPypxaqug8JwXFl+sqV64FsfKdehOfrtSvZSKcq5cwK8mXhfUggVu
C16ylXedUzDp7kGb/TGhalJef0JLlXForn86WloZD/i1GVoZXUUkcCs0vnaDAczr
GUk3ZZFQ+npqD381F4aINm7Tfes+Qb8aktrWU3+9h/wQ03F8/dnYp3sQ+2bp5574
4zSHGEaLcY6LIq/7LsQ3FOWhS31WD3EWGWB+QenP5EpXJe8nJkJFYQdSdqtmfDMq
bQyArI6cOmfeMdSubN2HrmW9JFUH23bqcXJFYnZyybDwXULabxXqk0V4+6uEz5nj
syvurpwKvb1UTpJ0cVMgFTlIVNvl0W7T7etUdeyO56bhQXFMA6ArkNbv5bjlUzme
MgJJMewZbcF/p2EsMYXAbHvU4HDfmhLaNWZJ//BdFHMfhr9XA1LGxc5dZNbeXRb8
LO2CTJgQhRHlNqATMOok7fyHMdv+Q6xL7aFxSgCK5R1bOPkjbCJ4mr7wldsjAhy/
6OoUqi7xiAe/aUT18SlbCOa8SbT1Jg1nNlmPW+XwvzHIv278sH2IKdv/ADQdo+Ph
wPwoxFqXnoUAODggUTXC
=m881
-----END PGP SIGNATURE-----

```

<!-- END SIGNATURES -->

### Begin signed statement 

#### Expect

```
size   exec  file              contents                                                        
             ./                                                                                
87             .kbignore       5f9f9b495e96f1c46eb15bd35e3d0ddd77841af255b954e9f203e791abab16e4
732            LICENSE         e7fa0c5707aa3eae23e841a73ea57cda21f3bd87b90ba3ea254ca5bdec29d386
1420           README.md       d6603f0df7e268ca289e02867891298d92dcdd258aa728c58611022b887db312
6016           dictionary      a23bd82e1e917dec4a63a92746267d3b3aa92fb0cae7cff7f07aaf30a17a707f
               help/                                                                           
219              decrypt.help  6b8082d6eb25905d159da48c8022766e9fe798320c02b5b7fc4745f8744744a0
679              default.help  d9ec43e71b8af33917eb44c3a7e5bbcd1f3ed2e660a2a65f5f6f020463be501c
310              encrypt.help  6e2260014c1ca24bd00a36468ebe932fa6f06d79e71128b3d866bc0b371b2017
75               help.help     b131efdb5be0962265704bcd146b05e207231436926bbcf06a24e4c8a21e5148
122              id.help       4f028b9e0b517c55d68f97405b928ab612dea1380df583848d902b718f7212b3
31013          main.js         df31cc96490564d756d7d488f1a8964b990d03d855c16dd7299dc6905af646c9
47     x       mlck            ad1d918f07b08400ddd47b71001b6ee4928c5f6bbe50ddb75cb1d024d47dcfbe
1237           package.json    9bc12fea22ec4f647086494264a8934b0bad6e39749c70faf13026e8cdc88e61
```

#### Ignore

```
/SIGNED.md
```

#### Presets

```
git      # ignore .git and anything as described by .gitignore files
dropbox  # ignore .dropbox-cache and other Dropbox-related files    
kb       # ignore anything as described by .kbignore files          
```

<!-- summarize version = 0.0.9 -->

### End signed statement

<hr>

#### Notes

With keybase you can sign any directory's contents, whether it's a git repo,
source code distribution, or a personal documents folder. It aims to replace the drudgery of:

  1. comparing a zipped file to a detached statement
  2. downloading a public key
  3. confirming it is in fact the author's by reviewing public statements they've made, using it

All in one simple command:

```bash
keybase dir verify
```

There are lots of options, including assertions for automating your checks.

For more info, check out https://keybase.io/docs/command_line/code_signing