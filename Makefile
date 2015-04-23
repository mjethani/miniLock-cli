all: SIGNED.md

$(VERSION):
	bash version.sh $(VERSION)

version: $(VERSION)

.npmignore: .gitignore
	sort -ru .gitignore > .npmignore
	echo '.gitignore .npmignore Makefile *.sh' | tr ' ' '\n' >> .npmignore

.kbignore: .npmignore
	sort -ru .npmignore > .kbignore

SIGNED.md: .kbignore
	keybase dir sign

verify:
	keybase dir verify

ifdef VERSION
tag: SIGNED.md
	git commit -am 'Signed PGP:E6B74303'
	git tag v$(VERSION)
endif

clean:
	git checkout SIGNED.md

.PHONY: clean version SIGNED.md verify tag

