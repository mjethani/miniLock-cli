all: build

build watch: babel_flags += -s
watch: babel_flags += -w

build watch:
	babel $(babel_flags) -d build src

test:
	babel-tape-runner tests/**/*.js

$(VERSION):
	npm version $(VERSION) --no-git-tag-version

version: $(VERSION)

.npmignore: .gitignore
	sort -ru .gitignore | grep -v '^build$$' > .npmignore
	echo '.gitignore .npmignore Makefile *.sh' | tr ' ' '\n' >> .npmignore

.kbignore: .npmignore
	sort -ru .npmignore > .kbignore
	echo .git >> .kbignore
	echo build >> .kbignore

sign: .kbignore
	keybase dir sign -p kb

verify:
	keybase dir verify

ifdef VERSION
tag: version sign
	git commit -am 'Signed PGP:E6B74303'
	git tag v$(VERSION)

publish:
	git checkout master
	git merge develop
	touch .gitignore
	make tag VERSION=$(VERSION)
	make
	npm publish
endif

clean:
	rm -rf build
	git checkout SIGNED.md

.PHONY: clean version build watch sign verify tag publish

