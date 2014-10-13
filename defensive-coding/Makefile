all: build

include src/src.mk

.PHONY: all build build-manual build-snippets build-manual-html build-manual-epub force clean upload

build: build-src build-manual

build-snippets:
	mkdir -p en-US/snippets
	python scripts/split-snippets.py . \
	  src/*.c src/*.cpp src/*.java src/*.py src/*.go src/*.sh

build-manual: build-snippets
	publican build --formats=html,epub,pdf --langs=en-US

build-manual-html: build-snippets
	publican build --formats=html --langs=en-US

build-manual-epub: build-snippets
	publican build --formats=epub --langs=en-US

build-manual-pdf: build-snippets
	publican build --formats=pdf --langs=en-US

clean: clean-src
	-rm -rf tmp
	-rm -rf en-US/*/snippets

upload:	clean build
	rsync -avP --delete tmp/en-US/html/. file.rdu.redhat.com:public_html/defensive-coding/.
	rsync -avP tmp/en-US/Defensive_Coding*.epub file.rdu.redhat.com:public_html/defensive-coding.epub
	rsync -avP tmp/en-US/pdf/Defensive_Coding*.pdf file.rdu.redhat.com:public_html/defensive-coding.pdf

