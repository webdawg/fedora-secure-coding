all: build

include src/src.mk

.PHONY: all build build-manual build-snippets build-manual-html build-manual-epub force clean upload

build: build-src build-manual

build-snippets:
	for p in en-US/* ; do test -d $$p && mkdir -p $$p/snippets; done
	python scripts/split-snippets.py . \
	  src/*.c src/*.cpp src/*.java src/*.py

build-manual: build-snippets
	publican build --format=html,epub,pdf --lang=en-US

build-manual-html: build-snippets
	publican build --format=html --lang=en-US

build-manual-epub: build-snippets
	publican build --format=epub --lang=en-US

build-manual-pdf: build-snippets
	publican build --format=pdf --lang=en-US

clean: clean-src
	-rm -rf tmp
	-rm -rf en-US/*/snippets

upload:	clean build
	rsync -avP --delete tmp/en-US/html/. file.rdu.redhat.com:public_html/defensive-coding/.
	rsync -avP tmp/en-US/Defensive_Coding*.epub file.rdu.redhat.com:public_html/defensive-coding.epub
	rsync -avP tmp/en-US/pdf/Defensive_Coding*.pdf file.rdu.redhat.com:public_html/defensive-coding.pdf

