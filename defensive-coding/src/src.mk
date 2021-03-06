.PHONY: build-sources

CC = gcc
CXX = g++
GCCGO = gccgo
CWARNFLAGS = -Wall -W -Wno-unused-parameter -Werror=implicit-function-declaration
CXXWARNFLAGS = -Wall -W
CFLAGS = -std=gnu99 -O2 $(CWARNFLAGS) -g
CXXFLAGS = -std=c++03 -O2 $(CXXWARNFLAGS) -g
GOFLAGS = -O2 -Wall -W
LDFLAGS = -g

# List files which should only be compiled for syntax checking.
compile_only += C-Pointers-remaining
compile_only += C-Arithmetic-add
compile_only += C-Arithmetic-mult
compile_only += C-Globals

compile_only += Java-JNI-Pointers
CFLAGS_Java-JNI-Pointers = \
  -I/usr/lib/jvm/java/include -I/usr/lib/jvm/java/include/linux

# List Java files which sould be compiled
compile_java += JavaFinally
compile_java += JavaReadArray
compile_java += JavaSecurityManagerUnprivileged
compile_java += JavaSecurityManagerPrivileged

compile_java += TLSClientOpenJDK
JCFLAGS_TLSClientOpenJDK = -source 1.6 -target 1.6

# List fiels which will be compiled and linked, together with
# additional dependencies.
compile_and_link += C-String-Functions
compile_and_link += TLS-Client-OpenSSL
LIBS_TLS-Client-OpenSSL = -lssl -lcrypto
compile_and_link += TLS-Client-GNUTLS
LIBS_TLS-Client-GNUTLS = -lgnutls
compile_and_link += TLS-Client-NSS
CFLAGS_TLS-Client-NSS = -I/usr/include/nspr4 -I/usr/include/nss3
LIBS_TLS-Client-NSS = -lnss3 -lnspr4 -lssl3
compile_and_link += XML-Parser-Expat
LIBS_XML-Parser-Expat = -lexpat
compile_and_link += XML-Parser-Qt
LIBS_XML-Parser-Qt = -lQtCore -lQtXml
compile_and_link += Go-Error_Handling

# Define preprocessor symbols if certain functions exist.
CHECK_FUNCTION = crypto/X509_check_host/-DHAVE_X509_CHECK_HOST \
	gnutls/gnutls_hash_fast/-DHAVE_GNUTLS_HASH_FAST
DEFINES := $(shell python src/check-function.py $(CHECK_FUNCTION))

CLASS_compile_java := $(patsubst %,src/%.class,$(compile_java))
BIN_compile_and_link := $(patsubst %,src/%,$(compile_and_link))

build-src: $(patsubst %,src/%.o,$(compile_only)) $(CLASS_compile_java) \
	$(BIN_compile_and_link)

clean-src:
	-rm src/*.o src/*.class $(BIN_compile_and_link)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(DEFINES) $(CFLAGS_$(basename $(notdir $@))) -c $< -o $@

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(DEFINES) $(CFLAGS_$(basename $(notdir $@))) -c $< -o $@

src/%.class: src/%.java
	javac $(JCFLAGS_$(basename $(notdir $@))) -Xlint:all $^

src/%: src/%.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LIBS_$(notdir $@))

src/%: src/%.go
	$(GCCGO) $(GOFLAGS) $(LDFLAGS) -o $@ $^

src/TLS-Client-GNUTLS: src/tcp_connect.o
src/TLS-Client-OpenSSL: src/tcp_connect.o src/x509_check_host.o
src/TLS-Client-NSS: src/tcp_connect.o
