# htgen - one binary, three C/C++ files and two submodules.
#
#   make            build ./htgen
#   make install    copy it to $(BINDIR) (default /usr/local/bin)
#   make uninstall
#   make clean
#
# PREFIX/DESTDIR follow the usual convention, so a packager can stage it:
#   make install PREFIX=$HOME/.local
#   make install DESTDIR=/tmp/stage PREFIX=/usr
#
# Every dependency is a submodule:
#   git submodule update --init --recursive
# ls-hpack pulls xxhash as a submodule of its own, hence --recursive.
#
# liburing is vendored rather than taken from the system on purpose. The
# distro copy is routinely older than the ring features this tool exists
# to use - Debian trixie ships 2.5, and send/recv BUNDLES arrived in 2.6.
# Built against 2.5 the code still compiles (the two uses are guarded) but
# it silently spends one completion per buffer, which is the opposite of
# the point. USE_SYSTEM_URING=1 takes the system copy anyway.

CXX      ?= c++
CC       ?= cc
OPT      ?= -O3 -march=native
CXXFLAGS ?= $(OPT) -std=c++20 -Wall -Wextra

# Which commit this binary is, baked in. A build date says when somebody
# typed make, which is not a version: two builds of the same commit have
# two dates, and that is how a bench came to compare a client with
# itself and read the difference as the server's. `-dirty` when the tree
# had uncommitted changes.
COMMIT := $(shell git -C $(dir $(firstword $(MAKEFILE_LIST))) describe --always --dirty --abbrev=8 2>/dev/null || echo unknown)
CFLAGS   ?= $(OPT) -std=gnu99 -Wall

HPACK    := deps/ls-hpack
PHR      := deps/picohttpparser
INCLUDES := -Isrc -I$(HPACK) -I$(HPACK)/deps/xxhash -I$(PHR)

URING := deps/liburing
ifdef USE_SYSTEM_URING
URING_CFLAGS := $(shell pkg-config --cflags liburing 2>/dev/null)
URING_LIBS   := $(shell pkg-config --libs liburing 2>/dev/null || echo -luring)
URING_DEP    :=
else
URING_CFLAGS := -I$(URING)/src/include
URING_LIBS   := $(URING)/src/liburing.a
URING_DEP    := $(URING)/src/liburing.a
endif

# TLS is off unless a path to mruby-ktls says otherwise, and it is a
# PATH rather than a submodule on purpose: the library needs an OpenSSL
# that was built WITH kTLS, and the distribution's usually was not
# (Ubuntu's libssl.so.3 exports no ktls symbol). mruby-ktls builds one
# and keeps it; point OPENSSL at that directory.
#
#   make KTLS=~/webmachine-mruby/mruby/build/repos/host/mruby-ktls \
#        OPENSSL=~/webmachine-mruby/mruby/build/host/mrbgems/mruby-ktls/openssl
#
# Without it htgen builds as before and --tls refuses by name.
ifdef KTLS
OPENSSL  ?= $(KTLS)/build/openssl
# TWO include paths, and both are needed: a configured OpenSSL puts its
# generated headers in the build directory and keeps the rest in its
# source tree. One of them alone fails on <openssl/e_ostime.h>.
OSSL_INC := -I$(OPENSSL)/include -I$(KTLS)/deps/openssl/include
TLS_CFLAGS := -DHTGEN_TLS=1 -I$(KTLS)/include $(OSSL_INC)
TLS_LIBS   := -L$(OPENSSL) -lssl -lcrypto -Wl,-rpath,$(OPENSSL)
TLS_OBJS   := build/ktls.o
else
TLS_CFLAGS :=
TLS_LIBS   :=
TLS_OBJS   :=
endif

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL ?= install

OBJS := build/htgen.o build/lshpack.o build/xxhash.o build/picohttpparser.o $(TLS_OBJS)

htgen: $(OBJS) $(URING_DEP)
	$(CXX) $(OBJS) $(URING_LIBS) $(TLS_LIBS) -o $@

# The library is one C file. It is compiled here rather than taken as an
# archive because mruby-ktls builds inside mruby's build system, and a
# load generator is not going to carry one.
build/ktls.o: $(KTLS)/src/ktls.c | build
	$(CC) $(CFLAGS) -I$(KTLS)/include $(OSSL_INC) -c $< -o $@

# liburing's own build. Its configure writes config-host.mak, which its
# Makefile needs, so both run here and only when the archive is missing.
$(URING)/src/liburing.a:
	@test -f $(URING)/configure || { echo "deps/liburing is empty - run: git submodule update --init --recursive" >&2; false; }
	cd $(URING) && ./configure >/dev/null && $(MAKE) -s -C src

build:
	@mkdir -p build

build/htgen.o: src/htgen.cpp src/h2_wire.hpp $(URING_DEP) | build $(HPACK)/lshpack.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(URING_CFLAGS) $(TLS_CFLAGS) -DHTGEN_COMMIT='"$(COMMIT)"' -c $< -o $@

# The C dependencies are C. Feeding lshpack.c to a C++ compiler fails on
# its designated initialisers and its implicit void* conversions - the
# error is a wall of "sorry, unimplemented", so it is worth saying here.
build/lshpack.o: $(HPACK)/lshpack.c | build
	$(CC) $(CFLAGS) $(INCLUDES) -DXXH_HEADER_NAME='"xxhash.h"' -c $< -o $@

build/xxhash.o: $(HPACK)/deps/xxhash/xxhash.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/picohttpparser.o: $(PHR)/picohttpparser.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(HPACK)/lshpack.h:
	@echo "deps/ls-hpack is empty - run: git submodule update --init --recursive" >&2
	@false

# One binary and nothing else - no libraries, no data files, no man page
# yet. -D makes the directory, so a staged PREFIX needs no mkdir first.
install: htgen
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 htgen $(DESTDIR)$(BINDIR)/htgen

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/htgen

clean:
	rm -rf build htgen
	-$(MAKE) -s -C $(URING) clean 2>/dev/null

.PHONY: clean install uninstall
