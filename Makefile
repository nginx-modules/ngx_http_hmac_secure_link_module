# Makefile — ngx_http_hmac_secure_link_module
#
# Common targets:
#   make build        Download NGINX source and compile the module into it
#   make test         Run the Perl test suite with prove
#   make lint         Run cppcheck static analysis
#   make clean        Remove the downloaded NGINX source tree
#   make distclean    Also remove the downloaded NGINX tarball
#
# Configuration:
#   NGINX_VERSION     NGINX version to download (default: 1.26.3)
#   NGINX_BINARY      Path to an already-compiled nginx binary.
#                     Set this to skip 'make build' and use an existing binary.
#                     Default: $(NGINX_SRC)/objs/nginx
#   MODULE_DIR        Directory containing this Makefile (default: current dir)

NGINX_VERSION ?= 1.26.3
MODULE_DIR    ?= $(CURDIR)
NGINX_TARBALL  = nginx-$(NGINX_VERSION).tar.gz
NGINX_SRC      = nginx-$(NGINX_VERSION)
NGINX_BINARY  ?= $(NGINX_SRC)/objs/nginx

# Number of parallel make jobs for the NGINX build.
JOBS ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

# prove flags: verbose, include t/lib for HmacSecureLink.pm.
PROVE_INCLUDE = -I$(MODULE_DIR)/t/lib

.PHONY: all build test lint clean distclean help

all: build

## Download NGINX source, configure with the module, and compile.
build: $(NGINX_BINARY)

$(NGINX_BINARY): $(NGINX_SRC)/Makefile
	$(MAKE) -C $(NGINX_SRC) -j$(JOBS)

$(NGINX_SRC)/Makefile: $(NGINX_SRC)/configure
	cd $(NGINX_SRC) && ./configure \
		--with-http_ssl_module \
		--with-http_v2_module  \
		--add-module=$(MODULE_DIR) \
		--with-cc-opt="-Wall -Wextra -Wno-unused-parameter"

$(NGINX_SRC)/configure: $(NGINX_TARBALL)
	tar xf $(NGINX_TARBALL)
	touch $@

$(NGINX_TARBALL):
	curl -fsSL "https://nginx.org/download/$(NGINX_TARBALL)" -o $(NGINX_TARBALL)

## Run the Perl test suite.
## Requires: cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
test: $(NGINX_BINARY)
	TEST_NGINX_BINARY=$(NGINX_BINARY) \
	prove $(PROVE_INCLUDE) -v t/

## Syntax-check the test file without running it.
test-syntax:
	for f in t/01_basic.t t/02_timestamps.t t/03_algorithms.t \
	         t/04_variables.t t/05_integration.t; do \
		perl -c -I$(MODULE_DIR)/t/lib "$$f" || exit 1; \
	done

## Run cppcheck static analysis on the C source.
lint:
	cppcheck \
		--enable=all   \
		--inconclusive \
		--std=c99      \
		--suppress=missingIncludeSystem \
		--suppress=variableScope \
		--error-exitcode=1 \
		ngx_http_hmac_secure_link_module.c

## Install Perl test dependencies via cpanm.
cpan-deps:
	cpanm --notest \
		Test::Nginx   \
		Digest::SHA   \
		Digest::HMAC  \
		Digest::HMAC_MD5 \
		URI::Escape

## Remove the compiled NGINX source tree (keeps the tarball).
clean:
	rm -rf $(NGINX_SRC)

## Remove everything including the downloaded tarball.
distclean: clean
	rm -f $(NGINX_TARBALL)

help:
	@echo "Targets:"
	@echo "  build       Download nginx $(NGINX_VERSION) and compile with module"
	@echo "  test        Run prove test suite (builds first if needed)"
	@echo "  test-syntax Perl -c syntax check on the test file"
	@echo "  lint        Run cppcheck on ngx_http_hmac_secure_link_module.c"
	@echo "  cpan-deps   Install Perl test dependencies via cpanm"
	@echo "  clean       Remove nginx source tree"
	@echo "  distclean   Remove nginx source tree and tarball"
	@echo ""
	@echo "Variables:"
	@echo "  NGINX_VERSION  $(NGINX_VERSION)"
	@echo "  NGINX_BINARY   $(NGINX_BINARY)"
	@echo "  JOBS           $(JOBS)"
