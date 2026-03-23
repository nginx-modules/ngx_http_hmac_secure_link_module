#!/usr/bin/perl
# 05_integration.t
#
# Separators, configuration edge cases, and real-world access-control patterns
#
# Prerequisites:
#   cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
#
# Run:
#   prove -I t/lib -v t/05_integration.t

use strict;
use warnings;

use Test::Nginx::Socket;
use lib 't/lib';
use HmacSecureLink qw(:all);
use POSIX qw(strftime);

# ---------------------------------------------------------------------------
# Make all HmacSecureLink helpers available inside --- request eval and
# --- response_body eval blocks.  Test::Base evaluates those blocks in the
# Test::Base::Filter package, so functions imported into main:: are invisible
# there.  Installing aliases into Test::Base::Filter:: solves this for both
# plain subs and constant subs (which are implemented as subs with no args).
# ---------------------------------------------------------------------------
BEGIN {
    no strict 'refs';
    for my $fn (qw(
        tok256 tok512 tok1 tokmd5 b64url
        unix_now unix_past unix_far
        iso_offset iso_z iso_past
        rfc7231_now rfc7231_past
        uri_escape
    )) {
        *{"Test::Base::Filter::$fn"} = \&{"HmacSecureLink::$fn"};
    }
    for my $c (qw(
        SECRET SECRET2
        TS_FIXED TS_FIXED_ISO TS_FIXED_Z TS_FIXED_RFC7231
    )) {
        *{"Test::Base::Filter::$c"} = \&{"HmacSecureLink::$c"};
    }
}

# 14 tests, 25 assertions total
our $repeat = repeat_each();
plan tests => 25 * $repeat;

no_shuffle();
run_tests();

__DATA__
# ===========================================================================
# CATEGORY 8 — Separator choices in secure_link_hmac_message
# ===========================================================================

=== TEST 8.1: pipe (|) separator — recommended convention
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 8.2: colon (:) separator
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri:$arg_ts:$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/t:$ts:$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 8.3: slash (/) separator
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri/$arg_ts/$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/t/$ts/$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 8.4: no separator — fields concatenated directly
# Valid but potentially ambiguous; documents the behaviour explicitly.
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri$arg_ts$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/t${ts}${e}");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 8.5: pipe on server, colon used by client — rejected
# Demonstrates that any separator mismatch invalidates the HMAC.
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/t:$ts:$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body eval
""
--- error_code: 200

=== TEST 9.1: no directives configured — not_found
--- config
    location /t {
        return 200 "$secure_link_hmac";
    }
--- request
GET /t?st=anything&ts=1234567890&e=3600
--- response_body eval
""
--- error_code: 200

=== TEST 9.2: secure_link_hmac_message missing — not_found
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 9.3: secure_link_hmac_secret missing — not_found
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 9.4: literal string message (no variables) — valid
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "static-message";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
"GET /t?st=" . tok256("static-message")
--- response_body: 1
--- error_code: 200

=== TEST 10.1: valid token — returns 200 with if/return guard
--- config
    location /protected/ {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "OK";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/protected/file.txt|$ts|$e");
"GET /protected/file.txt?st=$tok&ts=$ts&e=$e"
--- response_body: OK
--- error_code: 200

=== TEST 10.2: wrong token — returns 403
--- config
    location /protected/ {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "OK";
    }
--- request eval
my $ts  = unix_now();
my $e   = 3600;
my $tok = tok256("/protected/file.txt|$ts|$e", SECRET2);
"GET /protected/file.txt?st=$tok&ts=$ts&e=$e"
--- error_code: 403

=== TEST 10.3: expired token — returns 403 (value "0" != "1")
--- config
    location /protected/ {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "OK";
    }
--- request eval
my $ts  = unix_past();
my $e   = 60;
my $tok = tok256("/protected/file.txt|$ts|$e");
"GET /protected/file.txt?st=$tok&ts=$ts&e=$e"
--- error_code: 403

=== TEST 10.4: no parameters — returns 403
--- config
    location /protected/ {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "OK";
    }
--- request
GET /protected/file.txt
--- error_code: 403

=== TEST 10.5: distinguish expired (410) from invalid (403) separately
--- config
    location /protected/ {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac = "0") { return 410 "Gone"; }
        if ($secure_link_hmac != "1") { return 403 "Forbidden"; }
        return 200 "OK";
    }
--- request eval
my $ts  = unix_past();
my $e   = 60;
my $tok = tok256("/protected/file.txt|$ts|$e");
"GET /protected/file.txt?st=$tok&ts=$ts&e=$e"
--- response_body: Gone
--- error_code: 410
