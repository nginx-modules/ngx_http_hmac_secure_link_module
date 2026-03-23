#!/usr/bin/perl
# 04_variables.t
#
# Embedded variables — $secure_link_hmac_expires and $secure_link_hmac_token
#
# Prerequisites:
#   cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
#
# Run:
#   prove -I t/lib -v t/04_variables.t

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

# 10 tests, 20 assertions total
our $repeat = repeat_each();
plan tests => 20 * $repeat;

no_shuffle();
run_tests();

__DATA__
# ===========================================================================
# CATEGORY 6 — $secure_link_hmac_expires variable
# ===========================================================================

=== TEST 6.1: expires variable reflects the value supplied in the request
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "$secure_link_hmac_expires";
    }
--- request eval
my $ts  = unix_now();
my $e   = 7200;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 7200
--- error_code: 200

=== TEST 6.2: expires variable is unset when no expiry field present
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "expires=[$secure_link_hmac_expires]";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: expires=[]
--- error_code: 200

=== TEST 6.3: expires variable correct for a very large expiry value
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "$secure_link_hmac_expires";
    }
--- request eval
my $ts  = unix_now();
my $e   = 315360000;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 315360000
--- error_code: 200

=== TEST 6.4: expires variable — ISO 8601 timestamp
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "$secure_link_hmac_expires";
    }
--- request eval
my $ts     = iso_offset();
my $e      = 900;
my $tok    = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 900
--- error_code: 200

=== TEST 6.5: expires variable — RFC 7231 with expiry — internal comma safe
# Uses nginx set $ts with TS_FIXED_RFC7231 to avoid RFC 7231's embedded
# spaces and comma from breaking the HTTP request line when sent as $arg_ts.
# Verifies that the embedded comma in "Fri, 20 Nov ..." does not corrupt
# the expires substring stored in the module's request context.
--- config
    location /t {
        set $ts "Fri, 20 Nov 2286 17:46:39 GMT";
        set $e  "1800";
        secure_link_hmac         "$arg_st,$ts,$e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts|$e";
        secure_link_hmac_algorithm sha256;
        if ($secure_link_hmac != "1") { return 403; }
        return 200 "$secure_link_hmac_expires";
    }
--- request eval
my $tok = tok256("/t|" . TS_FIXED_RFC7231 . "|1800");
"GET /t?st=$tok"
--- response_body: 1800
--- error_code: 200

=== TEST 7.1: generated SHA-256 token matches independently computed HMAC
# Uses TS_FIXED so that both the request URL and the expected response body
# reference the same timestamp constant, eliminating any clock-second race.
--- config
    location /t {
        set $ts $arg_ts;
        set $e  $arg_e;
        secure_link_hmac_message "$uri|$ts|$e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac_token";
    }
--- request eval
"GET /t?ts=" . TS_FIXED . "&e=3600"
--- response_body eval
tok256("/t|" . TS_FIXED . "|3600")
--- error_code: 200

=== TEST 7.2: generated SHA-512 token matches independently computed HMAC
--- config
    location /t {
        set $ts $arg_ts;
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm sha512;
        return 200 "$secure_link_hmac_token";
    }
--- request eval
"GET /t?ts=" . TS_FIXED
--- response_body eval
tok512("/t|" . TS_FIXED)
--- error_code: 200

=== TEST 7.3: generated MD5 token matches independently computed HMAC
--- config
    location /t {
        set $ts $arg_ts;
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm md5;
        return 200 "$secure_link_hmac_token";
    }
--- request eval
"GET /t?ts=" . TS_FIXED
--- response_body eval
tokmd5("/t|" . TS_FIXED)
--- error_code: 200

=== TEST 7.4: $secure_link_hmac_token output is valid base64url without padding
# SHA-256 produces 32 bytes = 43 base64url characters (no trailing padding).
--- config
    location /t {
        set $ts $arg_ts;
        set $e  $arg_e;
        secure_link_hmac_message "$uri|$ts|$e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac_token";
    }
--- request eval
"GET /t?ts=" . unix_now() . "&e=3600"
--- response_body_like: ^[A-Za-z0-9_-]{43}$
--- error_code: 200

=== TEST 7.5: SHA-512 token output is 86 base64url characters
# SHA-512 produces 64 bytes = 86 base64url characters (no trailing padding).
--- config
    location /t {
        set $ts $arg_ts;
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_algorithm sha512;
        return 200 "$secure_link_hmac_token";
    }
--- request eval
"GET /t?ts=" . unix_now()
--- response_body_like: ^[A-Za-z0-9_-]{86}$
--- error_code: 200

