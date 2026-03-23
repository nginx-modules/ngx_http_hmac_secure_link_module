#!/usr/bin/perl
# 03_algorithms.t
#
# HMAC algorithm variants — SHA-1, SHA-256, SHA-512, MD5, unknown algorithm
#
# Prerequisites:
#   cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
#
# Run:
#   prove -I t/lib -v t/03_algorithms.t

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

# 5 tests, 10 assertions total
our $repeat = repeat_each();
plan tests => 10 * $repeat;

no_shuffle();
run_tests();

__DATA__
# ===========================================================================
# CATEGORY 5 — Algorithm variants
# ===========================================================================

=== TEST 5.1: SHA-1 algorithm
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha1;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok1("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 5.2: SHA-512 algorithm
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha512;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok512("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 5.3: MD5 algorithm
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm md5;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tokmd5("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 5.4: SHA-256 token presented to a SHA-512 location — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha512;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 5.5: unknown algorithm — variable empty, link invalid
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha999_does_not_exist;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

