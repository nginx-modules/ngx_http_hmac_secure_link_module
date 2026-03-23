#!/usr/bin/perl
# 01_basic.t
#
# Basic HMAC verification — permanent links, malformed and oversized tokens
#
# Prerequisites:
#   cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
#
# Run:
#   prove -I t/lib -v t/01_basic.t

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

# 7 tests, 14 assertions total
our $repeat = repeat_each();
plan tests => 14 * $repeat;

no_shuffle();
run_tests();

__DATA__
# ===========================================================================
# CATEGORY 1 — Basic HMAC verification (no timestamp, no expiry)
# ===========================================================================

=== TEST 1.1: valid token — no timestamp field (permanent link)
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
"GET /t?st=" . tok256("/t")
--- response_body: 1
--- error_code: 200

=== TEST 1.2: wrong token — no timestamp field
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request
GET /t?st=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--- response_body eval
""
--- error_code: 200

=== TEST 1.3: empty token
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request
GET /t?st=
--- response_body eval
""
--- error_code: 200

=== TEST 1.4: token with standard base64 padding character '='
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t");
CORE::chop($tok);
$tok .= "=";
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

=== TEST 1.5: token with standard base64 '+' character
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t");
substr($tok, 5, 1) = '+';
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

=== TEST 1.6: oversized token (longer than any HMAC digest output)
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request
GET /t?st=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--- response_body eval
""
--- error_code: 200

=== TEST 1.7: token signed with a different secret key
--- config
    location /t {
        secure_link_hmac         "$arg_st";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
"GET /t?st=" . tok256("/t", SECRET2)
--- response_body eval
""
--- error_code: 200

