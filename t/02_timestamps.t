#!/usr/bin/perl
# 02_timestamps.t
#
# Timestamp parsing — Unix epoch, ISO 8601 (offset and Z), RFC 7231 / IMF-fixdate
#
# Prerequisites:
#   cpanm Test::Nginx Digest::SHA Digest::HMAC_MD5 URI::Escape
#
# Run:
#   prove -I t/lib -v t/02_timestamps.t

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

# 32 tests, 64 assertions total
our $repeat = repeat_each();
plan tests => 64 * $repeat;

no_shuffle();
run_tests();

__DATA__
# ===========================================================================
# CATEGORY 2 — Unix timestamps
# ===========================================================================

=== TEST 2.1: Unix timestamp — valid, no expiry field
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_now();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 2.2: Unix timestamp — valid, future expiry (not yet expired)
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

=== TEST 2.3: Unix timestamp — valid HMAC but link is expired
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_past();
my $e   = 60;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 0
--- error_code: 200

=== TEST 2.4: Unix timestamp — expiry = 0 means unlimited lifetime
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = unix_past();
my $e   = 0;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 2.5: Unix timestamp = 0 — rejected by timestamp <= 0 guard
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|0");
"GET /t?st=$tok&ts=0"
--- response_body eval
""
--- error_code: 200

=== TEST 2.6: timestamp with non-digit characters — strict digit check rejects it
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = "1234abc";
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 2.7: timestamp with leading whitespace — rejected
# A leading space cannot be sent raw in an HTTP request line (causes 400).
# Uses nginx set $ts to inject the space-prefixed value directly so the
# module receives " 1234567890"; the digit-only scan rejects it because
# space (0x20) is not a decimal digit.
--- config
    location /t {
        set $ts " 1234567890";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t| 1234567890");
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

=== TEST 2.8: negative expiry string — rejected
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
my $e   = "-1";
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body eval
""
--- error_code: 200

=== TEST 2.9: no timestamp comma in directive value — treated as token-only
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

=== TEST 2.10: empty timestamp field (double comma) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $e   = 3600;
my $tok = tok256("/t||$e");
"GET /t?st=$tok&ts=&e=$e"
--- response_body eval
""
--- error_code: 200

=== TEST 2.11: Unix timestamp far in the future — valid (no expiry set)
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = TS_FIXED;
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 3.1: ISO 8601 +00:00 offset — valid, no expiry
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = iso_offset();
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 3.2: ISO 8601 positive UTC offset +05:30
# The module subtracts 5h30m from the supplied local time to obtain UTC.
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $utc_sec    = time();
my $offset_min = 330;
my $local_sec  = $utc_sec + $offset_min * 60;
my $ts = POSIX::strftime('%Y-%m-%dT%H:%M:%S+05:30', gmtime($local_sec));
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 3.3: ISO 8601 negative UTC offset -08:00
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $utc_sec    = time();
my $offset_min = -480;
my $local_sec  = $utc_sec + $offset_min * 60;
my $ts = POSIX::strftime('%Y-%m-%dT%H:%M:%S-08:00', gmtime($local_sec));
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 3.4: ISO 8601 with expiry — not yet expired
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = iso_offset();
my $e      = 3600;
my $tok    = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 3.5: ISO 8601 — valid HMAC, link expired
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = iso_past();
my $e      = 60;
my $tok    = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 0
--- error_code: 200

=== TEST 3.6: ISO 8601 'Z' suffix — valid, no expiry
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = iso_z();
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body: 1
--- error_code: 200

=== TEST 3.7: ISO 8601 'Z' suffix — with expiry, not yet expired
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts,$arg_e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts|$arg_e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = iso_z();
my $e   = 3600;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok&ts=$ts&e=$e"
--- response_body: 1
--- error_code: 200

=== TEST 3.8: ISO 8601 — date only, no time component — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = "2025-06-01";
my $tok = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 3.9: ISO 8601 — month 13 (out of range) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = "2025-13-01T00:00:00+00:00";
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 3.10: ISO 8601 — day 32 (out of range) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = "2025-06-32T00:00:00+00:00";
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 3.11: ISO 8601 — hour 25 (out of range) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = "2025-06-01T25:00:00+00:00";
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 3.12: ISO 8601 — year before Unix epoch (1969) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = "1969-12-31T23:59:59+00:00";
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 3.13: ISO 8601 — UTC offset hours out of range (+24:00) — rejected
--- config
    location /t {
        secure_link_hmac         "$arg_st,$arg_ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$arg_ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts     = "2025-06-01T00:00:00+24:00";
my $tok    = tok256("/t|$ts");
"GET /t?st=$tok&ts=$ts"
--- response_body eval
""
--- error_code: 200

=== TEST 4.1: RFC 7231 — valid, no expiry
# Uses nginx set $ts to inject the RFC 7231 timestamp directly, bypassing
# query-parameter encoding issues (spaces in RFC 7231 cannot be sent raw
# in an HTTP request line, and nginx $arg_* returns raw percent-encoded bytes).
--- config
    location /t {
        set $ts "Fri, 20 Nov 2286 17:46:39 GMT";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|" . TS_FIXED_RFC7231);
"GET /t?st=$tok"
--- response_body: 1
--- error_code: 200

=== TEST 4.2: RFC 7231 — with expiry, internal comma handled correctly
# Uses nginx set $ts to inject the RFC 7231 timestamp, and set $e for the expiry.
# The embedded comma in "Fri, 20 Nov ..." must not be confused with the
# comma field separator in secure_link_hmac.
--- config
    location /t {
        set $ts "Fri, 20 Nov 2286 17:46:39 GMT";
        set $e  "3600";
        secure_link_hmac         "$arg_st,$ts,$e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts|$e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|" . TS_FIXED_RFC7231 . "|3600");
"GET /t?st=$tok"
--- response_body: 1
--- error_code: 200

=== TEST 4.3: RFC 7231 — valid HMAC, link expired
# Uses a fixed past RFC 7231 date so the test is always expired regardless of
# when it runs.  "Wed, 01 Jan 2020 00:00:00 GMT" is always in the past.
--- config
    location /t {
        set $ts "Wed, 01 Jan 2020 00:00:00 GMT";
        set $e  "60";
        secure_link_hmac         "$arg_st,$ts,$e";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts|$e";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $ts  = "Wed, 01 Jan 2020 00:00:00 GMT";
my $e   = 60;
my $tok = tok256("/t|$ts|$e");
"GET /t?st=$tok"
--- response_body: 0
--- error_code: 200

=== TEST 4.4: RFC 7231 — unrecognised month abbreviation — rejected
# Spaces and commas in RFC 7231 dates cannot be sent raw in an HTTP request
# line. Uses nginx set $ts so the module receives the literal date string;
# the month name "Foo" is not in the lookup table so parsing fails.
--- config
    location /t {
        set $ts "Mon, 01 Foo 2025 00:00:00 GMT";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|Mon, 01 Foo 2025 00:00:00 GMT");
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

=== TEST 4.5: RFC 7231 — 'UTC' suffix instead of 'GMT' — rejected
# Uses nginx set $ts; the sscanf pattern requires a literal "GMT" suffix,
# so "UTC" does not match and parsing fails.
--- config
    location /t {
        set $ts "Mon, 01 Jan 2025 00:00:00 UTC";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|Mon, 01 Jan 2025 00:00:00 UTC");
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

=== TEST 4.6: RFC 7231 — month name is case-insensitive
# Uses nginx set $ts with TS_FIXED_RFC7231 uppercased.  The weekday and month
# abbreviations are both uppercased (FRI -> FRI, NOV -> NOV); the module's
# ngx_strncasecmp lookup must accept "NOV" as November.
--- config
    location /t {
        set $ts "FRI, 20 NOV 2286 17:46:39 GMT";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
(my $ts = TS_FIXED_RFC7231) =~ s/\b([A-Z][a-z]{2})\b/uc($1)/ge;
my $tok = tok256("/t|$ts");
"GET /t?st=$tok"
--- response_body: 1
--- error_code: 200

=== TEST 4.7: RFC 7231 — pre-computed fixed constant (TS_FIXED_RFC7231)
# Uses nginx set to inject TS_FIXED_RFC7231 directly, eliminating query-parameter
# encoding ambiguity.
--- config
    location /t {
        set $ts "Fri, 20 Nov 2286 17:46:39 GMT";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|" . TS_FIXED_RFC7231);
"GET /t?st=$tok"
--- response_body: 1
--- error_code: 200

=== TEST 4.8: Common Log Format timestamp — rejected
# CLF format "01/Jan/2025:00:00:00 +0000" contains a space before +0000 which
# cannot be sent raw in an HTTP request line. Uses nginx set $ts to deliver
# the value directly; the '/' makes it fail all four timestamp parsers.
--- config
    location /t {
        set $ts "01/Jan/2025:00:00:00 +0000";
        secure_link_hmac         "$arg_st,$ts";
        secure_link_hmac_secret  "testsecret";
        secure_link_hmac_message "$uri|$ts";
        secure_link_hmac_algorithm sha256;
        return 200 "$secure_link_hmac";
    }
--- request eval
my $tok = tok256("/t|01/Jan/2025:00:00:00 +0000");
"GET /t?st=$tok"
--- response_body eval
""
--- error_code: 200

