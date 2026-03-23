package HmacSecureLink;
# t/lib/HmacSecureLink.pm
#
# Shared helpers used by all test files in t/.
#
# Import everything at once:
#   use lib 't/lib';
#   use HmacSecureLink qw(:all);
#
# Or import selectively:
#   use HmacSecureLink qw(tok256 b64url unix_now iso_offset rfc7231_now);

use strict;
use warnings;
use Exporter 'import';

use Digest::SHA     qw(hmac_sha256 hmac_sha512 hmac_sha1);
use Digest::HMAC_MD5 qw(hmac_md5);
use MIME::Base64    qw(encode_base64);
use URI::Escape     qw(uri_escape);
use POSIX           qw(strftime);

our @EXPORT_OK = qw(
    SECRET SECRET2
    TS_FIXED TS_FIXED_ISO TS_FIXED_Z TS_FIXED_RFC7231
    b64url
    tok256 tok512 tok1 tokmd5
    unix_now unix_past unix_far
    iso_offset iso_z iso_past
    rfc7231_now rfc7231_past
    uri_escape
);

our %EXPORT_TAGS = (all => \@EXPORT_OK);

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Shared HMAC secrets.
use constant SECRET  => 'testsecret';
use constant SECRET2 => 'anothersecret';

# A fixed Unix timestamp far in the future (year 2286) used in tests that
# need the request URL and the expected-response computation to agree on the
# same timestamp.  Because it is a compile-time constant, both the
# "--- request eval" and "--- response_body eval" blocks see the same value
# regardless of when they execute, eliminating the race condition that would
# arise from two independent time() calls straddling a second boundary.
use constant TS_FIXED => 9_999_999_999;

# The same point in time expressed in each timestamp format accepted by the
# module.  Pre-computed so test blocks can reference them without repeating
# the strftime calls.
use constant TS_FIXED_ISO     => '2286-11-20T17:46:39+00:00';
use constant TS_FIXED_Z       => '2286-11-20T17:46:39Z';
use constant TS_FIXED_RFC7231 => 'Fri, 20 Nov 2286 17:46:39 GMT';

# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

# b64url($raw_bytes) — encode raw bytes as base64url without padding.
sub b64url {
    my $raw = shift;
    my $b64 = encode_base64($raw, '');
    $b64 =~ tr|+/|-_|;
    $b64 =~ s/=+$//;
    return $b64;
}

# ---------------------------------------------------------------------------
# Token generators
# tok256($message [, $secret]) — HMAC-SHA-256, base64url, no padding.
# ---------------------------------------------------------------------------

sub tok256 { b64url(hmac_sha256($_[0], $_[1] // SECRET)) }
sub tok512 { b64url(hmac_sha512($_[0], $_[1] // SECRET)) }
sub tok1   { b64url(hmac_sha1  ($_[0], $_[1] // SECRET)) }
sub tokmd5 { b64url(hmac_md5  ($_[0], $_[1] // SECRET)) }

# ---------------------------------------------------------------------------
# Live timestamp generators (return the current wall-clock time).
#
# Use these for tests whose only job is to check the module's response
# variable values ("1" / "0" / not-found) and where both sides of the check
# use the URL parameter value — i.e. the Perl test code does NOT need to
# independently re-derive the timestamp to compare with.
#
# Do NOT use live timestamps in response_body eval blocks that must
# reproduce the same token the request carried; use TS_FIXED instead.
# ---------------------------------------------------------------------------

sub unix_now  { time() }
sub unix_past { time() - 7200 }          # 2 h ago — for expired-link tests
sub unix_far  { time() + 86400 * 3650 }  # ~10 years ahead — quasi-permanent

# ISO 8601 with numeric UTC offset (the format emitted by $time_iso8601)
sub iso_offset { strftime('%Y-%m-%dT%H:%M:%S+00:00', gmtime(time())) }

# ISO 8601 UTC Z suffix
sub iso_z      { strftime('%Y-%m-%dT%H:%M:%SZ',       gmtime(time())) }

# ISO 8601, 2 hours ago
sub iso_past   { strftime('%Y-%m-%dT%H:%M:%S+00:00', gmtime(time() - 7200)) }

# RFC 7231 / IMF-fixdate (always UTC, always "GMT" suffix)
sub rfc7231_now  { strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime(time())) }
sub rfc7231_past { strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime(time() - 7200)) }

1;
__END__

=head1 NAME

HmacSecureLink — shared test helpers for ngx_http_hmac_secure_link_module

=head1 SYNOPSIS

    use lib 't/lib';
    use HmacSecureLink qw(:all);

    my $tok = tok256("/protected/file.txt|" . TS_FIXED . "|3600");

=head1 CONSTANTS

=over 4

=item C<SECRET>, C<SECRET2>

Default and alternate HMAC secrets used throughout the test suite.

=item C<TS_FIXED>

Unix timestamp 9,999,999,999 (2286-11-20).  Use this — not C<unix_now()> —
whenever a "--- request eval" and a "--- response_body eval" block both need
the same numeric timestamp.  Two calls to C<time()> in separate eval blocks
can straddle a second boundary and produce different values, causing a
spurious test failure.

=item C<TS_FIXED_ISO>, C<TS_FIXED_Z>, C<TS_FIXED_RFC7231>

The same point in time as C<TS_FIXED> pre-formatted in each timestamp
dialect accepted by the module.

=back

=head1 FUNCTIONS

=over 4

=item C<b64url($bytes)>

Encode raw bytes as base64url without padding.

=item C<tok256($msg [, $secret])>, C<tok512(…)>, C<tok1(…)>, C<tokmd5(…)>

Compute HMAC using the named algorithm and return a base64url-encoded token.
Defaults to C<SECRET> when no secret is supplied.

=item C<unix_now()>, C<unix_past()>, C<unix_far()>

Current time, 2 h ago, and ~10 years from now, as Unix timestamps.

=item C<iso_offset()>, C<iso_z()>, C<iso_past()>

Current time formatted as ISO 8601 with C<+00:00> offset, with C<Z> suffix,
and 2 h ago with C<+00:00> offset respectively.

=item C<rfc7231_now()>, C<rfc7231_past()>

Current time and 2 h ago formatted as RFC 7231 IMF-fixdate.

=back
