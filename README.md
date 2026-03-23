Nginx HMAC Secure Link Module
=============================

Description
-----------

The Nginx HMAC Secure Link Module enhances the security and functionality
of the standard `secure_link` module.  Secure tokens are created using a
proper HMAC construction (RFC 2104) with any hash algorithm supported by
OpenSSL 3.x.  Available algorithms depend on the providers loaded in your
OpenSSL configuration.

**Default provider** (available out of the box on any OpenSSL 3.x installation):
`md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`, `sha512-256`,
`sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `shake128`, `shake256`,
`blake2b512`, `blake2s256`, `sm3`.

**Legacy provider** (requires the OpenSSL legacy provider to be explicitly loaded
in `openssl.cnf`; not available by default in OpenSSL 3.x):
`md4`, `mdc2`, `rmd160`, `gost`.

The recommended algorithm is `sha256` or stronger.  `md5` and `sha1` are
accepted but should not be used in new deployments.

The HMAC is computed as `H(secret ⊕ opad, H(secret ⊕ ipad, message))`
rather than the insecure `MD5(secret, message, expire)` used by the built-in
module.


Pre-built Packages (Ubuntu / Debian)
--------------------------------------

Pre-built packages for this module are freely available from the
GetPageSpeed repository:

```bash
# Install the repository keyring
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://extras.getpagespeed.com/deb-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/getpagespeed.gpg >/dev/null

# Add the repository (Ubuntu example — replace 'jammy' for your release)
echo "deb [signed-by=/etc/apt/keyrings/getpagespeed.gpg] \
  https://extras.getpagespeed.com/ubuntu jammy main" \
  | sudo tee /etc/apt/sources.list.d/getpagespeed-extras.list

# Install nginx and the module
sudo apt-get update
sudo apt-get install nginx nginx-module-hmac-secure-link
```

The module is automatically enabled after installation.  Supported
distributions include Debian 12/13 and Ubuntu 20.04/22.04/24.04 (both
amd64 and arm64).  See the [complete setup instructions][gps].

[gps]: https://apt-nginx-extras.getpagespeed.com/apt-setup/


Installation from Source
------------------------

You need to recompile Nginx from source to include this module.

**Static module** (compiled into the binary):

    ./configure --add-module=/absolute/path/to/ngx_http_hmac_secure_link_module

**Dynamic module** (`.so` loaded with `load_module`):

    ./configure --with-compat \
                --add-dynamic-module=/absolute/path/to/ngx_http_hmac_secure_link_module

Then build:

    make
    make install

OpenSSL is required at build and runtime.  The module is compatible with
OpenSSL 1.0.x, 1.1.x, and 3.x.  On OpenSSL 3.x the modern `EVP_MAC` API
is used; on older versions the `HMAC()` one-shot function is used.


Configuration Directives
------------------------

All directives accept NGINX variables and complex values.

### `secure_link_hmac`

**Context:** `http`, `server`, `location`

Specifies the variable expression whose evaluated value must follow the
format `<token>,<timestamp>[,<expires>]`.  **The field separator is always
a comma and is required between each field.**  The comma is hardcoded in
the module parser; no other separator is supported here.

| Field       | Description                                               |
|-------------|-----------------------------------------------------------|
| `token`     | Base64url-encoded HMAC (no padding `=`)                   |
| `timestamp` | Request creation time (see [Timestamp Formats](#timestamp-formats)) |
| `expires`   | Optional lifetime in seconds; omit or use `0` for unlimited |

```nginx
secure_link_hmac "$arg_st,$arg_ts,$arg_e";
```

> **Important:** When `secure_link_hmac` is assembled from query parameters
> (`"$arg_st,$arg_ts,$arg_e"`), the timestamp and expires values must not
> themselves contain unescaped commas.  ISO 8601 and Unix timestamps are
> comma-free and work without special handling.  RFC 7231 dates contain an
> embedded comma (e.g. `Sun, 06 Nov …`); the module handles this correctly
> for the second field, but you must URL-encode the comma when placing an
> RFC 7231 date in a query parameter so that `$arg_ts` resolves to the full
> decoded date string (see [Timestamp Formats](#timestamp-formats)).

### `secure_link_hmac_message`

**Context:** `http`, `server`, `location`

The message whose HMAC is to be verified.  Must match exactly what the
client used when computing the token.  Typically includes the URI and the
timestamp so that tokens are URL-specific and time-bound.

**The separator between fields in the message is freely chosen by the
operator and may be any byte or sequence of bytes** — pipe (`|`), colon
(`:`), slash (`/`), hyphen (`-`), or even nothing at all.  The module
treats `secure_link_hmac_message` as an opaque byte string and never
parses its contents; the separator is simply part of the HMAC pre-image.

The only requirement is that the separator chosen on the server side is
identical to the separator used by the client when computing the HMAC.
Using a separator that cannot appear naturally in any of the field values
(such as `|` for URIs and Unix timestamps) reduces the risk of length-
extension ambiguity.

```nginx
# Pipe separator (recommended — cannot appear in a URI path or Unix timestamp)
secure_link_hmac_message "$uri|$arg_ts|$arg_e";

# Colon separator
secure_link_hmac_message "$uri:$arg_ts:$arg_e";

# No separator (valid, but ambiguous if fields share a character set)
secure_link_hmac_message "$uri$arg_ts$arg_e";
```

### `secure_link_hmac_secret`

**Context:** `http`, `server`, `location`

The HMAC secret key.  Keep this out of version control.

```nginx
secure_link_hmac_secret "my_very_secret_key";
```

### `secure_link_hmac_algorithm`

**Context:** `http`, `server`, `location`  
**Default:** `sha256`

The OpenSSL digest name used for the HMAC.

```nginx
secure_link_hmac_algorithm sha256;
```


Embedded Variables
------------------

### `$secure_link_hmac`

Set after processing the `secure_link_hmac` directive.  Possible values:

| Value     | Meaning                                                         |
|-----------|-----------------------------------------------------------------|
| `"1"`     | Token is cryptographically valid and the link has **not** expired |
| `"0"`     | Token is valid but the link **has expired**                     |
| *(empty)* | Token is absent, malformed, HMAC mismatch, or timestamp invalid |

Use this variable to gate access.  In production, return the same error
code for all failing cases so that an attacker cannot distinguish between
an expired token and a forged one:

```nginx
if ($secure_link_hmac != "1") {
    return 403;
}
```

> **Note:** `"1"` and `"0"` are literal single-character strings, not
> numbers.  The empty / not-found case means the variable is unset, not
> that it equals `""`.

### `$secure_link_hmac_expires`

The raw expiration-period string (in seconds) as received in the request.
This variable is only set when an expiry was present in `secure_link_hmac`.
It can be used for logging or conditional logic:

```nginx
add_header X-Link-Expires $secure_link_hmac_expires;
```

- If the incoming value was `"3600"`, this variable contains `"3600"`.
- If no expiry field was present, the variable is unset (not_found).
- This variable is populated as a side-effect of evaluating
  `$secure_link_hmac`; evaluate `$secure_link_hmac` first.

### `$secure_link_hmac_token`

A freshly computed base64url-encoded HMAC token (no trailing `=` padding).
Use this variable when NGINX acts as a proxy that must forward
authenticated requests to a backend:

```nginx
location ^~ /backend/ {
    set $expire 60;
    secure_link_hmac_message "$uri|$time_iso8601|$expire";
    secure_link_hmac_secret  "my_very_secret_key";
    secure_link_hmac_algorithm sha256;

    proxy_pass "http://backend$uri?st=$secure_link_hmac_token&ts=$time_iso8601&e=$expire";
}
```

The token is base64url-encoded without padding, compatible with URL query
parameters without further escaping.


Timestamp Formats
-----------------

A timestamp **should** always be included in the signed message to prevent
replay attacks.  Three formats are accepted by the server-side parser.
Clients can use whichever is most convenient.

### ISO 8601 with numeric UTC offset  *(recommended)*

```
YYYY-MM-DDThh:mm:ss+HH:MM
YYYY-MM-DDThh:mm:ss-HH:MM
```

Examples:
```
2025-06-01T14:30:00+00:00   # UTC
2025-06-01T17:30:00+03:00   # UTC+3 (Kiev/Istanbul)
2025-06-01T08:30:00-06:00   # UTC-6 (Chicago CDT)
```

The server converts to UTC before comparing, so any valid offset is
accepted.

### ISO 8601 UTC (Z suffix)

```
YYYY-MM-DDThh:mm:ssZ
```

Example: `2025-06-01T14:30:00Z`

Equivalent to `+00:00` but shorter.  Nginx's built-in `$time_iso8601`
variable emits `+00:00` format; for `Z` you must format the timestamp
application-side.

### RFC 7231 / IMF-fixdate  *(HTTP date)*

As specified in [RFC 7231 §7.1.1.1][rfc7231].  All RFC 7231 dates are
implicitly UTC; no offset is applied.

```
Day, DD Mon YYYY hh:mm:ss GMT
```

Examples:
```
Sun, 01 Jun 2025 14:30:00 GMT
Mon, 23 Mar 2026 08:00:00 GMT
```

Where `Day` is a three-letter weekday abbreviation (`Mon`–`Sun`) and
`Mon` (month) is one of `Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec`.
The parser is case-insensitive for both abbreviations.

> **Note:** RFC 7231 also defines two obsolete formats (RFC 850 and
> ANSI C `asctime`).  Those are not supported; only the preferred
> IMF-fixdate format is accepted.

[rfc7231]: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.1

### Unix timestamp  *(plain integer)*

A string of decimal digits representing seconds since the Unix epoch
(1970-01-01T00:00:00Z).

Example: `1748785800`

This is the simplest format and works well in Bash and Node.js.  The
parser is strict: the timestamp field must contain **only** decimal
digits; any other character causes it to be rejected.

> **Security note:** Unix timestamps have only one-second resolution.
> Use ISO 8601 if sub-second precision matters, or if you need to
> express a specific timezone.


Usage Example — Server Side
----------------------------

```nginx
location ^~ /files/ {
    # The three comma-separated fields: token, timestamp, expires (seconds)
    secure_link_hmac "$arg_st,$arg_ts,$arg_e";

    # HMAC secret key
    secure_link_hmac_secret "my_secret_key";

    # The message that was signed: URI + timestamp + expiry
    secure_link_hmac_message "$uri|$arg_ts|$arg_e";

    # Hash algorithm
    secure_link_hmac_algorithm sha256;

    # In production, do not reveal whether the token was wrong or expired.
    # $secure_link_hmac == "1" → valid and not expired
    # $secure_link_hmac == "0" → valid but expired
    # $secure_link_hmac unset  → invalid / malformed
    if ($secure_link_hmac != "1") {
        return 403;
    }

    rewrite ^/files/(.*)$ /files/$1 break;
}
```


Client-Side Examples
--------------------

### Perl — ISO 8601 timestamp

```perl
perl_set $secure_token '
    sub {
        use Digest::SHA qw(hmac_sha256_base64);
        use POSIX qw(strftime);

        my $r       = shift;
        my $key     = "my_very_secret_key";
        my $expire  = 60;
        my $now     = time();

        # ISO 8601 with numeric UTC offset
        my $tz = strftime("%z", localtime($now));
        $tz =~ s/(\d{2})(\d{2})/$1:$2/;
        my $timestamp = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;

        my $message = $r->uri . "|" . $timestamp . "|" . $expire;
        my $digest  = hmac_sha256_base64($message, $key);
        $digest     =~ tr(+/)(-_);           # base64 → base64url
        $digest     =~ s/=+$//;             # strip padding

        return "st=$digest&ts=$timestamp&e=$expire";
    }
';
```

### PHP — Unix timestamp

```php
<?php
$secret    = 'my_very_secret_key';
$expire    = 60;
$algo      = 'sha256';
$timestamp = time();                       // Unix timestamp
$uri       = '/files/top_secret.pdf';
$message   = "{$uri}|{$timestamp}|{$expire}";

$token = base64_encode(hash_hmac($algo, $message, $secret, true));
$token = strtr($token, '+/', '-_');        // base64 → base64url
$token = rtrim($token, '=');              // strip padding

$host = $_SERVER['HTTP_HOST'];
$url  = "https://{$host}{$uri}?st={$token}&ts={$timestamp}&e={$expire}";
```

### PHP — ISO 8601 timestamp

```php
<?php
$secret    = 'my_very_secret_key';
$expire    = 60;
$algo      = 'sha256';
$timestamp = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
               ->format(DateTimeInterface::RFC3339);  // "2025-06-01T14:30:00+00:00"
$uri       = '/files/top_secret.pdf';
$message   = "{$uri}|{$timestamp}|{$expire}";

$token = base64_encode(hash_hmac($algo, $message, $secret, true));
$token = strtr($token, '+/', '-_');
$token = rtrim($token, '=');

$url = "https://example.com{$uri}?st={$token}&ts=" . urlencode($timestamp) . "&e={$expire}";
```

### PHP — RFC 7231 / IMF-fixdate timestamp

```php
<?php
$secret    = 'my_very_secret_key';
$expire    = 60;
$algo      = 'sha256';
// RFC 7231 IMF-fixdate — always UTC, always "GMT" suffix
$timestamp = gmdate('D, d M Y H:i:s') . ' GMT';  // "Sun, 01 Jun 2025 14:30:00 GMT"
$uri       = '/files/top_secret.pdf';
$message   = "{$uri}|{$timestamp}|{$expire}";

$token = base64_encode(hash_hmac($algo, $message, $secret, true));
$token = strtr($token, '+/', '-_');
$token = rtrim($token, '=');

// URL-encode the RFC 7231 date (contains spaces and commas)
$url = "https://example.com{$uri}?st={$token}&ts=" . rawurlencode($timestamp) . "&e={$expire}";
```

### Node.js — Unix timestamp

```javascript
const crypto = require('crypto');

const secret    = 'my_very_secret_key';
const expire    = 60;
const timestamp = Math.floor(Date.now() / 1000);   // Unix timestamp
const uri       = '/files/top_secret.pdf';
const message   = `${uri}|${timestamp}|${expire}`;

const token = crypto.createHmac('sha256', secret)
                    .update(message)
                    .digest('base64')
                    .replace(/=/g,  '')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_');

const url = `https://example.com${uri}?st=${token}&ts=${timestamp}&e=${expire}`;
```

### Node.js — RFC 7231 / IMF-fixdate timestamp

```javascript
const crypto = require('crypto');

const secret    = 'my_very_secret_key';
const expire    = 60;
// toUTCString() produces the RFC 7231 IMF-fixdate format in all modern runtimes
const timestamp = new Date().toUTCString();        // "Sun, 01 Jun 2025 14:30:00 GMT"
const uri       = '/files/top_secret.pdf';
const message   = `${uri}|${timestamp}|${expire}`;

const token = crypto.createHmac('sha256', secret)
                    .update(message)
                    .digest('base64')
                    .replace(/=/g,  '')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_');

const url = `https://example.com${uri}?st=${token}&ts=${encodeURIComponent(timestamp)}&e=${expire}`;
```

### Python — ISO 8601 timestamp (UTC Z suffix)

```python
import hmac, hashlib, base64, urllib.parse
from datetime import datetime, timezone

secret    = b'my_very_secret_key'
expire    = 60
timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
uri       = '/files/top_secret.pdf'
message   = f'{uri}|{timestamp}|{expire}'.encode()

token = base64.urlsafe_b64encode(
            hmac.new(secret, message, hashlib.sha256).digest()
        ).rstrip(b'=').decode()

url = f'https://example.com{uri}?st={token}&ts={urllib.parse.quote(timestamp)}&e={expire}'
```

### Bash — Unix timestamp

```bash
#!/bin/bash
SECRET="my_super_secret"
URI="/file/my_secret_file.txt"
TIMESTAMP="$(date +%s)"
EXPIRES=3600

MESSAGE="${URI}|${TIMESTAMP}|${EXPIRES}"
TOKEN="$(printf '%s' "$MESSAGE" \
         | openssl dgst -sha256 -hmac "$SECRET" -binary \
         | openssl base64 \
         | tr '+/' '-_' \
         | tr -d '=')"

echo "http://127.0.0.1${URI}?st=${TOKEN}&ts=${TIMESTAMP}&e=${EXPIRES}"
```


Proxy Usage
-----------

When NGINX acts as a proxy that must add an HMAC token to outgoing requests,
use the `$secure_link_hmac_token` variable:

```nginx
location ^~ /backend_location/ {
    set $expire 60;

    secure_link_hmac_message "$uri|$time_iso8601|$expire";
    secure_link_hmac_secret  "my_very_secret_key";
    secure_link_hmac_algorithm sha256;

    proxy_pass "http://backend_server$uri?st=$secure_link_hmac_token&ts=$time_iso8601&e=$expire";
}
```

> **Note:** `$time_iso8601` emits an ISO 8601 timestamp with a numeric UTC
> offset (e.g. `2025-06-01T14:30:00+00:00`), which this module accepts.


Security Notes
--------------

**Separator in `secure_link_hmac`**
The field separator inside the `secure_link_hmac` directive value is
always a comma.  The timestamp and expires fields must not contain bare
commas (ISO 8601 and Unix timestamps are safe; RFC 7231 timestamps are
handled by the module's internal comma-skip logic but the embedded comma
must survive URL encoding/decoding intact — see
[Timestamp Formats](#timestamp-formats)).

**Separator in `secure_link_hmac_message`**
Choose a separator that cannot appear in any of the fields being
concatenated.  Pipe (`|`) is a good default for URI + Unix-timestamp
combinations.  Using no separator at all is valid but can allow a
length-extension attack where one valid set of field values is
reinterpreted as a different set; a separator prevents this.

**Other recommendations**
- Always include a timestamp in the signed message to prevent replay attacks.
- Choose a short `expires` value for your use case (60–3600 seconds is
  typical for download links).
- Return the same HTTP error code (e.g. `403`) for all failure cases —
  both `"0"` (expired) and not-found (invalid) — so that attackers cannot
  distinguish an expired token from a forged one.
- Use a secret key of at least 32 bytes of random entropy.
- Prefer `sha256` or stronger; avoid `md5` and `sha1` for new deployments.
- URL-encode timestamp values that contain characters special in query strings:
  - ISO 8601 UTC offset `+` must be sent as `%2B` (otherwise decoded as space)
  - RFC 7231 spaces must be sent as `%20` and the embedded comma as `%2C`


Contributing
------------

Source repository: https://github.com/nginx-modules/ngx_http_hmac_secure_link_module

Pull requests and patches are welcome.  Please open an issue before making
significant changes.
