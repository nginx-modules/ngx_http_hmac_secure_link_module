# Changelog

All notable changes to **ngx_http_hmac_secure_link_module** are documented
here.  The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2026-03-28

### Added

- **RFC 7231 / IMF-fixdate timestamp support.**  HTTP dates in the format
  `"Day, DD Mon YYYY hh:mm:ss GMT"` (RFC 7231 §7.1.1.1) are now accepted as
  the timestamp field of `secure_link_hmac`.  Month-name lookup is
  case-insensitive.  All RFC 7231 dates are implicitly UTC.

- **ISO 8601 `Z` suffix support.**  Timestamps of the form
  `"YYYY-MM-DDThh:mm:ssZ"` are now recognised as an alias for `+00:00` UTC
  offset.  Previously they fell through to the Unix-timestamp branch and were
  silently misinterpreted.

- **OpenSSL 3.0+ `EVP_MAC` API.**  HMAC computation now uses `EVP_MAC` on
  OpenSSL ≥ 3.0 (avoiding the `HMAC()` deprecation warning) and retains the
  `HMAC()` one-shot function on OpenSSL 1.0/1.1.  Controlled by a
  `OPENSSL_VERSION_NUMBER` compile-time guard.

- **`NGX_HMAC_MD_SIZE` macro.**  Wraps `EVP_MD_size()` (OpenSSL 1.x) and
  `EVP_MD_get_size()` (OpenSSL 3.x) behind a single call site.

- **Helper functions** extracted from the main variable handler:
  - `ngx_http_secure_link_gauss()` — Gauss proleptic Gregorian calendar
    formula with calendar-field range validation.
  - `ngx_http_secure_link_parse_ts()` — tries each timestamp format in
    order and returns `(time_t)-1` on failure.
  - `ngx_http_secure_link_hmac_compute()` — OpenSSL-version-aware HMAC
    computation with a key-length overflow guard.

- **Perl test suite** (`t/01_basic.t` … `t/05_integration.t`, 68 tests across 10
  categories split into five focused files) covering valid/expired/invalid tokens, all timestamp formats
  and their edge cases, algorithm variants, variable values, separator
  choices, and real-world access-control patterns.

- **Shared test helper module** (`t/lib/HmacSecureLink.pm`) providing
  token generators, timestamp formatters, and the `TS_FIXED` constant that
  eliminates timing-race failures in token-comparison tests.

- **CI matrix — NGINX versions updated:**
  - Added NGINX 1.28.3 (current stable) and 1.29.7 (current mainline) to
    the test matrix on ubuntu-22.04 and ubuntu-24.04.
  - Retained NGINX 1.26.3 (legacy stable) on ubuntu-22.04 and ubuntu-24.04.
  - Retained NGINX 1.20.2 (legacy, Aug 2021) on ubuntu-22.04 only; this
    version requires PCRE1 (`libpcre3-dev`) and is not compatible with PCRE2.

- **`Makefile`** for local build, test, lint, and dependency-installation
  targets.

### Fixed

- **Incorrect type casts in `sscanf`.**  `sscanf "%d"` requires `int *`.
  The original code cast local `int` variables to `ngx_tm_year_t *`,
  `ngx_tm_mon_t *`, etc., which differ in size from `int` on some platforms,
  causing undefined behaviour and potential stack corruption.

- **Y2038 overflow in the Gauss formula.**  The expression `365 * year` was
  computed as `int × int`.  For years ≥ 2038 on 32-bit `int` platforms the
  accumulated day count overflowed before the `(time_t)` cast was applied.
  Fixed by casting `year` to `time_t` before the first multiplication.

- **`size_t` / `unsigned int` mismatch in token variable handler.**  The
  original code passed `(u_int *) &hmac.len` to `HMAC()`.  `hmac.len` is
  `size_t` (8 bytes on LP64); only the low 4 bytes were written correctly on
  little-endian targets.  On big-endian LP64 the result was entirely wrong.
  Fixed by using a local `unsigned int hmac_len` variable.

- **`$secure_link_hmac_expires` returned token bytes instead of the expiry
  period.**  `ctx->expires` was set to `value.data/len` at a point where
  `value` had already been trimmed to the token substring.  Fixed by pointing
  `ctx->expires` at the actual expiry-period substring.

- **Loose Unix timestamp validation.**  `sscanf(p, "%llu", …)` greedily
  accepted any string starting with digits — including ISO 8601 dates such as
  `"2025-01-01T…"` (parsed as `2025`).  Fixed by requiring every byte in the
  timestamp substring to be a decimal digit.

- **`EVP_MD_size()` return value not checked.**  OpenSSL 3.0 returns `-1` on
  error.  The unchecked cast to `u_int` produced a huge buffer size and
  passed a garbage length to `CRYPTO_memcmp`.  Fixed with an explicit
  `md_size <= 0` guard.

- **GMT-offset sign applied twice.**  Two independent `if` statements allowed
  both branches to execute when the sign character was anything other than
  `'+'` or `'-'` (which `sscanf` already ensures cannot happen, but the
  logic was fragile).  Fixed with `if / else if / else`.

- **RFC 7231 internal comma broke the expiry-field separator search.**  The
  embedded comma in `"Sun, 06 Nov …"` was found before the real field
  separator when an expiry field was present, leaving `ts_end` pointing
  at a 3-byte substring that matched no parser.  Fixed by detecting the
  RFC 7231 weekday pattern and skipping its internal comma before scanning
  for the next field boundary.

- **Debug log timestamp width hardcoded to 25 bytes.**  The original code
  always logged 25 characters regardless of the actual timestamp format.
  Fixed to log `(int)(ts_end - ts_start)` bytes.

- **`%02d` in `sscanf` format strings.**  The `0` flag is a printf-only
  concept; it is silently ignored by `scanf`.  Changed to `%2d` throughout
  to eliminate misleading code.

- **`key.len` narrowed to `int` without a guard.**  `HMAC()`'s `key_len`
  parameter is `int`, but `ngx_str_t.len` is `size_t`.  Added an explicit
  overflow guard in the OpenSSL 1.x compatibility path.

### Changed

- File-level comment block replaced with a concise changelog (this file).
  Inline `/* FIX: … */` comments removed from function bodies; rationale
  lives here and in the commit history.

- `ngx_http_secure_link_add_variables`: loop variable `var` moved to inner
  scope to satisfy `cppcheck --enable=all`.

- `ngx_http_secure_link_parse_ts`: parameters `ts_last` declared `const`.

- **README — algorithm list updated for OpenSSL 3.x provider model:**
  - Algorithms are now grouped by provider: *default* (available without
    configuration — `sha256`, `sha3-*`, `blake2b512`, `sm3`, etc.) and
    *legacy* (requires the OpenSSL legacy provider to be loaded in
    `openssl.cnf` — `md4`, `mdc2`, `rmd160`, `gost`).
  - Added a note that `gost` and `mdc2` are not available on a default
    OpenSSL 3.x install.
  - Recommended algorithm note added: prefer `sha256` or stronger.

---

## [1.x] — prior to 2026

Original implementation by the nginx-modules project.  Supported ISO 8601
timestamps with numeric UTC offset and Unix timestamps.  See repository
history for individual changes.
