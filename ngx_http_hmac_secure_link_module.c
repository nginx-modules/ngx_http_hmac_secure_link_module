/*
 * ngx_http_hmac_secure_link_module.c
 *
 * NGINX HMAC Secure Link Module
 *
 * Verifies request authenticity using an HMAC token, an optional timestamp,
 * and an optional expiry period.  The field separator in secure_link_hmac is
 * always a comma.  The separator used inside secure_link_hmac_message is
 * freely chosen by the operator (pipe, colon, slash, …) and must match on
 * both the client and the server.
 *
 * Supported timestamp formats for the second comma-separated field:
 *   ISO 8601 numeric offset  "YYYY-MM-DDThh:mm:ss+HH:MM" / "…-HH:MM"
 *   ISO 8601 UTC Z suffix    "YYYY-MM-DDThh:mm:ssZ"
 *   RFC 7231 / IMF-fixdate   "Day, DD Mon YYYY hh:mm:ss GMT"
 *   Unix timestamp           plain decimal integer (seconds since epoch)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

/* -------------------------------------------------------------------------
 * OpenSSL version compatibility
 * ------------------------------------------------------------------------- */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/params.h>
#  include <openssl/core_names.h>
   /*
    * EVP_MD_size() is deprecated in OpenSSL 3.0; the replacement is
    * EVP_MD_get_size().  Wrap both spellings behind a single macro so the
    * rest of the code is version-agnostic.
    */
#  define NGX_HMAC_MD_SIZE(md)  EVP_MD_get_size(md)
#else
#  define NGX_HMAC_MD_SIZE(md)  EVP_MD_size(md)
#endif


#define NGX_DEFAULT_HASH_FUNCTION  "sha256"

/*
 * ngx_isalpha is not defined by NGINX (ngx_string.h only provides
 * ngx_isdigit, ngx_isspace, ngx_isalnum, etc.).  Define it here using
 * explicit ASCII range checks — the same approach NGINX uses for all its
 * character-class macros — so that the check is locale-independent and
 * avoids the implicit-function-declaration error when built with -Werror.
 */
#define ngx_isalpha(c) \
    (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))

/*
 * RFC 7231 §7.1.1.1 month-name table.
 * Index 0 = January, index 11 = December.
 */
static const char * const ngx_http_secure_link_months[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


/* -------------------------------------------------------------------------
 * Module data structures
 * ------------------------------------------------------------------------- */

typedef struct {
    ngx_http_complex_value_t  *hmac_variable;
    ngx_http_complex_value_t  *hmac_message;
    ngx_http_complex_value_t  *hmac_secret;
    ngx_str_t                  hmac_algorithm;
} ngx_http_secure_link_conf_t;

typedef struct {
    ngx_str_t                  expires;
} ngx_http_secure_link_ctx_t;


/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */

static ngx_int_t ngx_http_secure_link_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_link_token_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_secure_link_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_secure_link_add_variables(ngx_conf_t *cf);


/* -------------------------------------------------------------------------
 * Module directives, context, and descriptor
 * ------------------------------------------------------------------------- */

static ngx_command_t  ngx_http_hmac_secure_link_commands[] = {

    { ngx_string("secure_link_hmac"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, hmac_variable),
      NULL },

    { ngx_string("secure_link_hmac_message"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, hmac_message),
      NULL },

    { ngx_string("secure_link_hmac_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, hmac_secret),
      NULL },

    { ngx_string("secure_link_hmac_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_link_conf_t, hmac_algorithm),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_link_module_ctx = {
    ngx_http_secure_link_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_secure_link_create_conf,      /* create location configuration */
    ngx_http_secure_link_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_hmac_secure_link_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_link_module_ctx,      /* module context */
    ngx_http_hmac_secure_link_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_secure_link_vars[] = {

    { ngx_string("secure_link_hmac"), NULL,
      ngx_http_secure_link_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("secure_link_hmac_expires"), NULL,
      ngx_http_secure_link_expires_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("secure_link_hmac_token"), NULL,
      ngx_http_secure_link_token_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


/* =========================================================================
 * HELPER: ngx_http_secure_link_hmac_compute
 *
 * Computes HMAC using the specified digest algorithm.  Wraps the OpenSSL
 * 1.x HMAC() one-shot function and the OpenSSL 3.x EVP_MAC API so that the
 * caller does not need to handle the version difference.
 *
 * Parameters:
 *   r        – current NGINX request (for logging only)
 *   evp_md   – digest algorithm (from EVP_get_digestbyname)
 *   key      – HMAC secret key bytes
 *   key_len  – length of key in bytes
 *   msg      – message to authenticate
 *   msg_len  – length of message in bytes
 *   out      – output buffer; must be at least EVP_MAX_MD_SIZE bytes
 *   out_len  – receives the number of bytes written to out
 *
 * Returns NGX_OK on success, NGX_ERROR on failure.
 * ========================================================================= */

static ngx_int_t
ngx_http_secure_link_hmac_compute(ngx_http_request_t *r,
    const EVP_MD *evp_md,
    const u_char *key,  size_t key_len,
    const u_char *msg,  size_t msg_len,
    u_char *out, unsigned int *out_len)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L

    /*
     * OpenSSL 3.0+: use the EVP_MAC API.
     * HMAC() is still present but deprecated; EVP_MAC avoids the warning
     * and is the forward-compatible path.
     */
    EVP_MAC      *mac;
    EVP_MAC_CTX  *ctx;
    OSSL_PARAM    params[2];
    size_t        len;
    const char   *digest_name;
    ngx_int_t     rc;

    digest_name = EVP_MD_get0_name(evp_md);
    if (digest_name == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: EVP_MD_get0_name() failed");
        return NGX_ERROR;
    }

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: EVP_MAC_fetch(HMAC) failed");
        return NGX_ERROR;
    }

    ctx = EVP_MAC_CTX_new(mac);
    /* EVP_MAC_CTX_new() takes its own reference to mac; release ours. */
    EVP_MAC_free(mac);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: EVP_MAC_CTX_new() failed");
        return NGX_ERROR;
    }

    /*
     * OSSL_PARAM_construct_utf8_string takes a non-const char *.
     * digest_name is effectively a constant string owned by OpenSSL; the
     * cast is safe because EVP_MAC_init only reads it.
     */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)(uintptr_t) digest_name,
                                                 0);
    params[1] = OSSL_PARAM_construct_end();

    rc = NGX_ERROR;
    if (EVP_MAC_init(ctx, key, key_len, params) == 1
        && EVP_MAC_update(ctx, msg, msg_len) == 1
        && EVP_MAC_final(ctx, out, &len, EVP_MAX_MD_SIZE) == 1)
    {
        *out_len = (unsigned int) len;
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: EVP_MAC operation failed");
    }

    EVP_MAC_CTX_free(ctx);
    return rc;

#else /* OpenSSL 1.0.x / 1.1.x */

    /*
     * HMAC()'s key_len parameter is int.  Real secret keys are always short,
     * but guard the cast to avoid undefined signed-overflow on adversarial
     * configurations.
     */
    if (key_len > (size_t) INT_MAX) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: HMAC key length (%uz) exceeds INT_MAX",
                      key_len);
        return NGX_ERROR;
    }

    if (HMAC(evp_md, key, (int) key_len, msg, msg_len, out, out_len) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: HMAC() returned NULL");
        return NGX_ERROR;
    }

    return NGX_OK;

#endif /* OPENSSL_VERSION_NUMBER */
}


/* =========================================================================
 * HELPER: ngx_http_secure_link_gauss
 *
 * Converts a broken-down UTC calendar date to a Unix timestamp using
 * the Gauss formula for the proleptic Gregorian calendar.
 * Source: NGINX ngx_http_parse_time.c
 *
 * Parameters: full 4-digit year (>= 1970), month 1–12, mday 1–31,
 *             hour 0–23, min 0–59, sec 0–60 (60 allowed for leap second).
 *
 * Returns the Unix timestamp, or (time_t)-1 if any argument is out of range.
 *
 * KEY FIX — Y2038 safety:
 *   The original code computed "(time_t)(365 * year + …) * 86400".
 *   The sub-expression "365 * year" is evaluated as int * int = int.
 *   For year >= 2038, 365 * 2038 = 743,870 — still fits in int32 — but
 *   the accumulated day count eventually overflows signed int32 around
 *   2037/2038 before the cast to time_t is applied.
 *   Fix: cast year to time_t *before* the first multiplication so that
 *   all arithmetic in the formula promotes to the wider type.
 * ========================================================================= */

static time_t
ngx_http_secure_link_gauss(int year, int month, int mday,
    int hour, int min, int sec)
{
    time_t  days;

    /* Basic range checks — callers must still validate month names etc. */
    if (year < 1970
        || month < 1 || month > 12
        || mday  < 1 || mday  > 31
        || hour  < 0 || hour  > 23
        || min   < 0 || min   > 59
        || sec   < 0 || sec   > 60)   /* 60 is valid during a leap second */
    {
        return (time_t) -1;
    }

    /*
     * Rearrange so that March is the first month of the year (February is
     * last) — this simplifies leap-day handling in the Gauss formula.
     */
    month -= 2;
    if (month <= 0) {
        month += 12;
        year  -= 1;
    }

    /*
     * Gauss' formula: count Gregorian days since March 1, 1 BC, then
     * subtract the offset to the Unix epoch (March 1, 1970 = day 719527;
     * plus 31 days of January 1970 and 28 days of February 1970).
     *
     * IMPORTANT: "(time_t) year * 365" — cast year to time_t FIRST.
     * If both operands were int, the product would be computed as int and
     * would overflow for dates past ~2037 on 32-bit int platforms.
     */
    days = (time_t) year * 365
           + year / 4
           - year / 100
           + year / 400
           + 367 * month / 12
           - 30
           + mday - 1
           - 719527
           + 31 + 28;

    return days * 86400
           + (time_t) hour * 3600
           + (time_t) min  * 60
           + (time_t) sec;
}


/* =========================================================================
 * HELPER: ngx_http_secure_link_parse_ts
 *
 * Parses a timestamp substring [p, ts_last) into a Unix time_t.
 * ts_last must point one byte past the end of the timestamp (i.e. the
 * position of the next comma, or end-of-value — NOT the NUL terminator).
 *
 * The substring is tried against each format in order; the first match wins.
 * If no format matches, (time_t)-1 is returned.
 *
 * NOTE ON NUL TERMINATION:
 *   sscanf() reads until a format mismatch or NUL.  NGINX ensures that
 *   ngx_str_t values produced by ngx_http_complex_value() are NUL-terminated
 *   (one extra byte is always allocated).  The ts_last boundary is therefore
 *   used only to restrict digit-only validation, not to bound sscanf itself.
 *   The %n specifier is used to verify that sscanf consumed exactly the
 *   expected number of characters and did not overshoot.
 * ========================================================================= */

static time_t
ngx_http_secure_link_parse_ts(ngx_http_request_t *r,
    u_char *p, const u_char *ts_last)
{
    int      year, month, mday, hour, min, sec;
    int      gmtoff_hour, gmtoff_min, nchars, n, i; /* hoisted: C89 requires all decls before statements */
    char     gmtoff_sign;
    time_t   timestamp;
    char     mon_buf[4];    /* 3-char abbreviation + NUL */
    char     wday_buf[4];   /* weekday abbrev; syntactic only, not used */
    u_char  *q;
    size_t   ts_len;

    ts_len = (size_t)(ts_last - p);
    if (ts_len == 0) {
        return (time_t) -1;
    }

    /* ------------------------------------------------------------------
     * Format 1: ISO 8601 with numeric UTC offset
     *   "YYYY-MM-DDThh:mm:ss+HH:MM"  or  "…-HH:MM"
     *   25 characters; timezone offset is east (+) or west (-) of UTC.
     *
     * ------------------------------------------------------------------ */
    nchars = 0;
    n = sscanf((char *) p,
               "%4d-%2d-%2dT%2d:%2d:%2d%c%2d:%2d%n",
               &year, &month, &mday,
               &hour, &min, &sec,
               &gmtoff_sign, &gmtoff_hour, &gmtoff_min,
               &nchars);

    if (n == 9
        && nchars > 0
        && (gmtoff_sign == '+' || gmtoff_sign == '-')
        && gmtoff_hour >= 0 && gmtoff_hour <= 23
        && gmtoff_min  >= 0 && gmtoff_min  <= 59)
    {
        time_t  gmtoff;

        timestamp = ngx_http_secure_link_gauss(year, month, mday,
                                               hour, min, sec);
        if (timestamp == (time_t) -1) {
            return (time_t) -1;
        }

        gmtoff = (time_t) gmtoff_hour * 3600 + (time_t) gmtoff_min * 60;

        /* East of UTC: subtract offset; west of UTC: add offset. */
        if (gmtoff_sign == '+') {
            timestamp -= gmtoff;
        } else {
            timestamp += gmtoff;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link ISO 8601 +offset timestamp: %T", timestamp);
        return timestamp;
    }

    /* ------------------------------------------------------------------
     * Format 2: ISO 8601 UTC with "Z" suffix
     *   "YYYY-MM-DDThh:mm:ssZ"   (20 characters)
     *
     * ------------------------------------------------------------------ */
    nchars = 0;
    n = sscanf((char *) p,
               "%4d-%2d-%2dT%2d:%2d:%2dZ%n",
               &year, &month, &mday,
               &hour, &min, &sec,
               &nchars);

    if (n == 6 && nchars > 0) {
        timestamp = ngx_http_secure_link_gauss(year, month, mday,
                                               hour, min, sec);
        if (timestamp == (time_t) -1) {
            return (time_t) -1;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link ISO 8601 UTC (Z) timestamp: %T", timestamp);
        return timestamp;
    }

    /* ------------------------------------------------------------------
     * Format 3: RFC 7231 / IMF-fixdate (HTTP date)
     *   "Day, DD Mon YYYY hh:mm:ss GMT"
     *   e.g. "Sun, 06 Nov 1994 08:49:37 GMT"   (29 characters)
     *
     *   All RFC 7231 dates are implicitly UTC; no offset is applied.
     *   RFC 7231 §7.1.1.1 — this is the preferred HTTP date format.
     *
     *   The weekday abbreviation (wday_buf) is read for syntactic
     *   validity but not used in the timestamp calculation.
     * ------------------------------------------------------------------ */
    nchars = 0;
    n = sscanf((char *) p,
               "%3s, %2d %3s %4d %2d:%2d:%2d GMT%n",
               wday_buf, &mday, mon_buf, &year,
               &hour, &min, &sec,
               &nchars);

    if (n == 7 && nchars > 0) {

        /* Map the 3-letter month abbreviation to an integer 1–12 */
        month = 0;
        for (i = 0; i < 12; i++) {
            if (ngx_strncasecmp((u_char *) mon_buf,
                                (u_char *) ngx_http_secure_link_months[i],
                                3) == 0)
            {
                month = i + 1;
                break;
            }
        }

        if (month == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure link: unrecognised RFC 7231 month \"%.3s\"",
                           mon_buf);
            return (time_t) -1;
        }

        timestamp = ngx_http_secure_link_gauss(year, month, mday,
                                               hour, min, sec);
        if (timestamp == (time_t) -1) {
            return (time_t) -1;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link RFC 7231 timestamp: %T", timestamp);
        return timestamp;
    }

    /* ------------------------------------------------------------------
     * Format 4: Unix timestamp (decimal integer string)
     *
     * Every byte in [p, ts_last) must be a decimal digit — strings that
     * begin with digits but contain other characters are rejected before
     * ngx_atotm() is called.
     * ------------------------------------------------------------------ */
    for (q = p; q < ts_last; q++) {
        if (*q < '0' || *q > '9') {
            return (time_t) -1;
        }
    }

    /* ngx_atotm returns -1 on overflow/invalid input */
    timestamp = ngx_atotm(p, ts_len);
    if (timestamp < 0) {
        return (time_t) -1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link Unix timestamp: %T", timestamp);
    return timestamp;
}


/* =========================================================================
 * VARIABLE HANDLER: $secure_link_hmac
 *
 * Validates the incoming HMAC token.  Sets the variable to:
 *   "1"  — token is valid and the link has not expired
 *   "0"  — token is valid but the link has expired
 *   ""   — (not_found) token is missing, malformed, or HMAC mismatch
 * ========================================================================= */

static ngx_int_t
ngx_http_secure_link_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_link_ctx_t   *ctx;
    ngx_http_secure_link_conf_t  *conf;
    const EVP_MD                 *evp_md;
    u_char                       *last, *token_end, *ts_start, *ts_end,
                                 *exp_start;
    ngx_str_t                     value, hash, key;
    u_char                        hash_buf[EVP_MAX_MD_SIZE];
    u_char                        hmac_buf[EVP_MAX_MD_SIZE];
    unsigned int                  hmac_len;
    int                           md_size;
    time_t                        timestamp, expires;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_hmac_secure_link_module);

    if (conf->hmac_variable == NULL
        || conf->hmac_message == NULL
        || conf->hmac_secret  == NULL)
    {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->hmac_variable, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link variable: \"%V\"", &value);

    last      = value.data + value.len;
    timestamp = 0;
    expires   = 0;
    ctx       = NULL;

    /* ------------------------------------------------------------------
     * Split the directive value: "<token>,<timestamp>[,<expires>]"
     *
     * token_end points at the first comma (separator between token and
     * timestamp); ts_start is the byte after it.
     * ------------------------------------------------------------------ */
    token_end = ngx_strlchr(value.data, last, ',');

    if (token_end) {

        /* Trim value to the base64url token only */
        value.len = (size_t)(token_end - value.data);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link token: \"%V\"", &value);

        ts_start = token_end + 1;

        /*
         * Locate the end of the timestamp field.  RFC 7231 dates contain
         * an embedded comma after the three-character weekday abbreviation
         * (e.g. "Sun, 06 Nov 1994 08:49:37 GMT").  When the timestamp field
         * starts with three alpha characters followed by a comma we skip
         * past that internal comma before searching for the expires-field
         * separator, so the embedded comma is not mistaken for a field
         * boundary.
         */
        {
            u_char *sep_search = ts_start;
            if ((last - ts_start) >= 4
                && ngx_isalpha(ts_start[0])
                && ngx_isalpha(ts_start[1])
                && ngx_isalpha(ts_start[2])
                && ts_start[3] == ',')
            {
                sep_search = ts_start + 4;
            }
            ts_end = ngx_strlchr(sep_search, last, ',');
            if (ts_end == NULL) {
                ts_end = last;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link timestamp string: \"%*s\"",
                       (int)(ts_end - ts_start), ts_start);

        /* Parse using ISO 8601 (with offset or Z), RFC 7231, or Unix */
        timestamp = ngx_http_secure_link_parse_ts(r, ts_start, ts_end);
        if (timestamp == (time_t) -1 || timestamp <= 0) {
            goto not_found;
        }

        /* ------------------------------------------------------------------
         * Optional expiration period (seconds after the timestamp comma).
         * ------------------------------------------------------------------ */
        if (ts_end < last) {
            exp_start = ts_end + 1;
            expires   = ngx_atotm(exp_start, (size_t)(last - exp_start));

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure link expires: %T", expires);

            if (expires < 0) {
                goto not_found;
            }

            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_secure_link_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }

            ngx_http_set_ctx(r, ctx, ngx_http_hmac_secure_link_module);

            ctx->expires.data = exp_start;
            ctx->expires.len  = (size_t)(last - exp_start);
        }
    }

    /* ------------------------------------------------------------------
     * Resolve and validate the digest algorithm.
     * ------------------------------------------------------------------ */
    evp_md = EVP_get_digestbyname((const char *) conf->hmac_algorithm.data);
    if (evp_md == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: unknown digest algorithm \"%V\"",
                      &conf->hmac_algorithm);
        return NGX_ERROR;
    }

    /* EVP_MD_get_size() returns -1 on error in OpenSSL 3.0; check before use. */
    md_size = NGX_HMAC_MD_SIZE(evp_md);
    if (md_size <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: digest size query failed (returned %d)",
                      md_size);
        return NGX_ERROR;
    }

    /* ------------------------------------------------------------------
     * Decode and validate the base64url-encoded HMAC token.
     * ------------------------------------------------------------------ */
    hash.len  = (size_t) md_size;
    hash.data = hash_buf;

    if (value.len > (size_t)(ngx_base64_encoded_length((size_t) md_size) + 2)) {
        goto not_found;
    }

    if (ngx_decode_base64url(&hash, &value) != NGX_OK) {
        goto not_found;
    }

    if (hash.len != (size_t) md_size) {
        goto not_found;
    }

    /* ------------------------------------------------------------------
     * Retrieve message and secret key, then compute the expected HMAC.
     * ------------------------------------------------------------------ */
    if (ngx_http_complex_value(r, conf->hmac_message, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link message: \"%V\"", &value);

    if (ngx_http_complex_value(r, conf->hmac_secret, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_secure_link_hmac_compute(r, evp_md,
                                          key.data,   key.len,
                                          value.data, value.len,
                                          hmac_buf, &hmac_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Constant-time comparison to prevent timing-based side-channel attacks.
     * CRYPTO_memcmp is guaranteed not to be optimised out.
     */
    if (CRYPTO_memcmp(hash_buf, hmac_buf, (size_t) md_size) != 0) {
        goto not_found;
    }

    /* ------------------------------------------------------------------
     * Token is authentic.  Check expiry.
     * expires == 0 means no expiry (unlimited lifetime).
     * ------------------------------------------------------------------ */
    v->data = (u_char *) ((expires > 0 && timestamp + expires < ngx_time())
                          ? "0" : "1");
    v->len        = 1;
    v->valid      = 1;
    v->no_cacheable = 0;
    v->not_found  = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;
    return NGX_OK;
}


/* =========================================================================
 * VARIABLE HANDLER: $secure_link_hmac_token
 *
 * Computes and returns a fresh base64url-encoded HMAC token using the
 * configured message and secret key.  Useful when NGINX acts as a proxy
 * that must forward authenticated requests to a backend.
 * ========================================================================= */

static ngx_int_t
ngx_http_secure_link_token_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_link_conf_t  *conf;
    u_char                       *p;
    ngx_str_t                     value, key, hmac, token;
    const EVP_MD                 *evp_md;
    u_char                        hmac_buf[EVP_MAX_MD_SIZE];
    unsigned int                  hmac_len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_hmac_secure_link_module);

    if (conf->hmac_message == NULL || conf->hmac_secret == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->hmac_message, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link string to sign: \"%V\"", &value);

    if (ngx_http_complex_value(r, conf->hmac_secret, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    evp_md = EVP_get_digestbyname((const char *) conf->hmac_algorithm.data);
    if (evp_md == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "secure link: unknown digest algorithm \"%V\"",
                      &conf->hmac_algorithm);
        return NGX_ERROR;
    }

    /* Allocate enough for the base64url-encoded HMAC output */
    p = ngx_pnalloc(r->pool,
                    (size_t) ngx_base64_encoded_length(EVP_MAX_MD_SIZE) + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    hmac.data  = hmac_buf;
    token.data = p;

    if (ngx_http_secure_link_hmac_compute(r, evp_md,
                                          key.data,   key.len,
                                          value.data, value.len,
                                          hmac.data, &hmac_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    hmac.len = (size_t) hmac_len;

    ngx_encode_base64url(&token, &hmac);

    v->data       = token.data;
    v->len        = token.len;
    v->valid      = 1;
    v->no_cacheable = 0;
    v->not_found  = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;
    return NGX_OK;
}


/* =========================================================================
 * VARIABLE HANDLER: $secure_link_hmac_expires
 *
 * Returns the raw expiration-period string (in seconds) as it appeared in
 * the request, or sets not_found if no expiration was present.
 *
 * The context is populated by ngx_http_secure_link_variable(); this handler
 * must therefore be called after $secure_link_hmac has been evaluated.
 * ========================================================================= */

static ngx_int_t
ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_secure_link_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hmac_secure_link_module);

    if (ctx) {
        v->data       = ctx->expires.data;
        v->len        = ctx->expires.len;
        v->valid      = 1;
        v->no_cacheable = 0;
        v->not_found  = 0;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


/* =========================================================================
 * Configuration lifecycle
 * ========================================================================= */

static void *
ngx_http_secure_link_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_link_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * ngx_pcalloc() zero-initialises the block, so:
     *   conf->hmac_variable  = NULL
     *   conf->hmac_message   = NULL
     *   conf->hmac_secret    = NULL
     *   conf->hmac_algorithm = { 0, NULL }
     */

    return conf;
}


static char *
ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_link_conf_t *prev = parent;
    ngx_http_secure_link_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->hmac_algorithm, prev->hmac_algorithm,
                             NGX_DEFAULT_HASH_FUNCTION);

    if (conf->hmac_variable == NULL) {
        conf->hmac_variable = prev->hmac_variable;
    }

    if (conf->hmac_message == NULL) {
        conf->hmac_message = prev->hmac_message;
    }

    if (conf->hmac_secret == NULL) {
        conf->hmac_secret = prev->hmac_secret;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_link_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *v;

    for (v = ngx_http_secure_link_vars; v->name.len; v++) {
        ngx_http_variable_t  *var;
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data        = v->data;
    }

    return NGX_OK;
}
