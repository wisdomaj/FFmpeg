/*
 * HTTP protocol for ffmpeg client
 * Copyright (c) 2000, 2001 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdbool.h>

#include "config.h"
#include "config_components.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#if CONFIG_ZLIB
#include <zlib.h>
#endif /* CONFIG_ZLIB */

#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/getenv_utf8.h"
#include "libavutil/macros.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/parseutils.h"
#include "libavutil/dict.h"

#include "avformat.h"
#include "http.h"
#include "httpauth.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "version.h"

/* XXX: POST protocol is not completely implemented because ffmpeg uses
 * only a subset of it. */

/* The IO buffer size is unrelated to the max URL size in itself, but needs
 * to be large enough to fit the full request headers (including long
 * path names). */
#define BUFFER_SIZE   (MAX_URL_SIZE + HTTP_HEADERS_SIZE)
#define MAX_REDIRECTS 8
#define MAX_CACHED_REDIRECTS 32
#define HTTP_SINGLE   1
#define HTTP_MUTLI    2
#define MAX_DATE_LEN  19
#define WHITESPACES " \n\t\r"
typedef enum {
    LOWER_PROTO,
    READ_HEADERS,
    WRITE_REPLY_HEADERS,
    FINISH
}HandshakeState;

#ifndef MVD_USE_LIBCURL
typedef struct HTTPContext {
    const AVClass *class;
    URLContext *hd;
    unsigned char buffer[BUFFER_SIZE], *buf_ptr, *buf_end;
    int line_count;
    int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    uint64_t chunksize;
    int chunkend;
    uint64_t off, end_off, filesize;
    char *uri;
    char *location;
    HTTPAuthState auth_state;
    HTTPAuthState proxy_auth_state;
    char *http_proxy;
    char *headers;
    char *mime_type;
    char *http_version;
    char *user_agent;
    char *referer;
    char *content_type;
    /* Set if the server correctly handles Connection: close and will close
     * the connection after feeding us the content. */
    int willclose;
    int seekable;           /**< Control seekability, 0 = disable, 1 = enable, -1 = probe. */
    int chunked_post;
    /* A flag which indicates if the end of chunked encoding has been sent. */
    int end_chunked_post;
    /* A flag which indicates we have finished to read POST reply. */
    int end_header;
    /* A flag which indicates if we use persistent connections. */
    int multiple_requests;
    uint8_t *post_data;
    int post_datalen;
    int is_akamai;
    int is_mediagateway;
    char *cookies;          ///< holds newline (\n) delimited Set-Cookie header field values (without the "Set-Cookie: " field name)
    /* A dictionary containing cookies keyed by cookie name */
    AVDictionary *cookie_dict;
    int icy;
    /* how much data was read since the last ICY metadata packet */
    uint64_t icy_data_read;
    /* after how many bytes of read data a new metadata packet will be found */
    uint64_t icy_metaint;
    char *icy_metadata_headers;
    char *icy_metadata_packet;
    AVDictionary *metadata;
#if CONFIG_ZLIB
    int compressed;
    z_stream inflate_stream;
    uint8_t *inflate_buffer;
#endif /* CONFIG_ZLIB */
    AVDictionary *chained_options;
    /* -1 = try to send if applicable, 0 = always disabled, 1 = always enabled */
    int send_expect_100;
    char *method;
    int reconnect;
    int reconnect_at_eof;
    int reconnect_on_network_error;
    int reconnect_streamed;
    int reconnect_delay_max;
    char *reconnect_on_http_error;
    int listen;
    char *resource;
    int reply_code;
    int is_multi_client;
    HandshakeState handshake_step;
    int is_connected_server;
    int short_seek_size;
    int64_t expires;
    char *new_location;
    AVDictionary *redirect_cache;
    uint64_t filesize_from_content_range;
    int respect_retry_after;
    unsigned int retry_after;
    int reconnect_max_retries;
    int reconnect_delay_total_max;
} HTTPContext;

#define OFFSET(x) offsetof(HTTPContext, x)
#endif // !MVD_USE_LIBCURL

#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define DEFAULT_USER_AGENT "Lavf/" AV_STRINGIFY(LIBAVFORMAT_VERSION)

static int parse_http_date(const char *date_str, struct tm *buf)
{
    char date_buf[MAX_DATE_LEN];
    int i, j, date_buf_len = MAX_DATE_LEN-1;
    char *date;

    // strip off any punctuation or whitespace
    for (i = 0, j = 0; date_str[i] != '\0' && j < date_buf_len; i++) {
        if ((date_str[i] >= '0' && date_str[i] <= '9') ||
            (date_str[i] >= 'A' && date_str[i] <= 'Z') ||
            (date_str[i] >= 'a' && date_str[i] <= 'z')) {
            date_buf[j] = date_str[i];
            j++;
        }
    }
    date_buf[j] = '\0';
    date = date_buf;

    // move the string beyond the day of week
    while ((*date < '0' || *date > '9') && *date != '\0')
        date++;

    return av_small_strptime(date, "%d%b%Y%H%M%S", buf) ? 0 : AVERROR(EINVAL);
}

#ifdef MVD_USE_LIBCURL

#include <curl/curl.h>
#include <inttypes.h>
#include <errno.h>
#include "libavutil/error.h"
#include <stdatomic.h>

#define MVD_CURL_RING_CAP (4 * 1024 * 1024)  // 4 MiB bounded buffer

typedef struct MVDCurlHTTPContext {
    const AVClass *class;

    char *url;
    char *final_url;
    char *user_agent;
    char *referer;
    char *headers;   // CRLF-separated header lines
    char *cookies;   // treated as Cookie: value
    char *http_proxy;
    char *no_proxy;

    int64_t off;
    int64_t end_off;
    int seekable;

    int timeout_us;
    int rw_timeout_us;

    // Compatibility with FFmpeg http.c options
    int reconnect;
    int reconnect_at_eof;
    int reconnect_on_network_error;
    int reconnect_streamed;
    int reconnect_delay_max;
    int reconnect_max_retries;
    int reconnect_delay_total_max;
    int respect_retry_after;
    char *reconnect_on_http_error;
    unsigned int retry_after;

    uint8_t *ring;
    size_t cap, rpos, wpos, fill;

    int eof;
    int err;
    int64_t content_length; // best-effort
    long http_code;
    char *http_version;
    char *location_header;
    char *content_encoding;
    char *content_type;
    char *set_cookie_headers;
    char *cookie_jar;
    int accept_ranges;
    int header_status_line_seen;
    int64_t content_range_total;
    int64_t content_range_start;
    int last_curl_code;
    int icy;
    char *icy_metadata_headers;
    char *icy_metadata_packet;
    AVDictionary *metadata;
    int64_t icy_metaint;
    int64_t icy_data_read;

    CURL *easy;
    CURLM *multi;
    struct curl_slist *hdr_list;

    int abort_request;
    int64_t request_start;

    int paused;

    URLContext *h; // for interrupt_callback
} MVDCurlHTTPContext;

#define MVD_OFFSET(x) offsetof(MVDCurlHTTPContext, x)

// Forward declarations (C99 forbids implicit function declarations)
static int mvd_open(URLContext *h, const char *uri, int flags, AVDictionary **options);
static int mvd_read(URLContext *h, uint8_t *buf, int size);
static int mvd_read_once(URLContext *h, uint8_t *buf, int size);
static int64_t mvd_seek(URLContext *h, int64_t off, int whence);
static int mvd_close(URLContext *h);

static const AVOption mvd_curl_http_options[] = {
    { "headers",    "set custom HTTP headers",            MVD_OFFSET(headers),    AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "user_agent", "override User-Agent header",         MVD_OFFSET(user_agent), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
    { "referer",    "override referer header",            MVD_OFFSET(referer),    AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "cookies",    "newline-delimited Set-Cookie values for curl COOKIELIST",    MVD_OFFSET(cookies),    AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "http_proxy",  "set HTTP proxy to tunnel through", MVD_OFFSET(http_proxy), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "no_proxy",    "comma separated hostlist to not proxy", MVD_OFFSET(no_proxy),   AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "offset",     "initial byte offset",                MVD_OFFSET(off),        AV_OPT_TYPE_INT64,  { .i64 = 0 },    0, INT64_MAX, D },
    { "end_offset", "try to limit the request to bytes preceding this offset", MVD_OFFSET(end_off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "seekable",   "control seekability of connection",  MVD_OFFSET(seekable),   AV_OPT_TYPE_INT,    { .i64 = -1 },  -1, 1, D },
    { "timeout",    "connection timeout in microseconds", MVD_OFFSET(timeout_us), AV_OPT_TYPE_INT,    { .i64 = 0 },     0, INT_MAX, D },
    { "rw_timeout", "read/write timeout in microseconds", MVD_OFFSET(rw_timeout_us), AV_OPT_TYPE_INT, { .i64 = 0 },  0, INT_MAX, D },
    { "http_version", "export HTTP version",              MVD_OFFSET(http_version), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "location",     "Location header value",            MVD_OFFSET(location_header), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    // Default to off for libcurl backend: a bunch of CDNs will hard-drop (e.g. nginx 444)
    // requests that contain Icy-MetaData on non-ICY endpoints. Users can still enable it.
    { "icy",         "request ICY metadata",              MVD_OFFSET(icy), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "icy_metadata_headers", "return ICY metadata headers",   MVD_OFFSET(icy_metadata_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "icy_metadata_packet",  "return current ICY metadata packet", MVD_OFFSET(icy_metadata_packet), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "metadata",     "metadata read from the bitstream", MVD_OFFSET(metadata), AV_OPT_TYPE_DICT, {0}, 0, 0, AV_OPT_FLAG_EXPORT },
    { "content_encoding", "Content-Encoding header",        MVD_OFFSET(content_encoding), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "set_cookie_headers", "Set-Cookie headers",          MVD_OFFSET(set_cookie_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },

    // Insert FFmpeg http.c compatible options for CLI compatibility and retry logic
    { "reconnect", "auto reconnect after disconnect before EOF", MVD_OFFSET(reconnect), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_at_eof", "auto reconnect at EOF", MVD_OFFSET(reconnect_at_eof), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_network_error", "auto reconnect in case of network error", MVD_OFFSET(reconnect_on_network_error), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_http_error", "list of http status codes/groups to reconnect on", MVD_OFFSET(reconnect_on_http_error), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "reconnect_streamed", "auto reconnect streamed / non seekable streams", MVD_OFFSET(reconnect_streamed), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_delay_max", "max reconnect delay in seconds after which to give up", MVD_OFFSET(reconnect_delay_max), AV_OPT_TYPE_INT, { .i64 = 120 }, 0, INT_MAX, D },
    { "reconnect_max_retries", "the max number of times to retry a connection", MVD_OFFSET(reconnect_max_retries), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, D },
    { "reconnect_delay_total_max", "max total reconnect delay in seconds after which to give up", MVD_OFFSET(reconnect_delay_total_max), AV_OPT_TYPE_INT, { .i64 = 256 }, 0, INT_MAX, D },
    { "respect_retry_after", "respect the Retry-After header when retrying connections", MVD_OFFSET(respect_retry_after), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },

    { NULL }
};

static const AVClass mvd_curl_http_class = {
    .class_name = "mvd_curl_http",
    .item_name  = av_default_item_name,
    .option     = mvd_curl_http_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static int mvd_should_abort(MVDCurlHTTPContext *s)
{
    if (s->abort_request) return 1;
    if (s->h && s->h->interrupt_callback.callback &&
        s->h->interrupt_callback.callback(s->h->interrupt_callback.opaque))
        return 1;
    return 0;
}

static int mvd_xferinfo_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                          curl_off_t ultotal, curl_off_t ulnow)
{
    MVDCurlHTTPContext *s = (MVDCurlHTTPContext *)clientp;
    (void)dltotal; (void)dlnow; (void)ultotal; (void)ulnow;
    return mvd_should_abort(s) ? 1 : 0;
}

static int mvd_is_curl_network_error(CURLcode code)
{
    switch (code) {
    case CURLE_COULDNT_CONNECT:
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_RECV_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_PARTIAL_FILE:
        return 1;
    default:
        return 0;
    }
}

static int mvd_read_full(MVDCurlHTTPContext *s, uint8_t *buf, int size)
{
    URLContext *h = s->h;
    int total = 0;

    while (total < size) {
        int ret = mvd_read_once(h, buf + total, size - total);
        if (ret <= 0)
            return total ? total : ret;
        total += ret;
    }
    return total;
}

static void mvd_update_metadata(MVDCurlHTTPContext *s, char *data)
{
    char *key;
    char *val;
    char *end;
    char *next = data;

    while (*next) {
        key = next;
        val = strstr(key, "='");
        if (!val)
            break;
        end = strstr(val, "';");
        if (!end)
            break;

        *val = '\0';
        *end = '\0';
        val += 2;

        av_dict_set(&s->metadata, key, val, 0);
        av_log(s->h, AV_LOG_VERBOSE, "Metadata update for %s: %s\n", key, val);

        next = end + 2;
    }
}

static int mvd_handle_icy_metadata(MVDCurlHTTPContext *s)
{
    URLContext *h = s->h;
    uint8_t header;
    int ret = mvd_read_full(s, &header, 1);
    if (ret <= 0)
        return ret;

    int len = header * 16;
    if (len > 255 * 16 || len < 0)
        return AVERROR(EINVAL);

    if (!len) {
        s->icy_data_read = 0;
        return 0;
    }

    char *data = av_malloc(len + 1);
    if (!data)
        return AVERROR(ENOMEM);

    ret = mvd_read_full(s, (uint8_t *)data, len);
    if (ret < 0) {
        av_free(data);
        return ret;
    }
    if (ret != len) {
        av_free(data);
        return AVERROR(EIO);
    }
    data[len] = '\0';

    ret = av_opt_set(s, "icy_metadata_packet", data, 0);
    if (ret >= 0)
        mvd_update_metadata(s, data);
    av_free(data);

    s->icy_data_read = 0;
    return ret;
}

static int mvd_read_data(URLContext *h, uint8_t *buf, int size)
{
    MVDCurlHTTPContext *s = h->priv_data;
    if (s->icy_metaint <= 0)
        return mvd_read_once(h, buf, size);

    int total = 0;
    while (total < size) {
        int64_t remaining = s->icy_metaint - s->icy_data_read;
        if (remaining <= 0) {
            int ret = mvd_handle_icy_metadata(s);
            if (ret < 0)
                return ret;
            continue;
        }

        int read_size = FFMIN(size - total, (int)remaining);
        int ret = mvd_read_once(h, buf + total, read_size);
        if (ret <= 0)
            return total ? total : ret;
        total += ret;
        s->icy_data_read += ret;

        if (s->icy_data_read >= s->icy_metaint) {
            int meta_ret = mvd_handle_icy_metadata(s);
            if (meta_ret < 0)
                return meta_ret;
        }
    }
    return total;
}

static int mvd_build_headers(MVDCurlHTTPContext *s)
{
    if (!s->headers || !*s->headers)
        return 0;

    // FFmpeg CLI passes -headers as a single string where lines are typically separated by '\n'.
    // Some callers use CRLF. Accept both.
    const char *p = s->headers;
    while (*p) {
        // Find end-of-line by LF; tolerate CRLF.
        const char *lf = strchr(p, '\n');
        size_t len = lf ? (size_t)(lf - p) : strlen(p);

        // Trim a trailing '\r' (CRLF case)
        while (len > 0 && p[len - 1] == '\r')
            len--;

        // Trim leading/trailing spaces/tabs
        size_t start = 0;
        while (start < len && (p[start] == ' ' || p[start] == '\t'))
            start++;
        while (len > start && (p[len - 1] == ' ' || p[len - 1] == '\t'))
            len--;

        if (len > start) {
            char *line = av_strndup(p + start, len - start);
            if (!line)
                return AVERROR(ENOMEM);

            // libcurl rejects header lines containing CR/LF. Be strict.
            if (!strchr(line, '\n') && !strchr(line, '\r')) {
                struct curl_slist *new_list = curl_slist_append(s->hdr_list, line);
                if (!new_list) {
                    av_log(s->h, AV_LOG_WARNING, "Failed to append header line to curl list (ignored): %s\n", line);
                } else {
                    s->hdr_list = new_list;
                }
            } else {
                av_log(s->h, AV_LOG_WARNING, "Skipping invalid header line containing CR/LF\n");
            }

            av_free(line);
        }

        if (!lf)
            break;
        p = lf + 1;
    }

    return 0;
}

static void mvd_log_request_headers(URLContext *h, MVDCurlHTTPContext *s, const char *range)
{
    // Mirror FFmpeg's debug style: dump what we are about to send.
    if (!h)
        return;

    AVBPrint bp;
    av_bprint_init(&bp, 0, AV_BPRINT_SIZE_UNLIMITED);

    av_bprintf(&bp, "\n--- mvd curl request ---\n");
    av_bprintf(&bp, "URL: %s\n", s->url ? s->url : "");

    // Note: libcurl will generate Host/Accept/Connection/etc. We log what we explicitly set.
    if (s->user_agent && *s->user_agent)
        av_bprintf(&bp, "User-Agent: %s\n", s->user_agent);
    if (s->referer && *s->referer)
        av_bprintf(&bp, "Referer: %s\n", s->referer);

    if (range && *range)
        av_bprintf(&bp, "Range: %s\n", range);

    if (s->headers && *s->headers) {
        av_bprintf(&bp, "Custom headers (from -headers):\n");
        // s->headers is CRLF-separated; print as-is but ensure it ends with \n for readability.
        av_bprintf(&bp, "%s\n", s->headers);
    }

    // Also dump the actual slist we pass to CURLOPT_HTTPHEADER (includes injected ICY).
    if (s->hdr_list) {
        struct curl_slist *it = s->hdr_list;
        av_bprintf(&bp, "libcurl header list:\n");
        for (; it; it = it->next) {
            if (it->data)
                av_bprintf(&bp, "%s\n", it->data);
        }
    }

    av_bprintf(&bp, "--- end mvd curl request ---\n");

    av_log(h, AV_LOG_DEBUG, "%s", bp.str);
    av_bprint_finalize(&bp, NULL);
}

static int mvd_has_header(const char *headers, const char *needle)
{
    if (!headers || !needle)
        return 0;
    return av_stristr(headers, needle) != NULL;
}

static int mvd_append_line(char **dst, const char *line)
{
    if (!line || !*line)
        return 0;

    if (!*dst)
        return (*dst = av_strdup(line)) ? 0 : AVERROR(ENOMEM);

    char *tmp = av_asprintf("%s\n%s", *dst, line);
    if (!tmp)
        return AVERROR(ENOMEM);
    av_free(*dst);
    *dst = tmp;
    return 0;
}

static void mvd_feed_cookie_list(CURL *easy, URLContext *h, const char *list, int add_prefix)
{
    if (!easy || !list)
        return;

    char *copy = av_strdup(list);
    if (!copy)
        return;

    av_log(h, AV_LOG_DEBUG, "Feeding cookie list (%s) tokens\n", add_prefix ? "user" : "jar");
    char *token = NULL;
    char *saveptr = NULL;
    for (token = av_strtok(copy, "\n", &saveptr); token; token = av_strtok(NULL, "\n", &saveptr)) {
        // Trim whitespace and \r from both ends
        while (*token && (*token == ' ' || *token == '\t' || *token == '\r'))
            token++;
        char *end = token + strlen(token) - 1;
        while (end >= token && (*end == ' ' || *end == '\t' || *end == '\r'))
            *end-- = '\0';
        if (!*token) {
            av_log(h, AV_LOG_DEBUG, "Skipped empty cookie token after trimming\n");
            continue; // Skip empty after trimming
        }

        av_log(h, AV_LOG_DEBUG, "Prepared cookie token: \"%s\"\n", token);

        char *command = NULL;
        const char *cmd = token;
        if (add_prefix) {
            if (!(av_strncasecmp(token, "Set-Cookie:", 11) == 0 ||
                  av_strncasecmp(token, "Set-Cookie2:", 12) == 0 ||
                  strchr(token, '\t') ||
                  token[0] == '#')) {
                command = av_asprintf("Set-Cookie: %s", token);
                if (command)
                    cmd = command;
            }
        }
        av_log(h, AV_LOG_DEBUG, "CURLOPT_COOKIELIST command: \"%s\"\n", cmd);
        CURLcode rc = curl_easy_setopt(easy, CURLOPT_COOKIELIST, cmd);
        av_free(command);
    }

    av_free(copy);
}

static void mvd_feed_cookie_jar(MVDCurlHTTPContext *s)
{
    mvd_feed_cookie_list(s->easy, s->h, s->cookie_jar, 0);
}

static int mvd_store_icy_header(MVDCurlHTTPContext *s, const char *tag, const char *value)
{
    int ret = av_dict_set(&s->metadata, tag, value, 0);
    if (ret < 0)
        return ret;

    char *line = av_asprintf("%s: %s", tag, value ? value : "");
    if (!line)
        return AVERROR(ENOMEM);
    ret = mvd_append_line(&s->icy_metadata_headers, line);
    av_free(line);
    return ret;
}

static void mvd_reset_header_state(MVDCurlHTTPContext *s)
{
    av_freep(&s->http_version);
    av_freep(&s->content_encoding);
    av_freep(&s->content_type);
    av_freep(&s->location_header);
    av_freep(&s->set_cookie_headers);
    av_freep(&s->icy_metadata_headers);
    av_freep(&s->icy_metadata_packet);
    av_dict_free(&s->metadata);
    s->metadata = NULL;
    s->accept_ranges = 0;
    s->content_range_total = -1;
    s->content_range_start = -1;
    s->header_status_line_seen = 0;
    s->content_length = -1;
    s->retry_after = 0;
    s->icy_metaint = 0;
    s->last_curl_code = CURLE_OK;
}

static void mvd_parse_content_range(MVDCurlHTTPContext *s, const char *value)
{
    const char *p;
    if (!value || !av_stristart(value, "bytes ", &p))
        return;

    char *endptr = NULL;
    int64_t start = strtoll(p, &endptr, 10);
    if (!endptr || *endptr != '-')
        return;

    (void)strtoll(endptr + 1, &endptr, 10);
    if (!endptr || *endptr != '/')
        return;

    int64_t total = -1;
    if (endptr[1] && endptr[1] != '*')
        total = strtoll(endptr + 1, NULL, 10);

    s->content_range_start = start;
    if (total > 0) {
        s->content_range_total = total;
        s->content_length = total;
    }

    if (s->seekable != 0 && s->h && total > 0)
        s->h->is_streamed = 0;
}

static void mvd_handle_header_line(MVDCurlHTTPContext *s, const char *name, const char *value)
{
    if (!name || !value)
        return;

    while (*name == ' ' || *name == '\t')
        name++;

    if (!*name)
        return;

    if (!av_strcasecmp(name, "content-length")) {
        int64_t len = strtoll(value, NULL, 10);
        if (len >= 0 && s->content_range_total <= 0)
            s->content_length = s->request_start + len;
    } else if (!av_strcasecmp(name, "content-range")) {
        mvd_parse_content_range(s, value);
    } else if (!av_strcasecmp(name, "accept-ranges")) {
        s->accept_ranges = av_stristr(value, "bytes") != NULL;
        if (s->accept_ranges && s->seekable != 0 && s->h)
            s->h->is_streamed = 0;
    } else if (!av_strcasecmp(name, "location")) {
        char resolved[MAX_URL_SIZE];
        ff_make_absolute_url(resolved, sizeof(resolved), s->url, value);
        av_freep(&s->location_header);
        s->location_header = av_strdup(resolved);
    } else if (!av_strcasecmp(name, "retry-after")) {
        unsigned long delay = 0;
        char *endptr = NULL;
        delay = strtoul(value, &endptr, 10);
        if (endptr == value) {
            struct tm tm = {0};
            if (!parse_http_date(value, &tm)) {
                int64_t retry = av_timegm(&tm);
                int64_t now = av_gettime() / 1000000;
                int64_t diff = retry - now;
                if (diff < 0)
                    diff = 0;
                if (diff > UINT_MAX)
                    delay = UINT_MAX;
                else
                    delay = (unsigned long)diff;
            }
        }
        if (delay > 0)
            s->retry_after = (unsigned int)delay;
    } else if (!av_strcasecmp(name, "content-encoding")) {
        av_freep(&s->content_encoding);
        s->content_encoding = av_strdup(value);
    } else if (!av_strcasecmp(name, "content-type")) {
        av_freep(&s->content_type);
        s->content_type = av_strdup(value);
    } else if (!av_strcasecmp(name, "set-cookie")) {
        mvd_append_line(&s->set_cookie_headers, value);
        char *cookie_line = av_asprintf("Set-Cookie: %s", value);
        if (cookie_line) {
            mvd_append_line(&s->cookie_jar, cookie_line);
            av_free(cookie_line);
        }
    } else if (!av_strncasecmp(name, "icy-", 4)) {
        if (!av_strcasecmp(name, "icy-metaint"))
            s->icy_metaint = strtoll(value, NULL, 10);
        mvd_store_icy_header(s, name, value);
    }
}

static int mvd_should_retry_http_code(MVDCurlHTTPContext *s, long code)
{
    if (!s->reconnect_on_http_error || code < 0)
        return 0;

    char *list = av_strdup(s->reconnect_on_http_error);
    if (!list)
        return 0;

    char *tok = NULL, *saveptr = NULL;
    int should = 0;
    for (tok = av_strtok(list, ", \t", &saveptr); tok; tok = av_strtok(NULL, ", \t", &saveptr)) {
        int len = strlen(tok);
        if (len == 3 && (tok[1] == 'x' || tok[1] == 'X') && (tok[2] == 'x' || tok[2] == 'X') && tok[0] >= '0' && tok[0] <= '9') {
            int prefix = tok[0] - '0';
            if (code >= prefix * 100 && code < (prefix + 1) * 100) {
                should = 1;
                break;
            }
        } else {
            char *end = NULL;
            long target = strtol(tok, &end, 10);
            if (end != tok && target == code) {
                should = 1;
                break;
            }
        }
    }

    av_free(list);
    return should;
}

static size_t mvd_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    MVDCurlHTTPContext *s = userdata;
    size_t total = size * nmemb;
    if (!total)
        return 0;

    char *line = av_strndup(ptr, total);
    if (!line)
        return 0;

    size_t len = total;
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n'))
        line[--len] = '\0';

    if (len) {
        if (av_stristart(line, "HTTP/", NULL) || av_stristart(line, "ICY ", NULL)) {
            if (s->header_status_line_seen) {
                mvd_reset_header_state(s);
                s->request_start = s->off;
            }

            char version[32];
            int code = 0;
            if (sscanf(line, "%31s %d", version, &code) >= 2) {
                s->http_code = code;
                av_freep(&s->http_version);
                s->http_version = av_strdup(version);
                s->header_status_line_seen = 1;
            }
        } else {
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                char *name = line;
                char *value = colon + 1;
                while (*value == ' ' || *value == '\t')
                    value++;
                char *value_end = value + strlen(value);
                while (value_end > value && (*(value_end - 1) == ' ' || *(value_end - 1) == '\t'))
                    *--value_end = '\0';
                char *end = colon;
                while (end > name && (*(end - 1) == ' ' || *(end - 1) == '\t'))
                    *--end = '\0';
                mvd_handle_header_line(s, name, value);
            }
        }
    }

    av_free(line);
    return total;
}

static size_t mvd_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    MVDCurlHTTPContext *s = (MVDCurlHTTPContext *)userdata;
    size_t n = size * nmemb;
    if (!n) return 0;

    size_t space = s->cap - s->fill;
    if (n > space) {
        s->paused = 1;
        return CURL_WRITEFUNC_PAUSE;
    }

    size_t first = FFMIN(n, s->cap - s->wpos);
    memcpy(s->ring + s->wpos, ptr, first);
    s->wpos = (s->wpos + first) % s->cap;
    s->fill += first;

    size_t rem = n - first;
    if (rem) {
        memcpy(s->ring + s->wpos, ptr + first, rem);
        s->wpos = (s->wpos + rem) % s->cap;
        s->fill += rem;
    }

    return n;
}

static int mvd_prepare_easy(MVDCurlHTTPContext *s)
{
    if (!s->easy) {
        s->easy = curl_easy_init();
        if (!s->easy) return AVERROR(ENOMEM);
    } else {
        curl_easy_reset(s->easy);
    }

    curl_easy_setopt(s->easy, CURLOPT_URL, s->url);
    curl_easy_setopt(s->easy, CURLOPT_HEADERFUNCTION, mvd_header_cb);
    curl_easy_setopt(s->easy, CURLOPT_HEADERDATA, s);
    curl_easy_setopt(s->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(s->easy, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(s->easy, CURLOPT_WRITEFUNCTION, mvd_write_cb);
    curl_easy_setopt(s->easy, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(s->easy, CURLOPT_ACCEPT_ENCODING, "");

    char *env_http_proxy = NULL;
    char *env_no_proxy = NULL;
    const char *proxy = s->http_proxy;
    if (!proxy) {
        env_http_proxy = getenv_utf8("http_proxy");
        if (!env_http_proxy)
            env_http_proxy = getenv_utf8("HTTP_PROXY");
        proxy = env_http_proxy;
    }
    if (proxy && *proxy) {
        curl_easy_setopt(s->easy, CURLOPT_PROXY, proxy);
        curl_easy_setopt(s->easy, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    }

    const char *noproxy = s->no_proxy;
    if (!noproxy) {
        env_no_proxy = getenv_utf8("no_proxy");
        if (!env_no_proxy)
            env_no_proxy = getenv_utf8("NO_PROXY");
        noproxy = env_no_proxy;
    }
    if (noproxy && *noproxy)
        curl_easy_setopt(s->easy, CURLOPT_NOPROXY, noproxy);

    freeenv_utf8(env_http_proxy);
    freeenv_utf8(env_no_proxy);

    curl_easy_setopt(s->easy, CURLOPT_COOKIEFILE, "");
    mvd_feed_cookie_jar(s);
    if (s->cookies && *s->cookies)
        mvd_feed_cookie_list(s->easy, s->h, s->cookies, 1);

    if (s->timeout_us > 0)
        curl_easy_setopt(s->easy, CURLOPT_CONNECTTIMEOUT_MS, (long)FFMAX(1, s->timeout_us / 1000));
    if (s->rw_timeout_us > 0) {
        long secs = (long)FFMAX(1, (s->rw_timeout_us + 999999) / 1000000);
        curl_easy_setopt(s->easy, CURLOPT_LOW_SPEED_TIME, secs);
        curl_easy_setopt(s->easy, CURLOPT_LOW_SPEED_LIMIT, 1L);
    } else {
        curl_easy_setopt(s->easy, CURLOPT_LOW_SPEED_TIME, 0L);
        curl_easy_setopt(s->easy, CURLOPT_LOW_SPEED_LIMIT, 0L);
    }

    // Respect explicit headers provided via -headers first.
    // If the caller provided "User-Agent:" or "Referer:" there, do not override with defaults.
    if (!mvd_has_header(s->headers, "User-Agent") && s->user_agent && *s->user_agent)
        curl_easy_setopt(s->easy, CURLOPT_USERAGENT, s->user_agent);
    if (!mvd_has_header(s->headers, "Referer") && s->referer && *s->referer)
        curl_easy_setopt(s->easy, CURLOPT_REFERER, s->referer);

    if (s->hdr_list) {
        curl_slist_free_all(s->hdr_list);
        s->hdr_list = NULL;
    }
    {
        int ret = mvd_build_headers(s);
        if (ret < 0) return ret;

        // ICY support: ONLY when explicitly enabled, and only if user didn't already set it.
        if (s->icy && !mvd_has_header(s->headers, "Icy-MetaData"))
            s->hdr_list = curl_slist_append(s->hdr_list, "Icy-MetaData: 1");

        if (s->hdr_list)
            curl_easy_setopt(s->easy, CURLOPT_HTTPHEADER, s->hdr_list);
    }

#if LIBCURL_VERSION_NUM >= 0x072000
    curl_easy_setopt(s->easy, CURLOPT_XFERINFOFUNCTION, mvd_xferinfo_cb);
    curl_easy_setopt(s->easy, CURLOPT_XFERINFODATA, s);
    curl_easy_setopt(s->easy, CURLOPT_NOPROGRESS, 0L);
#endif

    // Range logic with logging
    const char *range_for_log = NULL;
    char range_buf[128];
    range_buf[0] = '\0';

    if (!(s->h->flags & AVIO_FLAG_WRITE)) {
        if (s->request_start > 0 || s->end_off > 0) {
            if (s->end_off && s->end_off > s->request_start) {
                snprintf(range_buf, sizeof(range_buf), "bytes=%"PRId64"-%"PRId64, s->request_start, s->end_off - 1);
            } else {
                snprintf(range_buf, sizeof(range_buf), "bytes=%"PRId64"-", s->request_start);
            }
            curl_easy_setopt(s->easy, CURLOPT_RANGE, range_buf);
            range_for_log = range_buf;
        } else {
            curl_easy_setopt(s->easy, CURLOPT_RANGE, NULL);
        }
    } else {
        curl_easy_setopt(s->easy, CURLOPT_RANGE, NULL);
    }

    // Dump request headers when ffmpeg runs with -loglevel debug (or more verbose).
    mvd_log_request_headers(s->h, s, range_for_log);

    curl_easy_setopt(s->easy, CURLOPT_TCP_KEEPALIVE, 1L);
    return 0;
}

static int mvd_start(MVDCurlHTTPContext *s)
{
    s->abort_request = 0;
    s->rpos = s->wpos = s->fill = 0;
    s->eof = 0;
    s->err = 0;
    s->paused = 0;
    s->content_length = -1;
    mvd_reset_header_state(s);

    if (s->multi) {
        if (s->easy) curl_multi_remove_handle(s->multi, s->easy);
        curl_multi_cleanup(s->multi);
        s->multi = NULL;
    }

    int prep = mvd_prepare_easy(s);
    if (prep < 0) return prep;

    s->multi = curl_multi_init();
    if (!s->multi) return AVERROR(ENOMEM);

    curl_multi_add_handle(s->multi, s->easy);
    return 0;
}

static int mvd_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    MVDCurlHTTPContext *s = h->priv_data;
    int ret;
    static atomic_int mvd_curl_inited = 0;

    (void)flags;
    if (!atomic_load(&mvd_curl_inited)) {
        if (!atomic_exchange(&mvd_curl_inited, 1)) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
        }
    }

    s->class = &mvd_curl_http_class;
    s->h = h;
    av_opt_set_defaults(s);
    s->cookie_jar = av_strdup("");
    if (!s->cookie_jar) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if (options) {
        ret = av_opt_set_dict(s, options);
        if (ret < 0) goto fail;
    }

    av_freep(&s->url);
    s->url = av_strdup(uri);
    if (!s->url) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    s->cap = MVD_CURL_RING_CAP;
    s->ring = av_malloc(s->cap);
    if (!s->ring) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    h->is_streamed = (s->seekable == 1) ? 0 : 1;

    s->request_start = s->off;
    ret = mvd_start(s);
    if (ret < 0) goto fail;

    return 0;

fail:
    mvd_close(h);
    return ret;
}

static int mvd_read_once(URLContext *h, uint8_t *buf, int size)
{
    MVDCurlHTTPContext *s = h->priv_data;
    int out = 0;

    while (out < size) {
        if (mvd_should_abort(s)) return AVERROR_EXIT;

        if (s->fill > 0) {
            size_t take = FFMIN((size_t)(size - out), s->fill);
            size_t first = FFMIN(take, s->cap - s->rpos);
            memcpy(buf + out, s->ring + s->rpos, first);
            s->rpos = (s->rpos + first) % s->cap;
            s->fill -= first;
            out += (int)first;

            size_t rem = take - first;
            if (rem) {
                memcpy(buf + out, s->ring + s->rpos, rem);
                s->rpos = (s->rpos + rem) % s->cap;
                s->fill -= rem;
                out += (int)rem;
            }

            if (s->paused && (s->cap - s->fill) >= 64 * 1024) {
                s->paused = 0;
                curl_easy_pause(s->easy, CURLPAUSE_CONT);
            }
            continue;
        }

        if (s->eof) {
            if (out > 0) break;
            return s->err ? s->err : AVERROR_EOF;
        }

        // No data in ring, pump curl
        int running;
        CURLMcode mc = curl_multi_perform(s->multi, &running);
        if (mc != CURLM_OK) return AVERROR(EIO);

        if (!running) {
            int msgs;
            CURLMsg *msg;
            while ((msg = curl_multi_info_read(s->multi, &msgs))) {
                if (msg->msg != CURLMSG_DONE)
                    continue;
                CURLcode cc = msg->data.result;
                s->last_curl_code = cc;
                curl_easy_getinfo(s->easy, CURLINFO_RESPONSE_CODE, &s->http_code);
                {
                    char *eff = NULL;
                    curl_easy_getinfo(s->easy, CURLINFO_EFFECTIVE_URL, &eff);
                    av_log(h, AV_LOG_DEBUG,
                        "curl done: curl=%d(%s) http=%ld eff_url=%s fill=%zu\n",
                        (int)cc, curl_easy_strerror(cc), s->http_code,
                        eff ? eff : "", s->fill);
                }
                if (cc == CURLE_OK) {
                    if (s->http_code >= 400) {
                        if (s->fill > 0) {
                            size_t dump = FFMIN((size_t)64, s->fill);
                            char preview[65];
                            size_t i;
                            for (i = 0; i < dump; i++) {
                                preview[i] = (char)s->ring[(s->rpos + i) % s->cap];
                                if (preview[i] == '\r' || preview[i] == '\n')
                                    preview[i] = ' ';
                            }
                            preview[dump] = '\0';
                            av_log(h, AV_LOG_WARNING,
                                "HTTP %ld returned body bytes (first %zu): '%s' (Content-Type: %s)\n",
                                s->http_code, dump, preview, s->content_type ? s->content_type : "");
                        } else {
                            av_log(h, AV_LOG_WARNING,
                                "HTTP %ld with no buffered body (Content-Type: %s)\n",
                                s->http_code, s->content_type ? s->content_type : "");
                        }
                        // Don’t let demuxers parse error pages
                        s->rpos = s->wpos = s->fill = 0;
                        switch (s->http_code) {
                        case 400: s->err = AVERROR_HTTP_BAD_REQUEST; break;
                        case 401: s->err = AVERROR_HTTP_UNAUTHORIZED; break;
                        case 403: s->err = AVERROR_HTTP_FORBIDDEN; break;
                        case 404: s->err = AVERROR_HTTP_NOT_FOUND; break;
                        case 429: s->err = AVERROR_HTTP_TOO_MANY_REQUESTS; break;
                        default:
                            if (s->http_code >= 500) s->err = AVERROR_HTTP_SERVER_ERROR;
                            else s->err = AVERROR_HTTP_OTHER_4XX;
                            break;
                        }
                    } else {
                        curl_off_t clen = -1;
                        if (curl_easy_getinfo(s->easy, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &clen) == CURLE_OK && clen >= 0 && s->content_length < 0)
                            s->content_length = (int64_t)clen + s->request_start;

                        char *eff_url = NULL;
                        if (curl_easy_getinfo(s->easy, CURLINFO_EFFECTIVE_URL, &eff_url) == CURLE_OK && eff_url) {
                            av_freep(&s->final_url);
                            s->final_url = av_strdup(eff_url);
                        }
                    }
                } else {
                    s->http_code = 0;
                    s->err = (cc == CURLE_OPERATION_TIMEDOUT) ? AVERROR(ETIMEDOUT) : AVERROR(EIO);
                }
            }
            s->eof = 1;
            continue;
        }

        // Wait for activity if still running but no data produced
        if (s->fill == 0) {
            int numfds;
            curl_multi_wait(s->multi, NULL, 0, 100, &numfds);
        }
    }

    if (out > 0) s->off += out;
    return out;
}

static int mvd_read(URLContext *h, uint8_t *buf, int size)
{
    MVDCurlHTTPContext *s = h->priv_data;
    int reconnect_delay = 0;
    int reconnect_delay_total = 0;
    int conn_attempts = 1;

    while (1) {
        int ret = mvd_read_data(h, buf, size);
        if (ret >= 0 || ret == AVERROR_EXIT)
            return ret;

        if (h->is_streamed && !s->reconnect_streamed)
            return ret;

        bool is_http_error = s->http_code >= 400;
        bool network_error = mvd_is_curl_network_error(s->last_curl_code);
        int64_t target = h->is_streamed ? 0 : s->off;
        bool is_premature = s->content_length > 0 && s->off < s->content_length;
        bool should_retry = false;

        if (network_error && s->reconnect_on_network_error)
            should_retry = true;
        if (is_http_error && mvd_should_retry_http_code(s, s->http_code))
            should_retry = true;
        if (s->reconnect && !h->is_streamed && is_premature)
            should_retry = true;
        if (s->reconnect_at_eof && ret == AVERROR_EOF)
            should_retry = true;

        if (!should_retry)
            return ret;

        if (reconnect_delay > s->reconnect_delay_max ||
            (s->reconnect_max_retries >= 0 && conn_attempts > s->reconnect_max_retries) ||
            reconnect_delay_total > s->reconnect_delay_total_max)
            return ret;

        unsigned int delay = reconnect_delay;
        if (s->respect_retry_after && s->retry_after > 0)
            delay = FFMAX(delay, s->retry_after);

        av_log(h, AV_LOG_WARNING, "Will reconnect at %"PRId64" in %u second(s), error=%s.\n",
               target, delay, av_err2str(ret));

        int sleep_ret = ff_network_sleep_interruptible(delay * 1000000U,
                                                      &h->interrupt_callback);
        if (sleep_ret != AVERROR(ETIMEDOUT))
            return sleep_ret;

        reconnect_delay_total += delay;
        reconnect_delay = 1 + 2 * reconnect_delay;
        conn_attempts++;
        s->retry_after = 0;

        if (mvd_seek(h, target, SEEK_SET) < 0)
            return ret;
    }
}

static int64_t mvd_seek(URLContext *h, int64_t off, int whence)
{
    MVDCurlHTTPContext *s = h->priv_data;

    if (whence == AVSEEK_SIZE) {
        return s->content_length > 0 ? s->content_length : -1;
    }

    if (whence == SEEK_CUR) off += s->off;
    else if (whence == SEEK_END) {
        if (s->content_length <= 0) return AVERROR(EINVAL);
        off = s->content_length + off;
    } else if (whence != SEEK_SET) return AVERROR(EINVAL);

    if (off < 0) return AVERROR(EINVAL);

    s->off = off;
    s->request_start = off;
    return mvd_start(s) < 0 ? AVERROR(EIO) : off;
}

static int mvd_close(URLContext *h)
{
    MVDCurlHTTPContext *s = h->priv_data;

    if (s->multi && s->easy) {
        curl_multi_remove_handle(s->multi, s->easy);
    }
    if (s->multi) {
        curl_multi_cleanup(s->multi);
        s->multi = NULL;
    }
    if (s->hdr_list) {
        curl_slist_free_all(s->hdr_list);
        s->hdr_list = NULL;
    }
    if (s->easy) {
        curl_easy_cleanup(s->easy);
        s->easy = NULL;
    }

    av_freep(&s->ring);
    av_freep(&s->url);
    av_freep(&s->final_url);
    av_freep(&s->http_version);
    av_freep(&s->location_header);
    av_freep(&s->content_encoding);
    av_freep(&s->content_type);
    av_freep(&s->set_cookie_headers);
    av_freep(&s->cookie_jar);
    av_freep(&s->icy_metadata_headers);
    av_freep(&s->icy_metadata_packet);
    av_dict_free(&s->metadata);
    av_opt_free(s);
    return 0;
}

const URLProtocol ff_http_protocol = {
    .name               = "http",
    .url_open2          = mvd_open,
    .url_read           = mvd_read,
    .url_seek           = mvd_seek,
    .url_close          = mvd_close,
    .priv_data_size     = sizeof(MVDCurlHTTPContext),
    .priv_data_class    = &mvd_curl_http_class,
    .flags              = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist  = "http,https,tcp,tls,crypto,httpproxy,data,file"
};

const URLProtocol ff_https_protocol = {
    .name               = "https",
    .url_open2          = mvd_open,
    .url_read           = mvd_read,
    .url_seek           = mvd_seek,
    .url_close          = mvd_close,
    .priv_data_size     = sizeof(MVDCurlHTTPContext),
    .priv_data_class    = &mvd_curl_http_class,
    .flags              = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist  = "http,https,tcp,tls,crypto,httpproxy,data,file"
};

const URLProtocol ff_httpproxy_protocol = {
    .name               = "httpproxy",
    .url_open2          = mvd_open,
    .url_read           = mvd_read,
    .url_seek           = mvd_seek,
    .url_close          = mvd_close,
    .priv_data_size     = sizeof(MVDCurlHTTPContext),
    .priv_data_class    = &mvd_curl_http_class,
    .flags              = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist  = "http,https,tcp,tls,crypto,httpproxy,data,file"
};

int ff_http_averror(int status_code, int default_averror)
{
    switch (status_code) {
        case 400: return AVERROR_HTTP_BAD_REQUEST;
        case 401: return AVERROR_HTTP_UNAUTHORIZED;
        case 403: return AVERROR_HTTP_FORBIDDEN;
        case 404: return AVERROR_HTTP_NOT_FOUND;
        case 429: return AVERROR_HTTP_TOO_MANY_REQUESTS;
        default: break;
    }
    if (status_code >= 400 && status_code <= 499)
        return AVERROR_HTTP_OTHER_4XX;
    else if (status_code >= 500)
        return AVERROR_HTTP_SERVER_ERROR;
    else
        return default_averror;
}

const char* ff_http_get_new_location(URLContext *h)
{
    MVDCurlHTTPContext *s = h->priv_data;
    if (s->location_header)
        return s->location_header;
    if (s->final_url)
        return s->final_url;
    return s->url;
}

void ff_http_init_auth_state(URLContext *dest, const URLContext *src)
{
    // No-op for libcurl
}

int ff_http_do_new_request(URLContext *h, const char *uri)
{
    return ff_http_do_new_request2(h, uri, NULL);
}

int ff_http_do_new_request2(URLContext *h, const char *uri, AVDictionary **options)
{
    MVDCurlHTTPContext *s = h->priv_data;
    int ret;

    if (options) {
        ret = av_opt_set_dict(s, options);
        if (ret < 0) return ret;
    }

    av_freep(&s->url);
    s->url = av_strdup(uri);
    if (!s->url) return AVERROR(ENOMEM);

    // Match original http.c behavior for a new request: start from offset 0
    s->off = 0;
    s->request_start = 0;

    mvd_reset_header_state(s);
    return mvd_start(s);
}

#endif // MVD_USE_LIBCURL

#ifndef MVD_USE_LIBCURL
static const AVOption options[] = {
    { "seekable", "control seekability of connection", OFFSET(seekable), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, D },
    { "chunked_post", "use chunked transfer-encoding for posts", OFFSET(chunked_post), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, E },
    { "http_proxy", "set HTTP proxy to tunnel through", OFFSET(http_proxy), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "headers", "set custom HTTP headers, can override built in default headers", OFFSET(headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "content_type", "set a specific content type for the POST messages", OFFSET(content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "user_agent", "override User-Agent header", OFFSET(user_agent), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
    { "referer", "override referer header", OFFSET(referer), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "multiple_requests", "use persistent connections", OFFSET(multiple_requests), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D | E },
    { "post_data", "set custom HTTP post data", OFFSET(post_data), AV_OPT_TYPE_BINARY, .flags = D | E },
    { "mime_type", "export the MIME type", OFFSET(mime_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "http_version", "export the http response version", OFFSET(http_version), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "cookies", "set cookies to be sent in applicable future requests, use newline delimited Set-Cookie HTTP field value syntax", OFFSET(cookies), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "icy", "request ICY metadata", OFFSET(icy), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "icy_metadata_headers", "return ICY metadata headers", OFFSET(icy_metadata_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "icy_metadata_packet", "return current ICY metadata packet", OFFSET(icy_metadata_packet), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "metadata", "metadata read from the bitstream", OFFSET(metadata), AV_OPT_TYPE_DICT, {0}, 0, 0, AV_OPT_FLAG_EXPORT },
    { "auth_type", "HTTP authentication type", OFFSET(auth_state.auth_type), AV_OPT_TYPE_INT, { .i64 = HTTP_AUTH_NONE }, HTTP_AUTH_NONE, HTTP_AUTH_BASIC, D | E, .unit = "auth_type"},
    { "none", "No auth method set, autodetect", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_NONE }, 0, 0, D | E, .unit = "auth_type"},
    { "basic", "HTTP basic authentication", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_BASIC }, 0, 0, D | E, .unit = "auth_type"},
    { "send_expect_100", "Force sending an Expect: 100-continue header for POST", OFFSET(send_expect_100), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, E },
    { "location", "The actual location of the data received", OFFSET(location), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "offset", "initial byte offset", OFFSET(off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "end_offset", "try to limit the request to bytes preceding this offset", OFFSET(end_off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "method", "Override the HTTP method or set the expected HTTP method from a client", OFFSET(method), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "reconnect", "auto reconnect after disconnect before EOF", OFFSET(reconnect), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_at_eof", "auto reconnect at EOF", OFFSET(reconnect_at_eof), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_network_error", "auto reconnect in case of tcp/tls error during connect", OFFSET(reconnect_on_network_error), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_http_error", "list of http status codes to reconnect on", OFFSET(reconnect_on_http_error), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "reconnect_streamed", "auto reconnect streamed / non seekable streams", OFFSET(reconnect_streamed), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_delay_max", "max reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_max), AV_OPT_TYPE_INT, { .i64 = 120 }, 0, UINT_MAX/1000/1000, D },
    { "reconnect_max_retries", "the max number of times to retry a connection", OFFSET(reconnect_max_retries), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, D },
    { "reconnect_delay_total_max", "max total reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_total_max), AV_OPT_TYPE_INT, { .i64 = 256 }, 0, UINT_MAX/1000/1000, D },
    { "respect_retry_after", "respect the Retry-After header when retrying connections", OFFSET(respect_retry_after), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "listen", "listen on HTTP", OFFSET(listen), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, 2, D | E },
    { "resource", "The resource requested by a client", OFFSET(resource), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, E },
    { "reply_code", "The http status code to return to a client", OFFSET(reply_code), AV_OPT_TYPE_INT, { .i64 = 200}, INT_MIN, 599, E},
    { "short_seek_size", "Threshold to favor readahead over seek.", OFFSET(short_seek_size), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, D },
    { NULL }
};

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth);
static int http_read_header(URLContext *h);
static int http_shutdown(URLContext *h, int flags);

void ff_http_init_auth_state(URLContext *dest, const URLContext *src)
{
    memcpy(&((HTTPContext *)dest->priv_data)->auth_state,
           &((HTTPContext *)src->priv_data)->auth_state,
           sizeof(HTTPAuthState));
    memcpy(&((HTTPContext *)dest->priv_data)->proxy_auth_state,
           &((HTTPContext *)src->priv_data)->proxy_auth_state,
           sizeof(HTTPAuthState));
}

static int http_open_cnx_internal(URLContext *h, AVDictionary **options)
{
    const char *path, *proxy_path, *lower_proto = "tcp", *local_path;
    char *env_http_proxy, *env_no_proxy;
    char *hashmark;
    char hostname[1024], hoststr[1024], proto[10], tmp_host[1024];
    char auth[1024], proxyauth[1024] = "";
    char path1[MAX_URL_SIZE], sanitized_path[MAX_URL_SIZE + 1];
    char buf[1024], urlbuf[MAX_URL_SIZE];
    int port, use_proxy, err = 0;
    HTTPContext *s = h->priv_data;

    av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path1, sizeof(path1), s->location);

    av_strlcpy(tmp_host, hostname, sizeof(tmp_host));
    // In case of an IPv6 address, we need to strip the Zone ID,
    // if any. We do it at the first % sign, as percent encoding
    // can be used in the Zone ID itself.
    if (strchr(tmp_host, ':'))
        tmp_host[strcspn(tmp_host, "%")] = '\0';
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, tmp_host, port, NULL);

    env_http_proxy = getenv_utf8("http_proxy");
    proxy_path = s->http_proxy ? s->http_proxy : env_http_proxy;

    env_no_proxy = getenv_utf8("no_proxy");
    use_proxy  = !ff_http_match_no_proxy(env_no_proxy, hostname) &&
                 proxy_path && av_strstart(proxy_path, "http://", NULL);
    freeenv_utf8(env_no_proxy);

    if (!strcmp(proto, "https")) {
        lower_proto = "tls";
        use_proxy   = 0;
        if (port < 0)
            port = 443;
        /* pass http_proxy to underlying protocol */
        if (s->http_proxy) {
            err = av_dict_set(options, "http_proxy", s->http_proxy, 0);
            if (err < 0)
                goto end;
        }
    }
    if (port < 0)
        port = 80;

    hashmark = strchr(path1, '#');
    if (hashmark)
        *hashmark = '\0';

    if (path1[0] == '\0') {
        path = "/";
    } else if (path1[0] == '?') {
        snprintf(sanitized_path, sizeof(sanitized_path), "/%s", path1);
        path = sanitized_path;
    } else {
        path = path1;
    }
    local_path = path;
    if (use_proxy) {
        /* Reassemble the request URL without auth string - we don't
         * want to leak the auth to the proxy. */
        ff_url_join(urlbuf, sizeof(urlbuf), proto, NULL, hostname, port, "%s",
                    path1);
        path = urlbuf;
        av_url_split(NULL, 0, proxyauth, sizeof(proxyauth),
                     hostname, sizeof(hostname), &port, NULL, 0, proxy_path);
    }

    ff_url_join(buf, sizeof(buf), lower_proto, NULL, hostname, port, NULL);

    if (!s->hd) {
        err = ffurl_open_whitelist(&s->hd, buf, AVIO_FLAG_READ_WRITE,
                                   &h->interrupt_callback, options,
                                   h->protocol_whitelist, h->protocol_blacklist, h);
    }

end:
    freeenv_utf8(env_http_proxy);
    return err < 0 ? err : http_connect(
        h, path, local_path, hoststr, auth, proxyauth);
}

static int http_should_reconnect(HTTPContext *s, int err)
{
    const char *status_group;
    char http_code[4];

    switch (err) {
    case AVERROR_HTTP_BAD_REQUEST:
    case AVERROR_HTTP_UNAUTHORIZED:
    case AVERROR_HTTP_FORBIDDEN:
    case AVERROR_HTTP_NOT_FOUND:
    case AVERROR_HTTP_TOO_MANY_REQUESTS:
    case AVERROR_HTTP_OTHER_4XX:
        status_group = "4xx";
        break;

    case AVERROR_HTTP_SERVER_ERROR:
        status_group = "5xx";
        break;

    default:
        return s->reconnect_on_network_error;
    }

    if (!s->reconnect_on_http_error)
        return 0;

    if (av_match_list(status_group, s->reconnect_on_http_error, ',') > 0)
        return 1;

    snprintf(http_code, sizeof(http_code), "%d", s->http_code);

    return av_match_list(http_code, s->reconnect_on_http_error, ',') > 0;
}

static char *redirect_cache_get(HTTPContext *s)
{
    AVDictionaryEntry *re;
    int64_t expiry;
    char *delim;

    re = av_dict_get(s->redirect_cache, s->location, NULL, AV_DICT_MATCH_CASE);
    if (!re) {
        return NULL;
    }

    delim = strchr(re->value, ';');
    if (!delim) {
        return NULL;
    }

    expiry = strtoll(re->value, NULL, 10);
    if (time(NULL) > expiry) {
        return NULL;
    }

    return delim + 1;
}

static int redirect_cache_set(HTTPContext *s, const char *source, const char *dest, int64_t expiry)
{
    char *value;
    int ret;

    value = av_asprintf("%"PRIi64";%s", expiry, dest);
    if (!value) {
        return AVERROR(ENOMEM);
    }

    ret = av_dict_set(&s->redirect_cache, source, value, AV_DICT_MATCH_CASE | AV_DICT_DONT_STRDUP_VAL);
    if (ret < 0)
        return ret;

    return 0;
}

/* return non zero if error */
static int http_open_cnx(URLContext *h, AVDictionary **options)
{
    HTTPAuthType cur_auth_type, cur_proxy_auth_type;
    HTTPContext *s = h->priv_data;
    int ret, conn_attempts = 1, auth_attempts = 0, redirects = 0;
    int reconnect_delay = 0;
    int reconnect_delay_total = 0;
    uint64_t off;
    char *cached;

redo:

    cached = redirect_cache_get(s);
    if (cached) {
        av_free(s->location);
        s->location = av_strdup(cached);
        if (!s->location) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        goto redo;
    }

    av_dict_copy(options, s->chained_options, 0);

    cur_auth_type       = s->auth_state.auth_type;
    cur_proxy_auth_type = s->auth_state.auth_type;

    off = s->off;
    ret = http_open_cnx_internal(h, options);
    if (ret < 0) {
        if (!http_should_reconnect(s, ret) ||
            reconnect_delay > s->reconnect_delay_max ||
            (s->reconnect_max_retries >= 0 && conn_attempts > s->reconnect_max_retries) ||
            reconnect_delay_total > s->reconnect_delay_total_max)
            goto fail;

        /* Both fields here are in seconds. */
        if (s->respect_retry_after && s->retry_after > 0) {
            reconnect_delay = s->retry_after;
            if (reconnect_delay > s->reconnect_delay_max)
                goto fail;
            s->retry_after = 0;
        }

        av_log(h, AV_LOG_WARNING, "Will reconnect at %"PRIu64" in %d second(s).\n", off, reconnect_delay);
        ret = ff_network_sleep_interruptible(1000U * 1000 * reconnect_delay, &h->interrupt_callback);
        if (ret != AVERROR(ETIMEDOUT))
            goto fail;
        reconnect_delay_total += reconnect_delay;
        reconnect_delay = 1 + 2 * reconnect_delay;
        conn_attempts++;

        /* restore the offset (http_connect resets it) */
        s->off = off;

        ffurl_closep(&s->hd);
        goto redo;
    }

    auth_attempts++;
    if (s->http_code == 401) {
        if ((cur_auth_type == HTTP_AUTH_NONE || s->auth_state.stale) &&
            s->auth_state.auth_type != HTTP_AUTH_NONE && auth_attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else
            goto fail;
    }
    if (s->http_code == 407) {
        if ((cur_proxy_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
            s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && auth_attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else
            goto fail;
    }
    if ((s->http_code == 301 || s->http_code == 302 ||
         s->http_code == 303 || s->http_code == 307 || s->http_code == 308) &&
        s->new_location) {
        /* url moved, get next */
        ffurl_closep(&s->hd);
        if (redirects++ >= MAX_REDIRECTS)
            return AVERROR(EIO);

        if (!s->expires) {
            s->expires = (s->http_code == 301 || s->http_code == 308) ? INT64_MAX : -1;
        }

        if (s->expires > time(NULL) && av_dict_count(s->redirect_cache) < MAX_CACHED_REDIRECTS) {
            redirect_cache_set(s, s->location, s->new_location, s->expires);
        }

        av_free(s->location);
        s->location = s->new_location;
        s->new_location = NULL;

        /* Restart the authentication process with the new target, which
         * might use a different auth mechanism. */
        memset(&s->auth_state, 0, sizeof(s->auth_state));
        auth_attempts         = 0;
        goto redo;
    }
    return 0;

fail:
    if (s->hd)
        ffurl_closep(&s->hd);
    if (ret < 0)
        return ret;
    return ff_http_averror(s->http_code, AVERROR(EIO));
}

int ff_http_do_new_request(URLContext *h, const char *uri) {
    return ff_http_do_new_request2(h, uri, NULL);
}

int ff_http_do_new_request2(URLContext *h, const char *uri, AVDictionary **opts)
{
    HTTPContext *s = h->priv_data;
    AVDictionary *options = NULL;
    int ret;
    char hostname1[1024], hostname2[1024], proto1[10], proto2[10];
    int port1, port2;

    if (!h->prot ||
        !(!strcmp(h->prot->name, "http") ||
          !strcmp(h->prot->name, "https")))
        return AVERROR(EINVAL);

    av_url_split(proto1, sizeof(proto1), NULL, 0,
                 hostname1, sizeof(hostname1), &port1,
                 NULL, 0, s->location);
    av_url_split(proto2, sizeof(proto2), NULL, 0,
                 hostname2, sizeof(hostname2), &port2,
                 NULL, 0, uri);
    if (strcmp(proto1, proto2) != 0) {
        av_log(h, AV_LOG_INFO, "Cannot reuse HTTP connection for different protocol %s vs %s\n",
               proto1, proto2);
        return AVERROR(EINVAL);
    }
    if (port1 != port2 || strncmp(hostname1, hostname2, sizeof(hostname2)) != 0) {
        av_log(h, AV_LOG_INFO, "Cannot reuse HTTP connection for different host: %s:%d != %s:%d\n",
            hostname1, port1,
            hostname2, port2
        );
        return AVERROR(EINVAL);
    }

    if (!s->end_chunked_post) {
        ret = http_shutdown(h, h->flags);
        if (ret < 0)
            return ret;
    }

    if (s->willclose)
        return AVERROR_EOF;

    s->end_chunked_post = 0;
    s->chunkend      = 0;
    s->off           = 0;
    s->icy_data_read = 0;

    av_free(s->location);
    s->location = av_strdup(uri);
    if (!s->location)
        return AVERROR(ENOMEM);

    av_free(s->uri);
    s->uri = av_strdup(uri);
    if (!s->uri)
        return AVERROR(ENOMEM);

    if ((ret = av_opt_set_dict(s, opts)) < 0)
        return ret;

    av_log(s, AV_LOG_INFO, "Opening \'%s\' for %s\n", uri, h->flags & AVIO_FLAG_WRITE ? "writing" : "reading");
    ret = http_open_cnx(h, &options);
    av_dict_free(&options);
    return ret;
}

int ff_http_averror(int status_code, int default_averror)
{
    switch (status_code) {
        case 400: return AVERROR_HTTP_BAD_REQUEST;
        case 401: return AVERROR_HTTP_UNAUTHORIZED;
        case 403: return AVERROR_HTTP_FORBIDDEN;
        case 404: return AVERROR_HTTP_NOT_FOUND;
        case 429: return AVERROR_HTTP_TOO_MANY_REQUESTS;
        default: break;
    }
    if (status_code >= 400 && status_code <= 499)
        return AVERROR_HTTP_OTHER_4XX;
    else if (status_code >= 500)
        return AVERROR_HTTP_SERVER_ERROR;
    else
        return default_averror;
}

const char* ff_http_get_new_location(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return s->new_location;
}

static int http_write_reply(URLContext* h, int status_code)
{
    int ret, body = 0, reply_code, message_len;
    const char *reply_text, *content_type;
    HTTPContext *s = h->priv_data;
    char message[BUFFER_SIZE];
    content_type = "text/plain";

    if (status_code < 0)
        body = 1;
    switch (status_code) {
    case AVERROR_HTTP_BAD_REQUEST:
    case 400:
        reply_code = 400;
        reply_text = "Bad Request";
        break;
    case AVERROR_HTTP_FORBIDDEN:
    case 403:
        reply_code = 403;
        reply_text = "Forbidden";
        break;
    case AVERROR_HTTP_NOT_FOUND:
    case 404:
        reply_code = 404;
        reply_text = "Not Found";
        break;
    case AVERROR_HTTP_TOO_MANY_REQUESTS:
    case 429:
        reply_code = 429;
        reply_text = "Too Many Requests";
        break;
    case 200:
        reply_code = 200;
        reply_text = "OK";
        content_type = s->content_type ? s->content_type : "application/octet-stream";
        break;
    case AVERROR_HTTP_SERVER_ERROR:
    case 500:
        reply_code = 500;
        reply_text = "Internal server error";
        break;
    default:
        return AVERROR(EINVAL);
    }
    if (body) {
        s->chunked_post = 0;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %"SIZE_SPECIFIER"\r\n"
                 "%s"
                 "\r\n"
                 "%03d %s\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 strlen(reply_text) + 6, // 3 digit status code + space + \r\n
                 s->headers ? s->headers : "",
                 reply_code,
                 reply_text);
    } else {
        s->chunked_post = 1;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Transfer-Encoding: chunked\r\n"
                 "%s"
                 "\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 s->headers ? s->headers : "");
    }
    av_log(h, AV_LOG_TRACE, "HTTP reply header: \n%s----\n", message);
    if ((ret = ffurl_write(s->hd, message, message_len)) < 0)
        return ret;
    return 0;
}

static void handle_http_errors(URLContext *h, int error)
{
    av_assert0(error < 0);
    http_write_reply(h, error);
}

static int http_handshake(URLContext *c)
{
    int ret, err;
    HTTPContext *ch = c->priv_data;
    URLContext *cl = ch->hd;
    switch (ch->handshake_step) {
    case LOWER_PROTO:
        av_log(c, AV_LOG_TRACE, "Lower protocol\n");
        if ((ret = ffurl_handshake(cl)) > 0)
            return 2 + ret;
        if (ret < 0)
            return ret;
        ch->handshake_step = READ_HEADERS;
        ch->is_connected_server = 1;
        return 2;
    case READ_HEADERS:
        av_log(c, AV_LOG_TRACE, "Read headers\n");
        if ((err = http_read_header(c)) < 0) {
            handle_http_errors(c, err);
            return err;
        }
        ch->handshake_step = WRITE_REPLY_HEADERS;
        return 1;
    case WRITE_REPLY_HEADERS:
        av_log(c, AV_LOG_TRACE, "Reply code: %d\n", ch->reply_code);
        if ((err = http_write_reply(c, ch->reply_code)) < 0)
            return err;
        ch->handshake_step = FINISH;
        return 1;
    case FINISH:
        return 0;
    }
    // this should never be reached.
    return AVERROR(EINVAL);
}

static int http_listen(URLContext *h, const char *uri, int flags,
                       AVDictionary **options) {
    HTTPContext *s = h->priv_data;
    int ret;
    char hostname[1024], proto[10];
    char lower_url[100];
    const char *lower_proto = "tcp";
    int port;
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname), &port,
                 NULL, 0, uri);
    if (!strcmp(proto, "https"))
        lower_proto = "tls";
    ff_url_join(lower_url, sizeof(lower_url), lower_proto, NULL, hostname, port,
                NULL);
    if ((ret = av_dict_set_int(options, "listen", s->listen, 0)) < 0)
        goto fail;
    if ((ret = ffurl_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                                    &h->interrupt_callback, options,
                                    h->protocol_whitelist, h->protocol_blacklist, h
                                   )) < 0)
        goto fail;
    s->handshake_step = LOWER_PROTO;
    if (s->listen == HTTP_SINGLE) { /* single client */
        s->reply_code = 200;
        while ((ret = http_handshake(h)) > 0);
    }
fail:
    av_dict_free(&s->chained_options);
    av_dict_free(&s->cookie_dict);
    return ret;
}

static int http_open(URLContext *h, const char *uri, int flags,
                     AVDictionary **options)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    s->filesize = UINT64_MAX;

    s->location = av_strdup(uri);
    if (!s->location)
        return AVERROR(ENOMEM);

    s->uri = av_strdup(uri);
    if (!s->uri)
        return AVERROR(ENOMEM);

    if (options)
        av_dict_copy(&s->chained_options, *options, 0);

    if (s->headers) {
        int len = strlen(s->headers);
        if (len < 2 || strcmp("\r\n", s->headers + len - 2)) {
            av_log(h, AV_LOG_WARNING,
                   "No trailing CRLF found in HTTP header. Adding it.\n");
            ret = av_reallocp(&s->headers, len + 3);
            if (ret < 0)
                goto bail_out;
            s->headers[len]     = '\r';
            s->headers[len + 1] = '\n';
            s->headers[len + 2] = '\0';
        }
    }

    if (s->listen) {
        return http_listen(h, uri, flags, options);
    }
    ret = http_open_cnx(h, options);
bail_out:
    if (ret < 0) {
        av_dict_free(&s->chained_options);
        av_dict_free(&s->cookie_dict);
        av_dict_free(&s->redirect_cache);
        av_freep(&s->new_location);
        av_freep(&s->uri);
    }
    return ret;
}

static int http_accept(URLContext *s, URLContext **c)
{
    int ret;
    HTTPContext *sc = s->priv_data;
    HTTPContext *cc;
    URLContext *sl = sc->hd;
    URLContext *cl = NULL;

    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &sl->interrupt_callback)) < 0)
        goto fail;
    cc = (*c)->priv_data;
    if ((ret = ffurl_accept(sl, &cl)) < 0)
        goto fail;
    cc->hd = cl;
    cc->is_multi_client = 1;
    return 0;
fail:
    if (c) {
        ffurl_closep(c);
    }
    return ret;
}

static int http_getc(HTTPContext *s)
{
    int len;
    if (s->buf_ptr >= s->buf_end) {
        len = ffurl_read(s->hd, s->buffer, BUFFER_SIZE);
        if (len < 0) {
            return len;
        } else if (len == 0) {
            return AVERROR_EOF;
        } else {
            s->buf_ptr = s->buffer;
            s->buf_end = s->buffer + len;
        }
    }
    return *s->buf_ptr++;
}

static int http_get_line(HTTPContext *s, char *line, int line_size)
{
    int ch;
    char *q;

    q = line;
    for (;;) {
        ch = http_getc(s);
        if (ch < 0)
            return ch;
        if (ch == '\n') {
            /* process line */
            if (q > line && q[-1] == '\r')
                q--;
            *q = '\0';

            return 0;
        } else {
            if ((q - line) < line_size - 1)
                *q++ = ch;
        }
    }
}

static int check_http_code(URLContext *h, int http_code, const char *end)
{
    HTTPContext *s = h->priv_data;
    /* error codes are 4xx and 5xx, but regard 401 as a success, so we
     * don't abort until all headers have been parsed. */
    if (http_code >= 400 && http_code < 600 &&
        (http_code != 401 || s->auth_state.auth_type != HTTP_AUTH_NONE) &&
        (http_code != 407 || s->proxy_auth_state.auth_type != HTTP_AUTH_NONE)) {
        end += strspn(end, SPACE_CHARS);
        av_log(h, AV_LOG_WARNING, "HTTP error %d %s\n", http_code, end);
        return ff_http_averror(http_code, AVERROR(EIO));
    }
    return 0;
}

static int parse_location(HTTPContext *s, const char *p)
{
    char redirected_location[MAX_URL_SIZE];
    ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                         s->location, p);
    av_freep(&s->new_location);
    s->new_location = av_strdup(redirected_location);
    if (!s->new_location)
        return AVERROR(ENOMEM);
    return 0;
}

/* "bytes $from-$to/$document_size" */
static void parse_content_range(URLContext *h, const char *p)
{
    HTTPContext *s = h->priv_data;
    const char *slash;

    if (!strncmp(p, "bytes ", 6)) {
        p     += 6;
        s->off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '/')) && strlen(slash) > 0)
            s->filesize_from_content_range = strtoull(slash + 1, NULL, 10);
    }
    if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
        h->is_streamed = 0; /* we _can_ in fact seek */
}

static int parse_content_encoding(URLContext *h, const char *p)
{
    if (!av_strncasecmp(p, "gzip", 4) ||
        !av_strncasecmp(p, "deflate", 7)) {
#if CONFIG_ZLIB
        HTTPContext *s = h->priv_data;

        s->compressed = 1;
        inflateEnd(&s->inflate_stream);
        if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
            av_log(h, AV_LOG_WARNING, "Error during zlib initialisation: %s\n",
                   s->inflate_stream.msg);
            return AVERROR(ENOSYS);
        }
        if (zlibCompileFlags() & (1 << 17)) {
            av_log(h, AV_LOG_WARNING,
                   "Your zlib was compiled without gzip support.\n");
            return AVERROR(ENOSYS);
        }
#else
        av_log(h, AV_LOG_WARNING,
               "Compressed (%s) content, need zlib with gzip support\n", p);
        return AVERROR(ENOSYS);
#endif /* CONFIG_ZLIB */
    } else if (!av_strncasecmp(p, "identity", 8)) {
        // The normal, no-encoding case (although servers shouldn't include
        // the header at all if this is the case).
    } else {
        av_log(h, AV_LOG_WARNING, "Unknown content coding: %s\n", p);
    }
    return 0;
}

// Concat all Icy- header lines
static int parse_icy(HTTPContext *s, const char *tag, const char *p)
{
    int len = 4 + strlen(p) + strlen(tag);
    int is_first = !s->icy_metadata_headers;
    int ret;

    av_dict_set(&s->metadata, tag, p, 0);

    if (s->icy_metadata_headers)
        len += strlen(s->icy_metadata_headers);

    if ((ret = av_reallocp(&s->icy_metadata_headers, len)) < 0)
        return ret;

    if (is_first)
        *s->icy_metadata_headers = '\0';

    av_strlcatf(s->icy_metadata_headers, len, "%s: %s\n", tag, p);

    return 0;
}

static int parse_set_cookie(const char *set_cookie, AVDictionary **dict)
{
    char *param, *next_param, *cstr, *back;
    char *saveptr = NULL;

    if (!set_cookie[0])
        return 0;

    if (!(cstr = av_strdup(set_cookie)))
        return AVERROR(EINVAL);

    // strip any trailing whitespace
    back = &cstr[strlen(cstr)-1];
    while (strchr(WHITESPACES, *back)) {
        *back='\0';
        if (back == cstr)
            break;
        back--;
    }

    next_param = cstr;
    while ((param = av_strtok(next_param, ";", &saveptr))) {
        char *name, *value;
        next_param = NULL;
        param += strspn(param, WHITESPACES);
        if ((name = av_strtok(param, "=", &value))) {
            if (av_dict_set(dict, name, value, 0) < 0) {
                av_free(cstr);
                return -1;
            }
        }
    }

    av_free(cstr);
    return 0;
}

static int parse_cookie(HTTPContext *s, const char *p, AVDictionary **cookies)
{
    AVDictionary *new_params = NULL;
    const AVDictionaryEntry *e, *cookie_entry;
    char *eql, *name;

    // ensure the cookie is parsable
    if (parse_set_cookie(p, &new_params))
        return -1;

    // if there is no cookie value there is nothing to parse
    cookie_entry = av_dict_iterate(new_params, NULL);
    if (!cookie_entry || !cookie_entry->value) {
        av_dict_free(&new_params);
        return -1;
    }

    // ensure the cookie is not expired or older than an existing value
    if ((e = av_dict_get(new_params, "expires", NULL, 0)) && e->value) {
        struct tm new_tm = {0};
        if (!parse_http_date(e->value, &new_tm)) {
            AVDictionaryEntry *e2;

            // if the cookie has already expired ignore it
            if (av_timegm(&new_tm) < av_gettime() / 1000000) {
                av_dict_free(&new_params);
                return 0;
            }

            // only replace an older cookie with the same name
            e2 = av_dict_get(*cookies, cookie_entry->key, NULL, 0);
            if (e2 && e2->value) {
                AVDictionary *old_params = NULL;
                if (!parse_set_cookie(p, &old_params)) {
                    e2 = av_dict_get(old_params, "expires", NULL, 0);
                    if (e2 && e2->value) {
                        struct tm old_tm = {0};
                        if (!parse_http_date(e->value, &old_tm)) {
                            if (av_timegm(&new_tm) < av_timegm(&old_tm)) {
                                av_dict_free(&new_params);
                                av_dict_free(&old_params);
                                return -1;
                            }
                        }
                    }
                }
                av_dict_free(&old_params);
            }
        }
    }
    av_dict_free(&new_params);

    // duplicate the cookie name (dict will dupe the value)
    if (!(eql = strchr(p, '='))) return AVERROR(EINVAL);
    if (!(name = av_strndup(p, eql - p))) return AVERROR(ENOMEM);

    // add the cookie to the dictionary
    av_dict_set(cookies, name, eql, AV_DICT_DONT_STRDUP_KEY);

    return 0;
}

static int cookie_string(AVDictionary *dict, char **cookies)
{
    const AVDictionaryEntry *e = NULL;
    int len = 1;

    // determine how much memory is needed for the cookies string
    while ((e = av_dict_iterate(dict, e)))
        len += strlen(e->key) + strlen(e->value) + 1;

    // reallocate the cookies
    e = NULL;
    if (*cookies) av_free(*cookies);
    *cookies = av_malloc(len);
    if (!*cookies) return AVERROR(ENOMEM);
    *cookies[0] = '\0';

    // write out the cookies
    while ((e = av_dict_iterate(dict, e)))
        av_strlcatf(*cookies, len, "%s%s\n", e->key, e->value);

    return 0;
}

static void parse_expires(HTTPContext *s, const char *p)
{
    struct tm tm;

    if (!parse_http_date(p, &tm)) {
        s->expires = av_timegm(&tm);
    }
}

static void parse_cache_control(HTTPContext *s, const char *p)
{
    char *age;
    int offset;

    /* give 'Expires' higher priority over 'Cache-Control' */
    if (s->expires) {
        return;
    }

    if (av_stristr(p, "no-cache") || av_stristr(p, "no-store")) {
        s->expires = -1;
        return;
    }

    age = av_stristr(p, "s-maxage=");
    offset = 9;
    if (!age) {
        age = av_stristr(p, "max-age=");
        offset = 8;
    }

    if (age) {
        s->expires = time(NULL) + atoi(p + offset);
    }
}

static int process_line(URLContext *h, char *line, int line_count, int *parsed_http_code)
{
    HTTPContext *s = h->priv_data;
    const char *auto_method =  h->flags & AVIO_FLAG_READ ? "POST" : "GET";
    char *tag, *p, *end, *method, *resource, *version;
    int ret;

    /* end of header */
    if (line[0] == '\0') {
        s->end_header = 1;
        return 0;
    }

    p = line;
    if (line_count == 0) {
        if (s->is_connected_server) {
            // HTTP method
            method = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Received method: %s\n", method);
            if (s->method) {
                if (av_strcasecmp(s->method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                av_log(h, AV_LOG_TRACE, "Autodetected %s HTTP method\n", auto_method);
                if (av_strcasecmp(auto_method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
                if (!(s->method = av_strdup(method)))
                    return AVERROR(ENOMEM);
            }

            // HTTP resource
            while (av_isspace(*p))
                p++;
            resource = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Requested resource: %s\n", resource);
            if (!(s->resource = av_strdup(resource)))
                return AVERROR(ENOMEM);

            // HTTP version
            while (av_isspace(*p))
                p++;
            version = p;
            while (*p && !av_isspace(*p))
                p++;
            *p = '\0';
            if (av_strncasecmp(version, "HTTP/", 5)) {
                av_log(h, AV_LOG_ERROR, "Malformed HTTP version string.\n");
                return ff_http_averror(400, AVERROR(EIO));
            }
            av_log(h, AV_LOG_TRACE, "HTTP version string: %s\n", version);
        } else {
            if (av_strncasecmp(p, "HTTP/1.0", 8) == 0)
                s->willclose = 1;
            while (*p != '/' && *p != '\0')
                p++;
            while (*p == '/')
                p++;
            av_freep(&s->http_version);
            s->http_version = av_strndup(p, 3);
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);

            av_log(h, AV_LOG_TRACE, "http_code=%d\n", s->http_code);

            *parsed_http_code = 1;

            if ((ret = check_http_code(h, s->http_code, end)) < 0)
                return ret;
        }
    } else {
        while (*p != '\0' && *p != ':')
            p++;
        if (*p != ':')
            return 1;

        *p  = '\0';
        tag = line;
        p++;
        while (av_isspace(*p))
            p++;
        if (!av_strcasecmp(tag, "Location")) {
            if ((ret = parse_location(s, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!av_strcasecmp(tag, "Content-Range")) {
            parse_content_range(h, p);
        } else if (!av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            h->is_streamed = 0;
        } else if (!av_strcasecmp(tag, "Transfer-Encoding") &&
                   !av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
        } else if (!av_strcasecmp(tag, "WWW-Authenticate")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Authentication-Info")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Proxy-Authenticate")) {
            ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Connection")) {
            if (!strcmp(p, "close"))
                s->willclose = 1;
        } else if (!av_strcasecmp(tag, "Server")) {
            if (!av_strcasecmp(p, "AkamaiGHost")) {
                s->is_akamai = 1;
            } else if (!av_strncasecmp(p, "MediaGateway", 12)) {
                s->is_mediagateway = 1;
            }
        } else if (!av_strcasecmp(tag, "Content-Type")) {
            av_free(s->mime_type);
            s->mime_type = av_get_token((const char **)&p, ";");
        } else if (!av_strcasecmp(tag, "Set-Cookie")) {
            if (parse_cookie(s, p, &s->cookie_dict))
                av_log(h, AV_LOG_WARNING, "Unable to parse '%s'\n", p);
        } else if (!av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parse_icy(s, tag, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Content-Encoding")) {
            if ((ret = parse_content_encoding(h, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Expires")) {
            parse_expires(s, p);
        } else if (!av_strcasecmp(tag, "Cache-Control")) {
            parse_cache_control(s, p);
        } else if (!av_strcasecmp(tag, "Retry-After")) {
            /* The header can be either an integer that represents seconds, or a date. */
            struct tm tm;
            int date_ret = parse_http_date(p, &tm);
            if (!date_ret) {
                time_t retry   = av_timegm(&tm);
                int64_t now    = av_gettime() / 1000000;
                int64_t diff   = ((int64_t) retry) - now;
                s->retry_after = (unsigned int) FFMAX(0, diff);
            } else {
                s->retry_after = strtoul(p, NULL, 10);
            }
        }
    }
    return 1;
}

/**
 * Create a string containing cookie values for use as a HTTP cookie header
 * field value for a particular path and domain from the cookie values stored in
 * the HTTP protocol context. The cookie string is stored in *cookies, and may
 * be NULL if there are no valid cookies.
 *
 * @return a negative value if an error condition occurred, 0 otherwise
 */
static int get_cookies(HTTPContext *s, char **cookies, const char *path,
                       const char *domain)
{
    // cookie strings will look like Set-Cookie header field values.  Multiple
    // Set-Cookie fields will result in multiple values delimited by a newline
    int ret = 0;
    char *cookie, *set_cookies, *next;
    char *saveptr = NULL;

    // destroy any cookies in the dictionary.
    av_dict_free(&s->cookie_dict);

    if (!s->cookies)
        return 0;

    next = set_cookies = av_strdup(s->cookies);
    if (!next)
        return AVERROR(ENOMEM);

    *cookies = NULL;
    while ((cookie = av_strtok(next, "\n", &saveptr)) && !ret) {
        AVDictionary *cookie_params = NULL;
        const AVDictionaryEntry *cookie_entry, *e;

        next = NULL;
        // store the cookie in a dict in case it is updated in the response
        if (parse_cookie(s, cookie, &s->cookie_dict))
            av_log(s, AV_LOG_WARNING, "Unable to parse '%s'\n", cookie);

        // continue on to the next cookie if this one cannot be parsed
        if (parse_set_cookie(cookie, &cookie_params))
            goto skip_cookie;

        // if the cookie has no value, skip it
        cookie_entry = av_dict_iterate(cookie_params, NULL);
        if (!cookie_entry || !cookie_entry->value)
            goto skip_cookie;

        // if the cookie has expired, don't add it
        if ((e = av_dict_get(cookie_params, "expires", NULL, 0)) && e->value) {
            struct tm tm_buf = {0};
            if (!parse_http_date(e->value, &tm_buf)) {
                if (av_timegm(&tm_buf) < av_gettime() / 1000000)
                    goto skip_cookie;
            }
        }

        // if no domain in the cookie assume it applied to this request
        if ((e = av_dict_get(cookie_params, "domain", NULL, 0)) && e->value) {
            // find the offset comparison is on the min domain (b.com, not a.b.com)
            int domain_offset = strlen(domain) - strlen(e->value);
            if (domain_offset < 0)
                goto skip_cookie;

            // match the cookie domain
            if (av_strcasecmp(&domain[domain_offset], e->value))
                goto skip_cookie;
        }

        // if a cookie path is provided, ensure the request path is within that path
        e = av_dict_get(cookie_params, "path", NULL, 0);
        if (e && av_strncasecmp(path, e->value, strlen(e->value)))
            goto skip_cookie;

        // cookie parameters match, so copy the value
        if (!*cookies) {
            *cookies = av_asprintf("%s=%s", cookie_entry->key, cookie_entry->value);
        } else {
            char *tmp = *cookies;
            *cookies = av_asprintf("%s; %s=%s", tmp, cookie_entry->key, cookie_entry->value);
            av_free(tmp);
        }
        if (!*cookies)
            ret = AVERROR(ENOMEM);

    skip_cookie:
        av_dict_free(&cookie_params);
    }

    av_free(set_cookies);

    return ret;
}

static inline int has_header(const char *str, const char *header)
{
    /* header + 2 to skip over CRLF prefix. (make sure you have one!) */
    if (!str)
        return 0;
    return av_stristart(str, header + 2, NULL) || av_stristr(str, header);
}

static int http_read_header(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    char line[MAX_URL_SIZE];
    int err = 0, http_err = 0;

    av_freep(&s->new_location);
    s->expires = 0;
    s->chunksize = UINT64_MAX;
    s->filesize_from_content_range = UINT64_MAX;

    for (;;) {
        int parsed_http_code = 0;

        if ((err = http_get_line(s, line, sizeof(line))) < 0)
            return err;

        av_log(h, AV_LOG_TRACE, "header='%s'\n", line);

        err = process_line(h, line, s->line_count, &parsed_http_code);
        if (err < 0) {
            if (parsed_http_code) {
                http_err = err;
            } else {
                /* Prefer to return HTTP code error if we've already seen one. */
                if (http_err)
                    return http_err;
                else
                    return err;
            }
        }
        if (err == 0)
            break;
        s->line_count++;
    }
    if (http_err)
        return http_err;

    // filesize from Content-Range can always be used, even if using chunked Transfer-Encoding
    if (s->filesize_from_content_range != UINT64_MAX)
        s->filesize = s->filesize_from_content_range;

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        h->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookie_string(s->cookie_dict, &s->cookies);
    av_dict_free(&s->cookie_dict);

    return err;
}

/**
 * Escape unsafe characters in path in order to pass them safely to the HTTP
 * request. Insipred by the algorithm in GNU wget:
 * - escape "%" characters not followed by two hex digits
 * - escape all "unsafe" characters except which are also "reserved"
 * - pass through everything else
 */
static void bprint_escaped_path(AVBPrint *bp, const char *path)
{
#define NEEDS_ESCAPE(ch) \
    ((ch) <= ' ' || (ch) >= '\x7f' || \
     (ch) == '"' || (ch) == '%' || (ch) == '<' || (ch) == '>' || (ch) == '\\' || \
     (ch) == '^' || (ch) == '`' || (ch) == '{' || (ch) == '}' || (ch) == '|')
    while (*path) {
        char buf[1024];
        char *q = buf;
        while (*path && q - buf < sizeof(buf) - 4) {
            if (path[0] == '%' && av_isxdigit(path[1]) && av_isxdigit(path[2])) {
                *q++ = *path++;
                *q++ = *path++;
                *q++ = *path++;
            } else if (NEEDS_ESCAPE(*path)) {
                q += snprintf(q, 4, "%%%02X", (uint8_t)*path++);
            } else {
                *q++ = *path++;
            }
        }
        av_bprint_append_data(bp, buf, q - buf);
    }
}

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth)
{
    HTTPContext *s = h->priv_data;
    int post, err;
    AVBPrint request;
    char *authstr = NULL, *proxyauthstr = NULL;
    uint64_t off = s->off;
    const char *method;
    int send_expect_100 = 0;

    av_bprint_init_for_buffer(&request, s->buffer, sizeof(s->buffer));

    /* send http header */
    post = h->flags & AVIO_FLAG_WRITE;

    if (s->post_data) {
        /* force POST method and disable chunked encoding when
         * custom HTTP post data is set */
        post            = 1;
        s->chunked_post = 0;
    }

    if (s->method)
        method = s->method;
    else
        method = post ? "POST" : "GET";

    authstr      = ff_http_auth_create_response(&s->auth_state, auth,
                                                local_path, method);
    proxyauthstr = ff_http_auth_create_response(&s->proxy_auth_state, proxyauth,
                                                local_path, method);

     if (post && !s->post_data) {
        if (s->send_expect_100 != -1) {
            send_expect_100 = s->send_expect_100;
        } else {
            send_expect_100 = 0;
            /* The user has supplied authentication but we don't know the auth type,
             * send Expect: 100-continue to get the 401 response including the
             * WWW-Authenticate header, or an 100 continue if no auth actually
             * is needed. */
            if (auth && *auth &&
                s->auth_state.auth_type == HTTP_AUTH_NONE &&
                s->http_code != 401)
                send_expect_100 = 1;
        }
    }

    av_bprintf(&request, "%s ", method);
    bprint_escaped_path(&request, path);
    av_bprintf(&request, " HTTP/1.1\r\n");

    if (post && s->chunked_post)
        av_bprintf(&request, "Transfer-Encoding: chunked\r\n");
    /* set default headers if needed */
    if (!has_header(s->headers, "\r\nUser-Agent: "))
        av_bprintf(&request, "User-Agent: %s\r\n", s->user_agent);
    if (s->referer) {
        /* set default headers if needed */
        if (!has_header(s->headers, "\r\nReferer: "))
            av_bprintf(&request, "Referer: %s\r\n", s->referer);
    }
    if (!has_header(s->headers, "\r\nAccept: "))
        av_bprintf(&request, "Accept: */*\r\n");
    // Note: we send the Range header on purpose, even when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!has_header(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable != 0)) {
        av_bprintf(&request, "Range: bytes=%"PRIu64"-", s->off);
        if (s->end_off)
            av_bprintf(&request, "%"PRId64, s->end_off - 1);
        av_bprintf(&request, "\r\n");
    }
    if (send_expect_100 && !has_header(s->headers, "\r\nExpect: "))
        av_bprintf(&request, "Expect: 100-continue\r\n");

    if (!has_header(s->headers, "\r\nConnection: "))
        av_bprintf(&request, "Connection: %s\r\n", s->multiple_requests ? "keep-alive" : "close");

    if (!has_header(s->headers, "\r\nHost: "))
        av_bprintf(&request, "Host: %s\r\n", hoststr);
    if (!has_header(s->headers, "\r\nContent-Length: ") && s->post_data)
        av_bprintf(&request, "Content-Length: %d\r\n", s->post_datalen);

    if (!has_header(s->headers, "\r\nContent-Type: ") && s->content_type)
        av_bprintf(&request, "Content-Type: %s\r\n", s->content_type);
    if (!has_header(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!get_cookies(s, &cookies, path, hoststr) && cookies) {
            av_bprintf(&request, "Cookie: %s\r\n", cookies);
            av_free(cookies);
        }
    }
    if (!has_header(s->headers, "\r\nIcy-MetaData: ") && s->icy)
        av_bprintf(&request, "Icy-MetaData: 1\r\n");

    /* now add in custom headers */
    if (s->headers)
        av_bprintf(&request, "%s", s->headers);

    if (authstr)
        av_bprintf(&request, "%s", authstr);
    if (proxyauthstr)
        av_bprintf(&request, "Proxy-%s", proxyauthstr);
    av_bprintf(&request, "\r\n");

    av_log(h, AV_LOG_DEBUG, "request: %s\n", request.str);

    if (!av_bprint_is_complete(&request)) {
        av_log(h, AV_LOG_ERROR, "overlong headers\n");
        err = AVERROR(EINVAL);
        goto done;
    }

    if ((err = ffurl_write(s->hd, request.str, request.len)) < 0)
        goto done;

    if (s->post_data)
        if ((err = ffurl_write(s->hd, s->post_data, s->post_datalen)) < 0)
            goto done;

    /* init input buffer */
    s->buf_ptr          = s->buffer;
    s->buf_end          = s->buffer;
    s->line_count       = 0;
    s->off              = 0;
    s->icy_data_read    = 0;
    s->filesize         = UINT64_MAX;
    s->willclose        = 0;
    s->end_chunked_post = 0;
    s->end_header       = 0;
#if CONFIG_ZLIB
    s->compressed       = 0;
#endif
    if (post && !s->post_data && !send_expect_100) {
        /* Pretend that it did work. We didn't read any header yet, since
         * we've still to send the POST data, but the code calling this
         * function will check http_code after we return. */
        s->http_code = 200;
        err = 0;
        goto done;
    }

    /* wait for header */
    err = http_read_header(h);
    if (err < 0)
        goto done;

    if (s->new_location)
        s->off = off;

    err = (off == s->off) ? 0 : -1;
done:
    av_freep(&authstr);
    av_freep(&proxyauthstr);
    return err;
}

static int http_buf_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int len;

    if (s->chunksize != UINT64_MAX) {
        if (s->chunkend) {
            return AVERROR_EOF;
        }
        if (!s->chunksize) {
            char line[32];
            int err;

            do {
                if ((err = http_get_line(s, line, sizeof(line))) < 0)
                    return err;
            } while (!*line);    /* skip CR LF from last chunk */

            s->chunksize = strtoull(line, NULL, 16);

            av_log(h, AV_LOG_TRACE,
                   "Chunked encoding data size: %"PRIu64"\n",
                    s->chunksize);

            if (!s->chunksize && s->multiple_requests) {
                http_get_line(s, line, sizeof(line)); // read empty chunk
                s->chunkend = 1;
                return 0;
            }
            else if (!s->chunksize) {
                av_log(h, AV_LOG_DEBUG, "Last chunk received, closing conn\n");
                ffurl_closep(&s->hd);
                return 0;
            }
            else if (s->chunksize == UINT64_MAX) {
                av_log(h, AV_LOG_ERROR, "Invalid chunk size %"PRIu64"\n",
                       s->chunksize);
                return AVERROR(EINVAL);
            }
        }
        size = FFMIN(size, s->chunksize);
    }

    /* read bytes from input buffer first */
    len = s->buf_end - s->buf_ptr;
    if (len > 0) {
        if (len > size)
            len = size;
        memcpy(buf, s->buf_ptr, len);
        s->buf_ptr += len;
    } else {
        uint64_t target_end = s->end_off ? s->end_off : s->filesize;
        if ((!s->willclose || s->chunksize == UINT64_MAX) && s->off >= target_end)
            return AVERROR_EOF;
        len = ffurl_read(s->hd, buf, size);
        if ((!len || len == AVERROR_EOF) &&
            (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
            av_log(h, AV_LOG_ERROR,
                   "Stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                   s->off, target_end
                  );
            return AVERROR(EIO);
        }
    }
    if (len > 0) {
        s->off += len;
        if (s->chunksize > 0 && s->chunksize != UINT64_MAX) {
            av_assert0(s->chunksize >= len);
            s->chunksize -= len;
        }
    }
    return len;
}

#if CONFIG_ZLIB
#define DECOMPRESS_BUF_SIZE (256 * 1024)
static int http_buf_read_compressed(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer)
            return AVERROR(ENOMEM);
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = http_buf_read(h, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        av_log(h, AV_LOG_WARNING, "inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}
#endif /* CONFIG_ZLIB */

static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect);

static int http_read_stream(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int err, read_ret;
    int64_t seek_ret;
    int reconnect_delay = 0;
    int reconnect_delay_total = 0;
    int conn_attempts = 1;

    if (!s->hd)
        return AVERROR_EOF;

    if (s->end_chunked_post && !s->end_header) {
        err = http_read_header(h);
        if (err < 0)
            return err;
    }

#if CONFIG_ZLIB
    if (s->compressed)
        return http_buf_read_compressed(h, buf, size);
#endif /* CONFIG_ZLIB */
    read_ret = http_buf_read(h, buf, size);
    while (read_ret < 0) {
        uint64_t target = h->is_streamed ? 0 : s->off;
        bool is_premature = s->filesize > 0 && s->off < s->filesize;

        if (read_ret == AVERROR_EXIT)
            break;

        if (h->is_streamed && !s->reconnect_streamed)
            break;

        if (!(s->reconnect && is_premature) &&
            !(s->reconnect_at_eof && read_ret == AVERROR_EOF)) {
            if (is_premature)
                return AVERROR(EIO);
            else
                break;
        }

        if (reconnect_delay > s->reconnect_delay_max || (s->reconnect_max_retries >= 0 && conn_attempts > s->reconnect_max_retries) ||
            reconnect_delay_total > s->reconnect_delay_total_max)
            return AVERROR(EIO);

        av_log(h, AV_LOG_WARNING, "Will reconnect at %"PRIu64" in %d second(s), error=%s.\n", s->off, reconnect_delay, av_err2str(read_ret));
        err = ff_network_sleep_interruptible(1000U*1000*reconnect_delay, &h->interrupt_callback);
        if (err != AVERROR(ETIMEDOUT))
            return err;
        reconnect_delay_total += reconnect_delay;
        reconnect_delay = 1 + 2*reconnect_delay;
        conn_attempts++;
        seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
        if (seek_ret >= 0 && seek_ret != target) {
            av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRIu64".\n", target);
            return read_ret;
        }

        read_ret = http_buf_read(h, buf, size);
    }

    return read_ret;
}

// Like http_read_stream(), but no short reads.
// Assumes partial reads are an error.
static int http_read_stream_all(URLContext *h, uint8_t *buf, int size)
{
    int pos = 0;
    while (pos < size) {
        int len = http_read_stream(h, buf + pos, size - pos);
        if (len < 0)
            return len;
        pos += len;
    }
    return pos;
}

static void update_metadata(URLContext *h, char *data)
{
    char *key;
    char *val;
    char *end;
    char *next = data;
    HTTPContext *s = h->priv_data;

    while (*next) {
        key = next;
        val = strstr(key, "='");
        if (!val)
            break;
        end = strstr(val, "';");
        if (!end)
            break;

        *val = '\0';
        *end = '\0';
        val += 2;

        av_dict_set(&s->metadata, key, val, 0);
        av_log(h, AV_LOG_VERBOSE, "Metadata update for %s: %s\n", key, val);

        next = end + 2;
    }
}

static int store_icy(URLContext *h, int size)
{
    HTTPContext *s = h->priv_data;
    /* until next metadata packet */
    uint64_t remaining;

    if (s->icy_metaint < s->icy_data_read)
        return AVERROR_INVALIDDATA;
    remaining = s->icy_metaint - s->icy_data_read;

    if (!remaining) {
        /* The metadata packet is variable sized. It has a 1 byte header
         * which sets the length of the packet (divided by 16). If it's 0,
         * the metadata doesn't change. After the packet, icy_metaint bytes
         * of normal data follows. */
        uint8_t ch;
        int len = http_read_stream_all(h, &ch, 1);
        if (len < 0)
            return len;
        if (ch > 0) {
            char data[255 * 16 + 1];
            int ret;
            len = ch * 16;
            ret = http_read_stream_all(h, data, len);
            if (ret < 0)
                return ret;
            data[len] = 0;
            if ((ret = av_opt_set(s, "icy_metadata_packet", data, 0)) < 0)
                return ret;
            update_metadata(h, data);
        }
        s->icy_data_read = 0;
        remaining        = s->icy_metaint;
    }

    return FFMIN(size, remaining);
}

static int http_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;

    if (s->icy_metaint > 0) {
        size = store_icy(h, size);
        if (size < 0)
            return size;
    }

    size = http_read_stream(h, buf, size);
    if (size > 0)
        s->icy_data_read += size;
    return size;
}

/* used only when posting data */
static int http_write(URLContext *h, const uint8_t *buf, int size)
{
    char temp[11] = "";  /* 32-bit hex + CRLF + nul */
    int ret;
    char crlf[] = "\r\n";
    HTTPContext *s = h->priv_data;

    if (!s->chunked_post) {
        /* non-chunked data is sent without any special encoding */
        return ffurl_write(s->hd, buf, size);
    }

    /* silently ignore zero-size data since chunk encoding that would
     * signal EOF */
    if (size > 0) {
        /* upload data using chunked encoding */
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = ffurl_write(s->hd, temp, strlen(temp))) < 0 ||
            (ret = ffurl_write(s->hd, buf, size)) < 0          ||
            (ret = ffurl_write(s->hd, crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    }
    return size;
}

static int http_shutdown(URLContext *h, int flags)
{
    int ret = 0;
    char footer[] = "0\r\n\r\n";
    HTTPContext *s = h->priv_data;

    /* signal end of chunked encoding if used */
    if (((flags & AVIO_FLAG_WRITE) && s->chunked_post) ||
        ((flags & AVIO_FLAG_READ) && s->chunked_post && s->listen)) {
        ret = ffurl_write(s->hd, footer, sizeof(footer) - 1);
        ret = ret > 0 ? 0 : ret;
        /* flush the receive buffer when it is write only mode */
        if (!(flags & AVIO_FLAG_READ)) {
            char buf[1024];
            int read_ret;
            s->hd->flags |= AVIO_FLAG_NONBLOCK;
            read_ret = ffurl_read(s->hd, buf, sizeof(buf));
            s->hd->flags &= ~AVIO_FLAG_NONBLOCK;
            if (read_ret < 0 && read_ret != AVERROR(EAGAIN)) {
                av_log(h, AV_LOG_ERROR, "URL read error: %s\n", av_err2str(read_ret));
                ret = read_ret;
            }
        }
        s->end_chunked_post = 1;
    }

    return ret;
}

static int http_close(URLContext *h)
{
    int ret = 0;
    HTTPContext *s = h->priv_data;

#if CONFIG_ZLIB
    inflateEnd(&s->inflate_stream);
    av_freep(&s->inflate_buffer);
#endif /* CONFIG_ZLIB */

    if (s->hd && !s->end_chunked_post)
        /* Close the write direction by sending the end of chunked encoding. */
        ret = http_shutdown(h, h->flags);

    if (s->hd)
        ffurl_closep(&s->hd);
    av_dict_free(&s->chained_options);
    av_dict_free(&s->cookie_dict);
    av_dict_free(&s->redirect_cache);
    av_freep(&s->new_location);
    av_freep(&s->uri);
    return ret;
}

static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect)
{
    HTTPContext *s = h->priv_data;
    URLContext *old_hd = s->hd;
    uint64_t old_off = s->off;
    uint8_t old_buf[BUFFER_SIZE];
    int old_buf_size, ret;
    AVDictionary *options = NULL;

    if (whence == AVSEEK_SIZE)
        return s->filesize;
    else if (!force_reconnect &&
             ((whence == SEEK_CUR && off == 0) ||
              (whence == SEEK_SET && off == s->off)))
        return s->off;
    else if ((s->filesize == UINT64_MAX && whence == SEEK_END))
        return AVERROR(ENOSYS);

    if (whence == SEEK_CUR)
        off += s->off;
    else if (whence == SEEK_END)
        off += s->filesize;
    else if (whence != SEEK_SET)
        return AVERROR(EINVAL);
    if (off < 0)
        return AVERROR(EINVAL);
    s->off = off;

    if (s->off && h->is_streamed)
        return AVERROR(ENOSYS);

    /* do not try to make a new connection if seeking past the end of the file */
    if (s->end_off || s->filesize != UINT64_MAX) {
        uint64_t end_pos = s->end_off ? s->end_off : s->filesize;
        if (s->off >= end_pos)
            return s->off;
    }

    /* if the location changed (redirect), revert to the original uri */
    if (strcmp(s->uri, s->location)) {
        char *new_uri;
        new_uri = av_strdup(s->uri);
        if (!new_uri)
            return AVERROR(ENOMEM);
        av_free(s->location);
        s->location = new_uri;
    }

    /* we save the old context in case the seek fails */
    old_buf_size = s->buf_end - s->buf_ptr;
    memcpy(old_buf, s->buf_ptr, old_buf_size);
    s->hd = NULL;

    /* if it fails, continue on old connection */
    if ((ret = http_open_cnx(h, &options)) < 0) {
        av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
    av_dict_free(&options);
    ffurl_close(old_hd);
    return off;
}

static int64_t http_seek(URLContext *h, int64_t off, int whence)
{
    return http_seek_internal(h, off, whence, 0);
}

static int http_get_file_handle(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return ffurl_get_file_handle(s->hd);
}

static int http_get_short_seek(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    if (s->short_seek_size >= 1)
        return s->short_seek_size;
    return ffurl_get_short_seek(s->hd);
}

#define HTTP_CLASS(flavor)                          \
static const AVClass flavor ## _context_class = {   \
    .class_name = # flavor,                         \
    .item_name  = av_default_item_name,             \
    .option     = options,                          \
    .version    = LIBAVUTIL_VERSION_INT,            \
}

#if CONFIG_HTTP_PROTOCOL
HTTP_CLASS(http);

const URLProtocol ff_http_protocol = {
    .name                = "http",
    .url_open2           = http_open,
    .url_accept          = http_accept,
    .url_handshake       = http_handshake,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &http_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy,data"
};
#endif /* CONFIG_HTTP_PROTOCOL */

#if CONFIG_HTTPS_PROTOCOL
HTTP_CLASS(https);

const URLProtocol ff_https_protocol = {
    .name                = "https",
    .url_open2           = http_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &https_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy"
};
#endif /* CONFIG_HTTPS_PROTOCOL */

#if CONFIG_HTTPPROXY_PROTOCOL
HTTP_CLASS(httpproxy);

const URLProtocol ff_httpproxy_protocol = {
    .name                = "httpproxy",
    .url_open            = http_proxy_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_proxy_close,
    .url_get_file_handle = http_get_file_handle,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &httpproxy_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
};
#endif /* CONFIG_HTTPPROXY_PROTOCOL */

#endif // !MVD_USE_LIBCURL
