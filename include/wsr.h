#ifndef WSR_H
#define	WSR_H

#include "rcd.h"
#define WSR_VERSION "0.1"

/// A http header.
typedef struct wsr_hdr {
    /// Lowercased and trimmed http header key.
    fstr_t key;
    /// Trimmed http header value.
    fstr_t value;
} wsr_hdr_t;

/// An incoming http request.
typedef struct wsr_req {
    fstr_t method;
    fstr_t path;
    /// Requests headers. All keys are trimmed and lowercased. All values are trimmed.
    dict(fstr_t)* headers;
    dict(fstr_t)* url_params;
} wsr_req_t;

decl_fid_t(wssr);
decl_fid_t(wssw);

/// Callback for http web socket sessions. reader_fid and writer_fid should be used only for
/// calls to wsr_web_socket_read and wsr_web_socket_write/wsr_web_socket_close, respectively.
typedef void (*wsr_wss_cb_t)(rio_in_addr4_t peer, sf(wssr)* reader_sf, sf(wssw)* writer_sf, void* cb_arg);

/// An outgoing http response.
typedef struct wsr_rsp {
    /// Heap for response.
    lwt_heap_t* heap;
    /// Response status code.
    uint16_t status;
    /// Response reason phrase.
    fstr_t reason;
    /// Extra headers to send with the response or 0.
    dict(fstr_t)* headers;
    /// If request should trigger a web socket connection, this is the
    /// corresponding callback for the web socket session, otherwise 0.
    wsr_wss_cb_t wss_cb;
    /// If wss_cb is not 0, the selected web socket protocol to use.
    fstr_t ws_protocol;
    /// If wss_cb is 0, response body stream, otherwise undefined.
    rio_t* body_stream;
    /// If body_stream is 0, the rendered html page, otherwise undefined.
    struct html* html;
    /// If html is 0, response body blob, otherwise undefined.
    fstr_t body_blob;
    /// Extra argument passed to callback.
    void* cb_arg;
} wsr_rsp_t;

/// Callback for http requests.
typedef wsr_rsp_t (*wsr_req_cb_t)(wsr_req_t req, void* cb_arg);

typedef struct wsr_cfg {
    /// Address the http server should bind and listen to.
    rio_in_addr4_t bind;
    /// TCP backlog size.
    int32_t tcp_backlog;
    /// TCP keep alive configuration.
    rio_tcp_ka_t tcp_ka;
    /// Callback for standard web requests.
    wsr_req_cb_t req_cb;
    /// Extra argument passed to callback.
    void* cb_arg;
} wsr_cfg_t;

/// Standard http status codes.
typedef enum wsr_status {
    HTTP_CONTINUE = 100,
    HTTP_SWITCH_PROTO = 101,
    HTTP_OK = 200,
    HTTP_CREATED = 201,
    HTTP_ACCEPTED = 202,
    HTTP_NON_AUTH_INFO = 203,
    HTTP_NO_CONTENT = 204,
    HTTP_RESET_CONTENT = 205,
    HTTP_PARTIAL_CONTENT = 206,
    HTTP_MULTIPLE_CHOICES = 300,
    HTTP_MOVED_PERM = 301,
    HTTP_FOUND = 302,
    HTTP_SEE_OTHER = 303,
    HTTP_NOT_MODIFIED = 304,
    HTTP_USE_PROXY = 305,
    HTTP_TEMP_REDIRECT = 307,
    HTTP_BAD_REQUEST = 400,
    HTTP_UNAUTHORIZED = 401,
    HTTP_PAYMENT_REQ = 402,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_NOT_ACCEPTABLE = 406,
    HTTP_PROXY_AUTH_REQ = 407,
    HTTP_REQUEST_TIME_OUT = 408,
    HTTP_CONFLICT = 409,
    HTTP_GONE = 410,
    HTTP_LENGTH_REQUIRED = 411,
    HTTP_PRECOND_FAILED = 412,
    HTTP_REQ_ENT_TOO_LARGE = 413,
    HTTP_REQ_URI_TOO_LARGE = 414,
    HTTP_UNSUP_MEDIA_TYPE = 415,
    HTTP_REQ_RANGE_NOT_SAT = 416,
    HTTP_EXPECTATION_FAILED = 417,
    HTTP_UPGRADE_REQUIRED = 426,
    HTTP_PRECOND_REQUIRED = 428,
    HTTP_TOO_MANY_REQUESTS = 429,
    HTTP_REQ_HDR_TOO_LARGE = 431,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_BAD_GATEWAY = 502,
    HTTP_SERVICE_UNAVAILABLE = 503,
    HTTP_GATEWAY_TIME_OUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505,
} wsr_status_t;

/// Standard web socket close codes. Usually applications should only need
/// WS_CLOSE_NORMAL (a normal closure, for when the connection is no longer
/// needed) and WS_CLOSE_POLICY_VIOLATION (a generic "invalid message" code).
/// Status codes in the range 4000-4999 are reserved for private use and may
/// also be used for any reason.
typedef enum wsr_ws_close_reason {
    WS_CLOSE_NORMAL = 1000,
    WS_CLOSE_GOING_AWAY = 1001,
    WS_CLOSE_PROTOCOL_ERROR = 1002,
    WS_CLOSE_UNSUPPORTED_DATA = 1003,
    WS_CLOSE_NO_STATUS_RECEIVED = 1005,
    WS_CLOSE_ABNORMAL = 1006,
    WS_CLOSE_INVALID_FRAME_PAYLOAD_DATA = 1007,
    WS_CLOSE_POLICY_VIOLATION = 1008,
    WS_CLOSE_MESSAGE_TOO_BIG = 1009,
    WS_CLOSE_MANDATORY_EXTENSION = 1010,
    WS_CLOSE_INTERNAL_SERVER_ERROR = 1011,
    WS_CLOSE_TLS_HANDSHAKE = 1015,
} wsr_ws_close_reason_t;

/// Web socket handshake GUID.
extern const fstr_t wsr_ws_handshake_guid;

/// Gets a built-in reason phrase from a status code.
fstr_t wsr_reason(wsr_status_t status);

/// Gets a default initialized http configuration.
wsr_cfg_t wsr_default_cfg();

/// Returns true if request is a web socket open.
bool wsr_req_is_ws_open(wsr_req_t req);

/// Safely respond with a file read from the file system with proper caching.
/// Note that the base path must be a real path.
wsr_rsp_t wsr_response_file(wsr_req_t req, fstr_t base_path);

/// Starts a wsr http server with specified configuration.
/// Listens to specified socket and spawns a new static unsynchronized fiber
/// for each connection that calls the configured callback handlers.
/// This function never returns. Throws io exception on various io failures.
void wsr_start(wsr_cfg_t cfg);

/// Write a web socket message. Throws io exception.
void wsr_web_socket_write(fstr_t data, bool binary, fid(wssw) writer_fid);

/// Send a close message (a close code + a textual explanation) over a web socket
/// connection, then close the connection. If "data" is empty, no close code is
/// sent, which should be interpreted by the client as WS_CLOSE_NO_STATUS_RECEIVED.
/// Throws io exception.
void wsr_web_socket_close(wsr_ws_close_reason_t status_code, fstr_t data, fid(wssw) writer_fid);

/// Read a web socket message size with <= limit, while simultaneously taking
/// care to respond to Ping and Close packets. The application should always be
/// blocked on this function in its default state, to be able to know when the
/// connection closes, and to avoid client disconnects due to inactivity.
/// Throws io exception on too large messages, or if the connection is closed.
/// If non-null, out_binary will be set to whether the message was in binary
/// form, rather than text.
fstr_mem_t* wsr_web_socket_read(size_t limit, fid(wssr) reader_fid, bool* out_binary);

/// Returns a simple response without a body.
static inline wsr_rsp_t wsr_response(wsr_status_t status) {
    wsr_rsp_t rsp = {
        .status = status,
        .reason = wsr_reason(status),
    };
    return rsp;
}

/// Returns a simple response with specified static body.
/// Tip: You can set "mime_type" to wsr_mime_html if you are responding with html.
static inline wsr_rsp_t wsr_response_static(wsr_status_t status, fstr_t body, fstr_t mime_type) {
    wsr_rsp_t rsp = wsr_response(status);
    rsp.heap = lwt_alloc_heap();
    switch_heap(rsp.heap) {
        rsp.headers = new_dict(fstr_t);
        (void) dict_insert(rsp.headers, fstr_t, fstr("content-type"), mime_type);
        rsp.body_blob = body;
    }
    return rsp;
}

/// Returns a simple response with specified dynamic body.
static inline wsr_rsp_t wsr_response_dynamic(wsr_status_t status, fstr_mem_t* body, fstr_t mime_type) {
    wsr_rsp_t rsp = wsr_response(status);
    rsp.heap = lwt_alloc_heap();
    switch_heap(rsp.heap) {
        rsp.headers = new_dict(fstr_t);
        (void) dict_insert(rsp.headers, fstr_t, fstr("content-type"), mime_type);
        rsp.body_blob = fss(import(body));
    }
    return rsp;
}

static inline wsr_rsp_t wsr_response_html(wsr_status_t status, struct html* html) {
    wsr_rsp_t rsp = wsr_response(status);
    rsp.heap = lwt_alloc_heap();
    switch_heap(rsp.heap) {
        rsp.headers = new_dict(fstr_t);
        extern const fstr_t wsr_mime_html;
        (void) dict_insert(rsp.headers, fstr_t, fstr("content-type"), wsr_mime_html);
        rsp.html = html;
    }
    return rsp;
}

static inline wsr_rsp_t wsr_response_redirect(fstr_t path) {
    wsr_rsp_t rsp = wsr_response(HTTP_FOUND);
    rsp.heap = lwt_alloc_heap();
    switch_heap(rsp.heap) {
        rsp.headers = new_dict(fstr_t);
        (void) dict_insert(rsp.headers, fstr_t, fstr("location"), path);
    }
    return rsp;
}

/// Returns a virtual response indicating that connection should be upgraded to web socket.
static inline wsr_rsp_t wsr_response_web_socket(wsr_req_t req, wsr_wss_cb_t wss_cb, fstr_t ws_protocol, void* cb_arg) {
    if (!wsr_req_is_ws_open(req))
        return wsr_response(HTTP_NO_CONTENT);
    wsr_rsp_t ws_rsp = {
        .wss_cb = wss_cb,
        .ws_protocol = ws_protocol,
        .cb_arg = cb_arg,
    };
    return ws_rsp;
}

#endif	/* WSR_H */
