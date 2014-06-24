/* wsr.c - Web Scale RCD, minimal HTTP and Web Socket implementation. */
/* This implementation has the ambition to be fast, minimal and incomplete. */
/* The HTTP "Standard" is over engineered, bloated and horrible in general. */
/* Therefore we will only implement the parts that makes us good enough for */
/* most modern use cases. */

#include "rcd.h"
#include "polarssl/sha1.h"
#include "wsr.h"
#include "wsr-mime.h"
#include "wsr-tpl.h"

/// The minimum number of bytes that we should accept in the header.
/// We use 6 kB as this is a good compromise between memory usage and what
/// is usually expected that http should accept in practice.
#define WSR_MIN_ACCEPTED_HEADER_SIZE (0x1500)

/// Buffer size we use when streaming body to client
/// with chunked transfer encoding.
#define WSR_BODY_STREAM_BUF_SIZE (0x8000)

/// The internal peek buffer size for the http rio handle. The approximate
/// worst case maximum number of os read() calls is WSR_BODY_STREAM_BUF_SIZE
/// times this value.
#define WSR_READ_PEEK_BUF_SIZE (0x800)

/// Maximum number of headers we support in a single http request.
#define WSR_MAX_N_HEADERS (0x100)

#pragma librcd

const fstr_t wsr_ws_handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fstr_t wsr_reason(wsr_status_t status) {
    switch (status) {
    case HTTP_CONTINUE:
        return "Continue";
    case HTTP_SWITCH_PROTO:
        return "Switching Protocols";
    case HTTP_OK:
        return "OK";
    case HTTP_CREATED:
        return "Created";
    case HTTP_ACCEPTED:
        return "Accepted";
    case HTTP_NON_AUTH_INFO:
        return "Non-Authoritative Information";
    case HTTP_NO_CONTENT:
        return "No Content";
    case HTTP_RESET_CONTENT:
        return "Reset Content";
    case HTTP_PARTIAL_CONTENT:
        return "Partial Content";
    case HTTP_MULTIPLE_CHOICES:
        return "Multiple Choices";
    case HTTP_MOVED_PERM:
        return "Moved Permanently";
    case HTTP_FOUND:
        return "Found";
    case HTTP_SEE_OTHER:
        return "See Other";
    case HTTP_NOT_MODIFIED:
        return "Not Modified";
    case HTTP_USE_PROXY:
        return "Use Proxy";
    case HTTP_TEMP_REDIRECT:
        return "Temporary Redirect";
    case HTTP_BAD_REQUEST:
        return "Bad Request";
    case HTTP_UNAUTHORIZED:
        return "Unauthorized";
    case HTTP_PAYMENT_REQ:
        return "Payment Required";
    case HTTP_FORBIDDEN:
        return "Forbidden";
    case HTTP_NOT_FOUND:
        return "Not Found";
    case HTTP_METHOD_NOT_ALLOWED:
        return "Method Not Allowed";
    case HTTP_NOT_ACCEPTABLE:
        return "Not Acceptable";
    case HTTP_PROXY_AUTH_REQ:
        return "Proxy Authentication Required";
    case HTTP_REQUEST_TIME_OUT:
        return "Request Time-out";
    case HTTP_CONFLICT:
        return "Conflict";
    case HTTP_GONE:
        return "Gone";
    case HTTP_LENGTH_REQUIRED:
        return "Length Required";
    case HTTP_PRECOND_FAILED:
        return "Precondition Failed";
    case HTTP_REQ_ENT_TOO_LARGE:
        return "Request Entity Too Large";
    case HTTP_REQ_URI_TOO_LARGE:
        return "Request-URI Too Large";
    case HTTP_UNSUP_MEDIA_TYPE:
        return "Unsupported Media Type";
    case HTTP_REQ_RANGE_NOT_SAT:
        return "Requested range not satisfiable";
    case HTTP_EXPECTATION_FAILED:
        return "Expectation Failed";
    case HTTP_UPGRADE_REQUIRED:
        return "Upgrade Required";
    case HTTP_PRECOND_REQUIRED:
        return "Precondition Required";
    case HTTP_TOO_MANY_REQUESTS:
        return "Too Many Requests";
    case HTTP_REQ_HDR_TOO_LARGE:
        return "Request Header Fields Too Large";
    case HTTP_INTERNAL_SERVER_ERROR:
        return "Internal Server Error";
    case HTTP_NOT_IMPLEMENTED:
        return "Not Implemented";
    case HTTP_BAD_GATEWAY:
        return "Bad Gateway";
    case HTTP_SERVICE_UNAVAILABLE:
        return "Service Unavailable";
    case HTTP_GATEWAY_TIME_OUT:
        return "Gateway Time-out";
    case HTTP_VERSION_NOT_SUPPORTED:
        return "HTTP Version not supported";
    }
}

wsr_cfg_t wsr_default_cfg() {
    wsr_cfg_t cfg = {
        .bind.port = 80,
        .tcp_backlog = 1024,
    };
    return cfg;
}

static inline void http_reply_raw_body(rio_t* client_h, fstr_t response, fstr_t extra_headers, fstr_t optional_body) {
    fstr_t reply = concs(
        "HTTP/1.1 ",
        response,
        "\r\nConnection: close"
        "\r\nContent-Length: ",
        ui2fs(optional_body.len),
        "\r\nContent-Type: text/html\r\n",
        extra_headers,
        "\r\n",
        optional_body,
    );
    rio_write(client_h, reply);
}

static void http_reply_raw(rio_t* client_h, fstr_t response, fstr_t extra_headers, bool generate_body) { sub_heap {
    fstr_t optional_body = generate_body? concs("<h1>", response, "</h1>\n"): "";
    http_reply_raw_body(client_h, response, extra_headers, optional_body);
}}

static void http_reply_simple_status(rio_t* client_h, wsr_status_t status) { sub_heap {
    fstr_t response = concs(ui2fs(status), " ", wsr_reason(status));
    http_reply_raw(client_h, response, "", true);
}}

static inline bool parse_req_line(fstr_t req_line, fstr_t* out_method, fstr_t* out_uri, fstr_t* out_version) {
    fstr_t c_method, c_request_uri, c_version;
    {
        #pragma ocre2c(req_line): ^ ([A-Z]{1,16}){c_method} [ ]+ (/[^\x00-\x20]*) {c_request_uri} [ ]+ HTTP/(\d+\.\d+) {c_version} [ ]* $ {@request_uri_match}
        // No match.
        return false;
    } request_uri_match: {
        *out_method = c_method;
        *out_uri = c_request_uri;
        *out_version = c_version;
        return true;
    }
}

static void request_header_error(rio_t* client_h) {
    // Return bad request and close connection.
    http_reply_simple_status(client_h, HTTP_BAD_REQUEST);
    throw("syntax error when parsing request header", exception_io);
}

typedef struct wss_cb_arg {
    wsr_wss_cb_t wss_cb;
    void* cb_arg;
} wss_cb_arg_t;

static wss_cb_arg_t http_session(rio_t* client_h, wsr_cfg_t cfg) {
    // Set tcp keep-alive.
    if (cfg.tcp_ka.idle_before_ping_s > 0 && cfg.tcp_ka.ping_interval_s > 0 && cfg.tcp_ka.count_before_timeout > 0)
        rio_tcp_set_keepalive(client_h, cfg.tcp_ka);
    // Allocate header buffer.
    fstr_t header_buf = fss(fstr_alloc_buffer(WSR_MIN_ACCEPTED_HEADER_SIZE));
    for (;;) sub_heap {
        // Read raw header of next request.
        fstr_t raw_headers;
        try {
            raw_headers = rio_read_to_separator(client_h, "\r\n\r\n", header_buf);
        } catch (exception_io, e) {
            // Peek first, this will throw another io exception if stream was closed.
            rio_peek(client_h);
            // Buffer ran out, got too large request header.
            http_reply_simple_status(client_h, HTTP_REQ_HDR_TOO_LARGE);
            throw_fwd("end of stream or too large request header", exception_io, e);
        }
        // Parse request-line.
        fstr_t req_line;
        if (!fstr_iterate_trim(&raw_headers, "\r\n", &req_line))
            request_header_error(client_h);
        wsr_req_t req;
        if (!parse_req_line(req_line, &req.method, &req.path, &req.version))
            request_header_error(client_h);
        // We only allow HTTP 1.0 and 1.1 at this point
        if (!fstr_equal(req.version, "1.1") && !fstr_equal(req.version, "1.0")) {
            http_reply_simple_status(client_h, HTTP_VERSION_NOT_SUPPORTED);
            throw("got unsupported http version from client", exception_io);
        }
        // We only handle GET and HEAD requests at this point. Handling other requests would require supporting uploads.
        if (!fstr_equal(req.method, "GET") && !fstr_equal(req.method, "HEAD")) {
            http_reply_simple_status(client_h, HTTP_METHOD_NOT_ALLOWED);
            throw("got unsupported http method from client", exception_io);
        }
        // Index headers from client.
        req.headers = new_dict(fstr_t);
        for (fstr_t raw_header; fstr_iterate_trim(&raw_headers, "\r\n", &raw_header);) {
            fstr_t key, value;
            if (!fstr_divide(raw_header, ":", &key, &value))
                request_header_error(client_h);
            key = fstr_trim(key);
            fstr_tolower(key);
            value = fstr_trim(value);
            (void) dict_insert(req.headers, fstr_t, key, value);
        }
        // Pass request to callback and get response.
        wsr_rsp_t rsp = cfg.req_cb(req, cfg.cb_arg);
        // Handle possible web socket upgrade.
        if (rsp.wss_cb != 0) {
            fstr_t* ws_version = dict_read(req.headers, fstr_t, "sec-websocket-version");
            if (ws_version == 0 || !fstr_equal(*ws_version, "13")) {
                http_reply_simple_status(client_h, HTTP_UPGRADE_REQUIRED);
                throw("client sent bad version in ws handshake", exception_io);
            }
            fstr_t* ws_key = dict_read(req.headers, fstr_t, "sec-websocket-key");
            if (ws_key == 0) {
                http_reply_simple_status(client_h, HTTP_BAD_REQUEST);
                throw("client sent no key in ws handshake", exception_io);
            }
            flstr(20)* ws_accept = fstr_sha1(concs(*ws_key, wsr_ws_handshake_guid));
            fstr_t header = concs(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: ", fss(fstr_base64_encode(flstr_to_fstr(ws_accept, 20))), "\r\n",
                (rsp.ws_protocol.len != 0? concs("Sec-WebSocket-Protocol: ", rsp.ws_protocol, "\r\n"): ""),
                "\r\n"
            );
            rio_write(client_h, header);
            return (wss_cb_arg_t) {.wss_cb = rsp.wss_cb, .cb_arg = rsp.cb_arg};
        }
        // Compile and send raw head to client.
        sub_heap {
            if (rsp.reason.len == 0)
                rsp.reason = "-";
            fstr_t status_line = concs("HTTP/1.1 ", ui2fs(rsp.status), " ", rsp.reason);
            list(fstr_t)* raw_headers = new_list(fstr_t, status_line);
            if (rsp.headers != 0) {
                dict_foreach(rsp.headers, fstr_t, key, value) {
                    list_push_end(raw_headers, fstr_t, concs(key, ": ", value));
                }
            }
            bool has_body;
            if (rsp.body_stream != 0) {
                list_push_end(raw_headers, fstr_t, "transfer-encoding: chunked");
                has_body = true;
            } else if (rsp.html != 0) {
                list_push_end(raw_headers, fstr_t, concs("content-length: ", ui2fs(wsr_tpl_length(rsp.html))));
                has_body = true;
            } else {
                list_push_end(raw_headers, fstr_t, concs("content-length: ", ui2fs(rsp.body_blob.len)));
                has_body = (rsp.body_blob.len > 0);
            }
            list_push_end(raw_headers, fstr_t, "server: wsr/" WSR_VERSION);
            list_push_end(raw_headers, fstr_t, concs("date: ", fss(rio_clock_to_rfc1123(rio_get_time_clock()))));
            list_push_end(raw_headers, fstr_t, "\r\n");
            fstr_t raw_header = fss(fstr_implode(raw_headers, "\r\n"));
            //*x-dbg*/ DBGFN(">>[", raw_header, "]<<");
            rio_write_part(client_h, raw_header, has_body);
        }
        // Send raw body.
        if (fstr_equal(req.method, "HEAD")) {
            // Don't send a body.
        } else if (rsp.body_stream != 0) {
            // Send response body with chunked transfer encoding.
            fstr_t body_buf = fss(fstr_alloc_buffer(WSR_BODY_STREAM_BUF_SIZE));
            for (;;) sub_heap {
                bool more_hint;
                fstr_t chunk;
                try {
                    chunk = rio_read_part(rsp.body_stream, body_buf, &more_hint);
                } catch (exception_io, e) {
                    // Assuming end of response stream. We don't expose i/o errors to the web client yet.
                    goto end_of_chunked_body;
                }
                if (chunk.len == 0)
                    goto end_of_chunked_body;
                // Write the chunk init line.
                sub_heap {
                    fstr_t chunk_init_line = concs(fss(fstr_from_uint(chunk.len, 16)), "\r\n");
                    rio_write_part(client_h, chunk_init_line, true);
                }
                // Write chunk data.
                rio_write_part(client_h, chunk, true);
                // Write chunk trailer.
                rio_write_part(client_h, "\r\n", false);
            } end_of_chunked_body: {
                // Write last-chunk without any trailing headers.
                rio_write(client_h, "0\r\n\r\n");
            }
        } else if (rsp.html != 0) {
            // Send rendered html page.
            wsr_tpl_writev(client_h, rsp.html);
        } else if (rsp.body_blob.len > 0) {
            // Send response body as a pure binary blob.
            rio_write(client_h, rsp.body_blob);
        }
    }
}

typedef struct wss_read_arg {
    rio_t* client_r;
    fid(wssw) writer_fid;
} wss_read_arg_t;

typedef struct wss_write_arg {
    rio_t* client_w;
    bool closed;
} wss_write_arg_t;

static void web_socket_read_masked(rio_t* client_r, fstr_t buf, uint8_t mask[4]) {
    rio_read_fill(client_r, buf);
    // Xor buf with mask32, 64 bits at a time. Writes may
    // be unaligned, but that's okay on x86_64 nowadays.
    uint32_t mask32 = *(uint32_t*)mask;
    uint64_t mask64 = mask32 | (uint64_t)mask32 << 32;
    uint64_t* buf64 = (uint64_t*)buf.str;
    for (size_t i = 0; i < buf.len / 8; i++)
        buf64[i] ^= mask64;
    for (size_t i = buf.len - (buf.len % 8); i < buf.len; i++)
        buf.str[i] ^= mask[i & 3];
}

static void web_socket_fail(fid(wssw) writer_fid, wsr_ws_close_reason_t status_code, fstr_t data) {
    wsr_web_socket_close(status_code, data, writer_fid);
    sub_heap_e(throw(concs("failed web socket: ", data), exception_io));
}

static void unknown_opcode_fail(fid(wssw) writer_fid, uint8_t opcode) { sub_heap {
    web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, concs("unknown opcode [", ui2fs(opcode), "]"));
}}

join_locked(void) web_socket_pong(fstr_t msg, join_server_params, wss_write_arg_t* write_arg) {
    assert(msg.len <= 125);
    rio_t* client_w = write_arg->client_w;
    uint16_t two_bytes_nbo = RIO_NBO_SWAP16(0x8A00 | (uint16_t)msg.len);
    rio_write(client_w, FSTR_PACK(two_bytes_nbo));
    rio_write(client_w, msg);
}

join_locked(fstr_mem_t*) web_socket_read(size_t limit, bool* out_binary, join_server_params, wss_read_arg_t read_arg) { sub_heap {
    rio_t* client_r = read_arg.client_r;
    fid(wssw) writer_fid = read_arg.writer_fid;
    fstr_mem_t* out = fstr_alloc(limit);
    size_t outind = 0;
    int frame_type = -1;
    for (;;) {
        // Read frame header.
        uint16_t two_bytes_nbo;
        rio_read_fill(client_r, FSTR_PACK(two_bytes_nbo));
        uint16_t two_bytes = RIO_NBO_SWAP16(two_bytes_nbo);
        bool fin = (two_bytes & 0x8000) != 0;
        uint16_t reserved = (two_bytes & 0x7000) >> 12;
        uint8_t opcode = (two_bytes & 0xf00) >> 8;
        bool mask_bit = (two_bytes & 0x80) != 0;
        size_t payload_len = two_bytes & 0x7f;
        if (payload_len == 126) {
            uint16_t payload_len16_nbo;
            rio_read_fill(client_r, FSTR_PACK(payload_len16_nbo));
            payload_len = RIO_NBO_SWAP16(payload_len16_nbo);
        } else if (payload_len == 127) {
            uint16_t payload_len64_nbo;
            rio_read_fill(client_r, FSTR_PACK(payload_len64_nbo));
            payload_len = RIO_NBO_SWAP64(payload_len64_nbo);
        }
        uint8_t mask[4];
        if (mask_bit) {
            rio_read_fill(client_r, FSTR_PACK(mask));
        } else {
            web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "missing mask");
        }
        if (reserved != 0)
            web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "unsupported extension");
        // Handle the frame.
        if (opcode >= 8) {
            // Control frame.
            if (payload_len > 125)
                web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "control frame payload too large");
            if (!fin)
                web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "fragmented control frame");
            sub_heap {
                fstr_t buf = fss(fstr_alloc(payload_len));
                web_socket_read_masked(client_r, buf, mask);
                if (opcode == 8) {
                    // Close - respond with the same thing and close the connection.
                    if (payload_len == 1)
                        web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "invalid close reason");
                    wsr_ws_close_reason_t status_code;
                    fstr_t close_reason;
                    if (payload_len == 0) {
                        status_code = WS_CLOSE_NO_STATUS_RECEIVED;
                        close_reason = "";
                    } else {
                        uint16_t status_code_nbo;
                        fstr_cpy_over(FSTR_PACK(status_code_nbo), buf, 0, 0);
                        status_code = RIO_NBO_SWAP16(status_code_nbo);
                        close_reason = fstr_slice(buf, 2, buf.len);
                    }
                    wsr_web_socket_close(status_code, close_reason, writer_fid);
                    sub_heap {
                        fstr_t reason = "client closed web socket";
                        if (close_reason.len != 0)
                            reason = concs(reason, ": ", close_reason);
                        throw(reason, exception_io);
                    }
                } else if (opcode == 9) {
                    // Ping.
                    web_socket_pong(buf, writer_fid.fid);
                } else if (opcode == 10) {
                    // Pong - just ignore.
                } else {
                    unknown_opcode_fail(writer_fid, opcode);
                }
            }
        } else {
            // Data frame.
            if (opcode == 0) {
                // Continuation.
                if (frame_type == -1)
                    web_socket_fail(writer_fid, WS_CLOSE_PROTOCOL_ERROR, "first frame is a continuation frame");
            } else if (opcode == 1 || opcode == 2) {
                // Text/Binary.
                frame_type = opcode;
            } else {
                unknown_opcode_fail(writer_fid, opcode);
            }
            if (payload_len > limit - outind)
                web_socket_fail(writer_fid, WS_CLOSE_MESSAGE_TOO_BIG, "payload too large");
            fstr_t buf = fstr_slice(fss(out), outind, outind + payload_len);
            outind += payload_len;
            web_socket_read_masked(client_r, buf, mask);
            if (fin)
                break;
        }
    }
    if (out_binary != 0)
        *out_binary = (frame_type == 2);
    out->len = outind;
    return escape(out);
}}

fstr_mem_t* wsr_web_socket_read(size_t limit, fid(wssr) reader_fid, bool* out_binary) {
    try {
        return web_socket_read(limit, out_binary, reader_fid.fid);
    } catch (exception_inner_join_fail, e) {
        throw_fwd("web socket reader already closed", exception_io, e);
    }
}

join_locked(void) web_socket_write(fstr_t data, bool binary, join_server_params, wss_write_arg_t* write_arg) {
    rio_t* client_w = write_arg->client_w;
    uint8_t buf[10];
    fstr_t header;
    header.len = 2;
    header.str = buf;
    uint16_t payload1;
    if (data.len <= 125) {
        payload1 = data.len;
    } else if (data.len < 0x10000) {
        payload1 = 126;
        header.len += 2;
        uint16_t len_nbo = RIO_NBO_SWAP16((uint16_t)data.len);
        fstr_cpy_over(fstr_slice(header, 2, 4), FSTR_PACK(len_nbo), 0, 0);
    } else {
        payload1 = 127;
        header.len += 8;
        uint64_t len_nbo = RIO_NBO_SWAP64((uint64_t)data.len);
        fstr_cpy_over(fstr_slice(header, 2, 10), FSTR_PACK(len_nbo), 0, 0);
    }
    uint16_t opcode = binary? 2: 1;
    uint16_t fin = 0x8000;
    uint16_t two_bytes_nbo = RIO_NBO_SWAP16(fin | (opcode << 8) | payload1);
    fstr_cpy_over(fstr_slice(header, 0, 2), FSTR_PACK(two_bytes_nbo), 0, 0);
    rio_write(client_w, header);
    rio_write(client_w, data);
}

void wsr_web_socket_write(fstr_t data, bool binary, fid(wssw) writer_fid) {
    try {
        web_socket_write(data, binary, writer_fid.fid);
    } catch (exception_inner_join_fail, e) {
        throw_fwd("web socket writer already closed", exception_io, e);
    }
}

join_locked(void) web_socket_close(wsr_ws_close_reason_t status_code, fstr_t data, join_server_params, wss_write_arg_t* write_arg) {
    assert(data.len <= 123);
    rio_t* client_w = write_arg->client_w;
    uint16_t str_len = (uint16_t)data.len;
    uint16_t two_bytes_nbo = RIO_NBO_SWAP16(0x8800 | (str_len == 0? 0: str_len + 2));
    rio_write(client_w, FSTR_PACK(two_bytes_nbo));
    if (str_len != 0) {
        uint16_t status_code_nbo = RIO_NBO_SWAP16(status_code);
        rio_write(client_w, FSTR_PACK(status_code_nbo));
        rio_write(client_w, data);
    }
    write_arg->closed = true;
}

void wsr_web_socket_close(wsr_ws_close_reason_t status_code, fstr_t data, fid(wssw) writer_fid) {
    try {
        web_socket_close(status_code, data, writer_fid.fid);
    } catch (exception_inner_join_fail, e) {
        throw_fwd("web socket writer already closed", exception_io, e);
    }
}

fiber_main_t(wssw) web_socket_writer(fiber_main_attr, rio_t* client_w) { try {
    wss_write_arg_t write_arg = {
        .client_w = client_w,
        .closed = false,
    };
    while (!write_arg.closed) {
        accept_join(web_socket_write, web_socket_pong, web_socket_close, join_server_params, &write_arg);
    }
} catch (exception_desync, e); }

fiber_main_t(wssr) web_socket_reader(fiber_main_attr, wss_read_arg_t read_arg) { try {
    auto_accept_join(web_socket_read, join_server_params, read_arg);
} catch (exception_desync, e); }

static void web_socket_session(rio_t* client_h, wss_cb_arg_t wss_cb) { sub_heap {
    rio_in_addr4_t peer;
    sf(wssw)* writer_sf;
    sf(wssr)* reader_sf;
    sub_heap {
        peer = rio_get_socket_address(client_h, true);
        fstr_t fiber_name = fss(rio_serial_in_addr4(peer));
        rio_t *client_r, *client_w;
        rio_realloc_split(client_h, &client_r, &client_w);
        fmitosis {
            writer_sf = spawn_fiber(web_socket_writer(fiber_name, import(client_w)));
        }
        fmitosis {
            wss_read_arg_t read_arg = {
                .client_r = import(client_r),
                .writer_fid = sf2id(wssw, writer_sf),
            };
            reader_sf = spawn_fiber(web_socket_reader(fiber_name, read_arg));
        }
        escape_list(writer_sf, reader_sf);
    }
    wss_cb.wss_cb(peer, reader_sf, writer_sf, wss_cb.cb_arg);
}}

fiber_main http_connection_fiber(fiber_main_attr, rio_t* client_h, wsr_cfg_t cfg) { try {
    // Handle http session until it upgrades to a web socket session.
    wss_cb_arg_t wss_cb = http_session(client_h, cfg);
    // Handle web socket session.
    web_socket_session(client_h, wss_cb);
} catch (exception_io | exception_desync, e) {
    //DBG(fss(lwt_get_exception_dump(e)));
}}

static bool contains_comma_separated(fstr_t values, fstr_t target) {
    for (fstr_t value; fstr_iterate_trim(&values, ",", &value);) {
        if (fstr_equal(value, target))
            return true;
    }
    return false;
}

bool wsr_req_is_ws_open(wsr_req_t req) {
    fstr_t* upgrade_hdr = dict_read(req.headers, fstr_t, "upgrade");
    if (upgrade_hdr == 0 || !contains_comma_separated(*upgrade_hdr, "websocket"))
        return false;
    fstr_t* connection_hdr = dict_read(req.headers, fstr_t, "connection");
    if (connection_hdr == 0 || !contains_comma_separated(*connection_hdr, "Upgrade"))
        return false;
    return true;
}

static fstr_mem_t* wsr_etag(rio_stat_t st) {
    sha1_context ctx;
    sha1_starts(&ctx);
    sha1_update(&ctx, (void*) &st.time_modified, sizeof(st.time_modified));
    sha1_update(&ctx, (void*) &st.size, sizeof(st.size));
    uint8_t raw_sha1_out[20];
    sha1_finish(&ctx, raw_sha1_out);
    fstr_t bin_etag = {.str = raw_sha1_out, .len = 8};
    return fstr_hexencode(bin_etag);
}

wsr_rsp_t wsr_response_file(wsr_req_t req, fstr_t base_path) { sub_heap {
    if (req.path.len == 0 || req.path.str[0] != '/' || base_path.len == 0)
        return wsr_response(HTTP_NOT_FOUND);
    try {
        // Base path is absolute per definition but may still contain a single
        // trailing slash indicating that it's a directory and still be valid.
        if (base_path.str[base_path.len - 1] == '/')
            base_path.len--;
        // Open the file we are supposed to send.
        rio_t* file_h = rio_file_open(concs(base_path, req.path), true, false);
        // Check that we really opened a regular file.
        rio_stat_t st = rio_file_fstat(file_h);
        if (st.file_type != rio_file_type_regular)
            return wsr_response(HTTP_NOT_FOUND);
        // Verify that the absolute path of the file we opened really is path inside base_path.
        fstr_t abs_path = fss(rio_file_get_path(file_h));
        if (!fstr_prefixes(abs_path, concs(base_path, "/")))
            return wsr_response(HTTP_NOT_FOUND);
        // We only use etag for caching. This is a minimal implementation and
        // sufficient for acceptable caching behavior in modern browsers.
        fstr_mem_t* etag = wsr_etag(st);
        fstr_t* client_etag = dict_read(req.headers, fstr_t, "if-none-match");
        if (client_etag != 0 && fstr_equal(*client_etag, fss(etag)))
            return wsr_response(HTTP_NOT_MODIFIED);
        // Determine the content type by checking file extension.
        fstr_t file_ext;
        if (!fstr_rdivide(abs_path, ".", 0, &file_ext))
            file_ext = "";
        fstr_t mime_type = wsr_mime_from_ext(file_ext);
        // Assemble normal response.
        wsr_rsp_t rsp = wsr_response(HTTP_OK);
        rsp.heap = lwt_alloc_heap();
        switch_heap(rsp.heap) {
            rsp.headers = new_dict(fstr_t);
            // Since we always reply with a chunked stream we explicitly hint the
            // final expected content size so client is aware of the download progress.
            (void) dict_insert(rsp.headers, fstr_t, "content-length", ui2fs(st.size));
            fstr_t content_type = mime_type;
            (void) dict_insert(rsp.headers, fstr_t, "content-type", content_type);
            (void) dict_insert(rsp.headers, fstr_t, "etag", fss(import(etag)));
            rsp.body_stream = import(file_h);
        }
        escape_list(rsp.heap);
        return rsp;
    } catch (exception_io, e) {
        // Assume not found. A better implementation could check
        // e->errno_snapshot and return a more truthful error message.
        return wsr_response(HTTP_NOT_FOUND);
    }
}}

void wsr_start(wsr_cfg_t cfg) { sub_heap {
    assert(cfg.req_cb != 0);
    // Accept tcp connections.
    rio_t* server = rio_tcp_server(cfg.bind, cfg.tcp_backlog);
    for (;;) sub_heap {
        rio_in_addr4_t remote_addr;
        rio_t* raw_h = rio_tcp_accept(server, &remote_addr);
        fmitosis {
            rio_t* client_h = rio_realloc_peek_buffer(raw_h, WSR_READ_PEEK_BUF_SIZE);
            fstr_t fiber_name = fss(rio_serial_in_addr4(rio_get_socket_address(client_h, true)));
            spawn_static_fiber(http_connection_fiber(fiber_name, client_h, cfg));
        }
    }
}}
