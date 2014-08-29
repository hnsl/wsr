/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */
#include "rcd.h"
#include "json.h"
#include "wsr.h"
#include "wsr-mime.h"

#pragma librcd

fstr_t web_root;

typedef struct chat_participant {
    fstr_t name;
    fid(wssw) writer_fid;
} chat_participant_t;

typedef struct chat {
    dict(chat_participant_t)* participants;
    uint64_t next_id;
} chat_t;

typedef struct req_arg {
    rcd_fid_t chat_fid;
} req_arg_t;

void write_to_participant(chat_participant_t part, fstr_t data) {
    try {
        wsr_web_socket_write(data, true, part.writer_fid);
    } catch(exception_io, e) {}
}

join_locked(void) chat_send(uint64_t id, fstr_t msg, join_server_params, chat_t* chat) { sub_heap {
    fstr_t data = fss(fstr_alloc(msg.len + 9)), data_tail;
    fstr_cpy_over(data, "m", &data_tail, 0);
    fstr_cpy_over(data_tail, FSTR_PACK(id), &data_tail, 0);
    fstr_cpy_over(data_tail, msg, 0, 0);
    dict_foreach(chat->participants, chat_participant_t, key, part) {
        uint64_t uid = FSTR_UNPACK(key, uint64_t);
        if (uid != id)
            write_to_participant(part, data);
    }
}}

join_locked(uint64_t) chat_connect(fstr_t name, fid(wssw) writer_fid, join_server_params, chat_t* chat) { server_heap_flip {
    uint64_t id = chat->next_id++;
    chat_participant_t new_part = {
        .writer_fid = writer_fid,
        .name = name,
    };
    dict_foreach(chat->participants, chat_participant_t, key, part) { sub_heap {
        fstr_t data = fss(fstr_alloc(part.name.len + 9)), data_tail;
        fstr_cpy_over(data, "c", &data_tail, 0);
        fstr_cpy_over(data_tail, key, &data_tail, 0);
        fstr_cpy_over(data_tail, part.name, 0, 0);
        write_to_participant(new_part, data);
    }}
    bool ok = dict_insert(chat->participants, chat_participant_t, FSTR_PACK(id), new_part);
    assert(ok);
    sub_heap {
        fstr_t data = fss(fstr_alloc(name.len + 9)), data_tail;
        fstr_cpy_over(data, "c", &data_tail, 0);
        fstr_cpy_over(data_tail, FSTR_PACK(id), &data_tail, 0);
        fstr_cpy_over(data_tail, name, 0, 0);
        dict_foreach(chat->participants, chat_participant_t, key, part)
            write_to_participant(part, data);
        return id;
    }
}}

join_locked(void) chat_disconnect(uint64_t id, join_server_params, chat_t* chat) { server_heap_flip {
    bool ok = dict_delete(chat->participants, chat_participant_t, FSTR_PACK(id));
    assert(ok);
    sub_heap {
        fstr_t data = fss(fstr_alloc(9)), data_tail;
        fstr_cpy_over(data, "d", &data_tail, 0);
        fstr_cpy_over(data_tail, FSTR_PACK(id), 0, 0);
        dict_foreach(chat->participants, chat_participant_t, key, part)
            write_to_participant(part, data);
    }
}}

static void ws_chat(rio_in_addr4_t peer, sf(wssr)* reader_sf, sf(wssw)* writer_sf, void* cb_arg) {
    req_arg_t* req_arg = cb_arg;
    rcd_fid_t chat_fid = req_arg->chat_fid;
    fstr_t name = fss(wsr_web_socket_read(0x100, wssr_sf2id(reader_sf), 0));
    uint64_t my_id = chat_connect(name, wssw_sf2id(writer_sf), chat_fid);
    try {
        for (;;) sub_heap {
            bool binary;
            fstr_t msg = fss(wsr_web_socket_read(0x1000, wssr_sf2id(reader_sf), &binary));
            if (!binary)
                throw("expected binary message, got text", exception_io);
            chat_send(my_id, msg, chat_fid);
        }
    } finally {
        chat_disconnect(my_id, chat_fid);
    }
}

fiber_main chat_fiber(fiber_main_attr) {
    chat_t chat = {
        .next_id = 0,
    };
    chat.participants = new_dict(chat_participant_t);
    auto_accept_join(chat_send, chat_connect, chat_disconnect, join_server_params, &chat);
}

static void ws_fail(fid(wssw) writer_fid, fstr_t msg) {
    wsr_web_socket_close(WS_CLOSE_POLICY_VIOLATION, msg, writer_fid);
    sub_heap_e(throw(concs("failed web socket: ", msg), exception_io));
}

static void frobnicate(json_value_t* val) {
    switch (val->type) {
        case JSON_NULL: {
            val->type = JSON_STRING;
            val->string_value = "FILE_NOT_FOUND";
            break;
        }
        case JSON_BOOL: {
            val->bool_value = !val->bool_value;
            break;
        }
        case JSON_NUMBER: {
            val->number_value = -val->number_value;
            break;
        }
        case JSON_STRING: {
            fstr_t out = fss(fstr_cpy(val->string_value));
            for (int i = 0; i < out.len; i++) {
                uint8_t c = out.str[i];
                if ((97 <= c && c < 110) || (65 <= c && c < 78)) out.str[i] += 13;
                else if ((110 <= c && c < 123) || (78 <= c && c < 91)) out.str[i] -= 13;
            }
            val->string_value = out;
            break;
        }
        case JSON_ARRAY: {
            list(json_value_t)* out = new_list(json_value_t);
            list_foreach(val->array_value, json_value_t, v) {
                frobnicate(&v);
                list_push_start(out, json_value_t, v);
            }
            val->array_value = out;
            break;
        }
        case JSON_OBJECT: {
            dict_foreach(val->object_value, json_value_t, k, v) {
                frobnicate(&v);
                dict_foreach_replace_current(json_value_t, v);
            }
            break;
        }
    }
}

static void ws_echo_json(rio_in_addr4_t peer, sf(wssr)* reader_sf, sf(wssw)* writer_sf, void* cb_arg) {
    fid(wssr) reader_fid = wssr_sf2id(reader_sf);
    fid(wssw) writer_fid = wssw_sf2id(writer_sf);
    for (;;) { sub_heap {
        bool binary;
        fstr_t msg = fss(wsr_web_socket_read(0x10000, reader_fid, &binary));
        if (binary)
            ws_fail(writer_fid, "expected text message, got binary");
        sub_heap {
            fstr_t res;
            try {
                json_tree_t* tree = json_parse(msg);
                json_value_t val = JSON_LREF(tree->value, "some", "key");
                if (!json_is_null(val)) {
                    // Then tree->value must have been an object.
                    fstr_t str = json_get_string(val);
                    json_value_t other = json_new_object();
                    JSON_SET(other, "key", json_string_v(concs(str, str)));
                    JSON_SET(tree->value, "other", other);
                }
                frobnicate(&tree->value);
                fstr_t resp = fss(json_stringify(tree->value));
                wsr_web_socket_write(resp, false, writer_fid);
            } catch (exception_arg, e) {
                wsr_web_socket_write("failure", false, writer_fid);
                //*x-dbg*/ DBGE(e);
            }
        }
    }}
}

static void ws_echo(rio_in_addr4_t peer, sf(wssr)* reader_sf, sf(wssw)* writer_sf, void* cb_arg) {
    for (;;) { sub_heap {
        bool binary;
        fstr_t msg = fss(wsr_web_socket_read(0x10000, wssr_sf2id(reader_sf), &binary));
        wsr_web_socket_write(msg, binary, wssw_sf2id(writer_sf));
    }}
}

fstr_t serial_method(wsr_method_t method) {
    switch (method) {
    case METHOD_GET: return "GET";
    case METHOD_HEAD: return "HEAD";
    case METHOD_POST: return "POST";
    }
}

static wsr_rsp_t http_echo(wsr_req_t req) {
    list(fstr_t)* li = new_list(fstr_t);
    list_push_end(li, fstr_t, "<!DOCTYPE html><plaintext style='white-space: pre-wrap'>");
    list_push_end(li, fstr_t, concs("Method: ", serial_method(req.method), "\n"));
    list_push_end(li, fstr_t, concs("Path: ", req.path, "\n"));
    list_push_end(li, fstr_t, "\n** Headers:");
    dict_foreach(req.headers, fstr_t, key, value) {
        list_push_end(li, fstr_t, "\n - ");
        list_push_end(li, fstr_t, key);
        list_push_end(li, fstr_t, ": ");
        list_push_end(li, fstr_t, value);
    }
    list_push_end(li, fstr_t, "\n** URL parameters:");
    dict_foreach(req.url_params, fstr_t, key, value) {
        list_push_end(li, fstr_t, "\n - ");
        list_push_end(li, fstr_t, key);
        list_push_end(li, fstr_t, ": ");
        list_push_end(li, fstr_t, value);
    }
    if (req.method == METHOD_POST) {
        list_push_end(li, fstr_t, "\n** POST parameters:");
        dict_foreach(req.post_params, fstr_t, key, value) {
            list_push_end(li, fstr_t, "\n - ");
            list_push_end(li, fstr_t, key);
            list_push_end(li, fstr_t, ": ");
            list_push_end(li, fstr_t, value);
        }
        list_push_end(li, fstr_t, "\n** POST files:");
        dict_foreach(req.post_file_data, wsr_post_file_data_t, key, value) {
            list_push_end(li, fstr_t, "\n - ");
            list_push_end(li, fstr_t, key);
            list_push_end(li, fstr_t, ": ");
            list_push_end(li, fstr_t, value.file_name);
            list_push_end(li, fstr_t, " (");
            list_push_end(li, fstr_t, value.mime_type);
            list_push_end(li, fstr_t, ")");
        }
    }
    list_push_end(li, fstr_t, "\n");
    fstr_mem_t* resp = fstr_implode(li, "");
    return wsr_response_dynamic(HTTP_OK, resp, wsr_mime_html);
}

static wsr_rsp_t http_request_cb(wsr_req_t req, void* cb_arg) {
    if (fstr_equal(req.path, "/") || fstr_equal(req.path, "/prefetch"))
        req.path = "/index.html";
    if (fstr_equal(req.path, "/lol"))
        return wsr_response_static(HTTP_OK, "<h1>this is a lol page</h1>", wsr_mime_txt);
    if (fstr_equal(req.path, "/echo")) {
        if (wsr_req_is_ws_open(req))
            return wsr_response_web_socket(req, ws_echo, "", cb_arg);
        else
            return http_echo(req);
    }
    if (fstr_equal(req.path, "/echo_json"))
        return wsr_response_web_socket(req, ws_echo_json, "", cb_arg);
    if (fstr_equal(req.path, "/chat"))
        return wsr_response_web_socket(req, ws_chat, "", cb_arg);
    return wsr_response_file(req, web_root);
}

void rcd_main(list(fstr_t)* main_args, list(fstr_t)* main_env) {
    fstr_t dir;
    if (!list_unpack(main_args, fstr_t, &dir)) {
        rio_debug("pass a path as first argument\n");
        lwt_exit(1);
    }
    global_heap {
        web_root = fss(rio_file_real_path(dir));
    }
    rcd_fid_t chat_fid;
    fmitosis {
        chat_fid = sfid(spawn_fiber(chat_fiber("")));
    }
    wsr_cfg_t cfg = wsr_default_cfg();
    cfg.bind.port = 8766;
    cfg.req_cb = http_request_cb;
    req_arg_t arg = {
        .chat_fid = chat_fid,
    };
    cfg.cb_arg = &arg;
    wsr_start(cfg);
}
