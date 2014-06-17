#include "rcd.h"
#include "wsr.h"
#include "wsr-mime.h"

#pragma librcd

typedef struct chat_participant {
    fstr_t name;
    rcd_fid_t writer_fid;
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

join_locked(uint64_t) chat_connect(fstr_t name, rcd_fid_t writer_fid, join_server_params, chat_t* chat) { server_heap_flip {
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

static void ws_chat(rio_in_addr4_t peer, rcd_fid_t reader_fid, rcd_fid_t writer_fid, void* cb_arg) {
    req_arg_t* req_arg = cb_arg;
    rcd_fid_t chat_fid = req_arg->chat_fid;
    fstr_t name = fss(wsr_web_socket_read(0x100, reader_fid, 0));
    fstr_t fiber_name = fss(rio_serial_in_addr4(peer));
    uint64_t my_id = chat_connect(name, writer_fid, chat_fid);
    try {
        for (;;) sub_heap {
            bool binary;
            fstr_t msg = fss(wsr_web_socket_read(0x1000, reader_fid, &binary));
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

static void ws_echo(rio_in_addr4_t peer, rcd_fid_t reader_fid, rcd_fid_t writer_fid, void* cb_arg) {
    for (;;) { sub_heap {
        bool binary;
        fstr_t msg = fss(wsr_web_socket_read(0x10000, reader_fid, &binary));
        wsr_web_socket_write(msg, binary, writer_fid);
    }}
}

static wsr_rsp_t http_request_cb(wsr_req_t req, void* cb_arg) {
    if (fstr_equal(req.path, "/") || fstr_equal(req.path, "/prefetch"))
        req.path = "/index.html";
    if (fstr_equal(req.path, "/lol"))
        return wsr_response_static(HTTP_OK, "<h1>this is a lol page</h1>", wsr_mime_txt);
    if (fstr_equal(req.path, "/echo"))
        return wsr_response_web_socket(req, ws_echo, "", cb_arg);
    if (fstr_equal(req.path, "/chat"))
        return wsr_response_web_socket(req, ws_chat, "", cb_arg);
    return wsr_response_file(req, "/home/simon/p/hello/build");
}

void rcd_main(list(fstr_t)* main_args, list(fstr_t)* main_env) {
    rcd_fid_t chat_fid;
    fmitosis {
        chat_fid = sfid(spawn_fiber(chat_fiber("")));
    }
    wsr_cfg_t cfg = wsr_default_cfg();
    cfg.bind.port = 8765;
    cfg.req_cb = http_request_cb;
    req_arg_t arg = {
        .chat_fid = chat_fid,
    };
    cfg.cb_arg = &arg;
    wsr_start(cfg);
}
