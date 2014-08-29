/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "rcd.h"
#include "linux.h"
#include "wsr-tpl.h"

#pragma librcd

typedef enum wsr_elem_type {
    WSR_ELEM_HTML,
    WSR_ELEM_TPL,
    WSR_ELEM_PARTIAL,
} wsr_elem_type_t;

typedef struct wsr_elem {
    wsr_elem_type_t type;
    union {
        fstr_t html;
        struct wsr_tpl* tpl;
        fstr_t partial_key;
    } val;
} wsr_elem_t;

typedef struct wsr_tpl {
    size_t n_elems;
    wsr_elem_t elems[];
} wsr_tpl_t;

struct html {
    wsr_tpl_ctx_t* ctx;
    size_t n_cap;
    size_t n_total;
    struct iovec* iov;
};

static size_t trq_iovcap_hint = 0x1;

static wsr_tpl_t* compile_tpl(wsr_tpl_ctx_t* ctx, fstr_t tpl_path);

static void html_append_iov(struct iovec iov, html_t* buf) {
    if (iov.iov_len == 0)
        return;
    assert(buf->n_total <= buf->n_cap);
    if (buf->n_total >= buf->n_cap) {
        size_t alloc_size;
        size_t new_cap = MAX(buf->n_cap * 2, trq_iovcap_hint);
        trq_iovcap_hint = new_cap;
        struct iovec* new_iov = lwt_alloc_buffer(new_cap * sizeof(struct iovec), &alloc_size);
        memcpy(new_iov, buf->iov, buf->n_total * sizeof(struct iovec));
        buf->n_cap = alloc_size / sizeof(struct iovec);
        buf->iov = new_iov;
    }
    buf->iov[buf->n_total] = iov;
    buf->n_total++;
}

static inline void html_append(fstr_t chunk, html_t* buf) {
    struct iovec iov = {.iov_base = chunk.str, .iov_len = chunk.len};
    html_append_iov(iov, buf);
}

html_t* wsr_html_raw(fstr_t raw_html) {
    html_t* buf = wsr_tpl_start();
    html_append(raw_html, buf);
    return buf;
}

html_t* wsr_html_conc(size_t n_html, html_t* htmls) {
    html_t* buf = wsr_tpl_start();
    for (size_t i = 0; i < n_html; i++) {
        for (size_t j = 0; j < htmls[i].n_total; j++)
            html_append_iov(htmls[i].iov[j], buf);
    }
    return buf;
}

html_t* wsr_html_implode(list(html_t*)* htmls) {
    html_t* buf = wsr_tpl_start();
    list_foreach(htmls, html_t*, html) {
        assert(html != 0);
        for (size_t j = 0; j < html->n_total; j++)
            html_append_iov(html->iov[j], buf);
    }
    return buf;
}

html_t* wsr_html_escape(fstr_t str) {
    html_t* buf = wsr_tpl_start();
    size_t raw_i = 0;
    for (size_t i = 0; i < str.len; i++) {
        fstr_t quote = "";
        switch (str.str[i]) {{
        } case '&': {
            quote = "&amp;";
            break;
        } case '\"': {
            quote = "&quot;";
            break;
        } case '\'': {
            quote = "&apos;";
            break;
        } case '<': {
            quote = "&lt;";
            break;
        } case '>': {
            quote = "&gt;";
            break;
        } default: {
            break;
        }}
        if (quote.len > 0) {
            html_append(fstr_slice(str, raw_i, i), buf);
            html_append(quote, buf);
            raw_i = i + 1;
        }
    }
    html_append(fstr_slice(str, raw_i, str.len), buf);
    return buf;
}

static wsr_tpl_t* get_precompiled_tpl(wsr_tpl_ctx_t* ctx, fstr_t tpl_path) {
    wsr_tpl_t** prepared_tpl_ptr = dict_read(ctx->precompiled_partials, wsr_tpl_t*, tpl_path);
    if (prepared_tpl_ptr == 0)
        throw(concs("template [", tpl_path, "]not compiled"), exception_arg);
    return *prepared_tpl_ptr;
}

static wsr_tpl_t* inner_compile_tpl(wsr_tpl_ctx_t* ctx, fstr_t tpl_path) { sub_heap_txn(heap) {
    DBGFN("compiling: [", tpl_path ,"]");
    fstr_t raw_tpl_path = concs(ctx->root_tpl_path, "/", tpl_path);
    if (!rio_file_exists(raw_tpl_path))
        throw(concs("could not find template [", tpl_path, "]"), exception_arg);
    fstr_mem_t* raw_tpl_mem = rio_read_file_contents(raw_tpl_path);
    list(wsr_elem_t)* elems = new_list(wsr_elem_t);
    for (fstr_t tpl = fss(raw_tpl_mem), html; fstr_iterate(&tpl, "<{", &html);) {
        if (html.len > 0) {
            wsr_elem_t elem = {
                .type = WSR_ELEM_HTML,
                .val.html = html,
            };
            list_push_end(elems, wsr_elem_t, elem);
        }
        fstr_t tpl_tag;
        if (!fstr_iterate_trim(&tpl, "}>", &tpl_tag))
            break;
        fstr_t prefix = fstr_slice(tpl_tag, 0, 1);
        if (fstr_equal(prefix, "$")) {
            wsr_elem_t elem = {
                .type = WSR_ELEM_PARTIAL,
                .val.partial_key = fstr_trim(fstr_sslice(tpl_tag, 1, -1)),
            };
            list_push_end(elems, wsr_elem_t, elem);
        } else if (fstr_equal(prefix, "/")) {
            wsr_tpl_t* tpl;
            switch_heap (heap) {
                tpl = compile_tpl(ctx, tpl_tag);
            }
            wsr_elem_t elem = {
                .type = WSR_ELEM_TPL,
                .val.tpl = tpl,
            };
            list_push_end(elems, wsr_elem_t, elem);
        } else {
            throw(concs("did not understand tpl tag [", tpl_tag, "]"), exception_arg);
        }
    }
    switch_heap (heap) {
        import_list(raw_tpl_mem);
        size_t n_elems = list_count(elems, wsr_elem_t);
        wsr_tpl_t* tpl = lwt_alloc_new(sizeof(wsr_tpl_t) + sizeof(wsr_elem_t) * n_elems);
        tpl->n_elems = n_elems;
        size_t i = 0;
        list_foreach(elems, wsr_elem_t, elem) {
            tpl->elems[i] = elem;
            i++;
        }
        return tpl;
    }
}}

static wsr_tpl_t* compile_tpl(wsr_tpl_ctx_t* ctx, fstr_t tpl_path) {
    wsr_tpl_t* tpl = 0;
    if (ctx->precompile) {
        try {
            tpl = get_precompiled_tpl(ctx, tpl_path);
        } catch(exception_arg, e){
            tpl = inner_compile_tpl(ctx, tpl_path);
            (void)dict_insert(ctx->precompiled_partials, wsr_tpl_t*, tpl_path, tpl);
        }
    } else {
        tpl = inner_compile_tpl(ctx, tpl_path);
    }
    return tpl;
}

static void tpl_execute(wsr_tpl_ctx_t* ctx, wsr_tpl_t* tpl, dict(html_t*)* partials, html_t* buf, fstr_t tpl_path) {
    for (size_t i = 0; i < tpl->n_elems; i++) {
        wsr_elem_t elem = tpl->elems[i];
        switch (elem.type) {{
        } case WSR_ELEM_HTML: {
            html_append(elem.val.html, buf);
            break;
        } case WSR_ELEM_TPL: {
            tpl_execute(ctx, elem.val.tpl, partials, buf, tpl_path);
            break;
        } case WSR_ELEM_PARTIAL: {
            fstr_t key = elem.val.partial_key;
            html_t** partial_ptr = dict_read(partials, html_t*, key);
            if (partial_ptr == 0) {
                if (!ctx->strict)
                    break;
                throw(concs("in tpl [", tpl_path,"], invalid partial key [", key, "]"), exception_arg);
            }
            html_t* partial = *partial_ptr;
            for (size_t i = 0; i < partial->n_total; i++)
                html_append_iov(partial->iov[i], buf);
            break;
        }}
    }
}

void wsr_tpl_render(wsr_tpl_ctx_t* ctx, fstr_t tpl_path, dict(html_t*)* partials, html_t* buf) {
    wsr_tpl_t* template = ctx->precompile? get_precompiled_tpl(ctx, tpl_path): compile_tpl(ctx, tpl_path);
    tpl_execute(ctx, template, partials, buf, tpl_path);
}

html_t* wsr_tpl_start() {
    size_t alloc_size;
    html_t* trb = lwt_alloc_buffer(sizeof(html_t) + trq_iovcap_hint * sizeof(struct iovec), &alloc_size);
    trb->n_cap = (alloc_size - sizeof(html_t)) / sizeof(struct iovec);
    trb->n_total = 0;
    trb->iov = ((void*) trb) + sizeof(html_t);
    return trb;
}

size_t wsr_tpl_length(html_t* html) {
    size_t len = 0;
    for (size_t i = 0; i < html->n_total; i++)
        len += html->iov[i].iov_len;
    return len;
}

void wsr_tpl_writev(rio_t* write_h, html_t* html) {
    size_t n_left = html->n_total;
    struct iovec* iov = html->iov;
    int32_t fd = rio_get_fd_write(write_h);
    while (n_left > 0) {
        ssize_t writev_r = writev(fd, iov, MIN(n_left, IOV_MAX));
        if (writev_r == -1) {
            int32_t err = errno;
            if (err == EWOULDBLOCK) {
                lwt_block_until_edge_level_io_event(fd, lwt_fd_event_write);
            } else if (err != EINTR) {
                RCD_SYSCALL_EXCEPTION(writev, exception_io);
            }
            continue;
        }
        while (n_left > 0) {
            if (iov->iov_len <= writev_r) {
                writev_r -= iov->iov_len;
                iov->iov_len = 0;
                n_left--;
                iov++;
            } else {
                iov->iov_len -= writev_r;
                iov->iov_base += writev_r;
                break;
            }
        }
    }
}

static void compile_templates_at(wsr_tpl_ctx_t* ctx, fstr_t tpl_rel_path) { sub_heap_txn(heap){
    fstr_t abs_path = concs(ctx->root_tpl_path, tpl_rel_path);
    rio_stat_t p_stat = rio_file_lstat(abs_path);
    switch(p_stat.file_type) {{
    } case rio_file_type_directory: {
        list(fstr_mem_t*)* sub_paths = rio_file_list(abs_path);
        list_foreach(sub_paths, fstr_mem_t*, sub_path_mem) {
            switch_heap(heap) {
                fstr_t next_rel_path = concs(tpl_rel_path, "/", fss(sub_path_mem));
                compile_templates_at(ctx, next_rel_path);
            }
        }
        break;
    } case rio_file_type_regular: {
        switch_heap(heap) {
            compile_tpl(ctx, tpl_rel_path);
        }
        break;
    } default: {
        break;
    }}
}}

wsr_tpl_ctx_t* wsr_tpl_init(fstr_t root_tpl_path, bool precompile, bool strict) {
    wsr_tpl_ctx_t* ctx = new(wsr_tpl_ctx_t);
    ctx->root_tpl_path = fsc(root_tpl_path);
    ctx->strict = strict;
    ctx->precompile = precompile;
    if (precompile) {
        ctx->precompiled_partials = new_dict(wsr_tpl_t*);
        compile_templates_at(ctx, "");
    }
    return ctx;
}
