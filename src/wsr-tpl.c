/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "rcd.h"
#include "linux.h"
#include "wsr-tpl.h"

#pragma librcd

define_eio(wsr_not_cpl);

define_eio(wsr_tpl_invalid);

typedef enum wsr_elem_type {
    WSR_ELEM_STATIC,
    WSR_ELEM_INCLUDE,
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

static wsr_tpl_t* get_tpl_from_file(wsr_tpl_ctx_t* ctx, dict(wsr_tpl_t*)* partials_in, fstr_t tpl_path) ;

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

static wsr_tpl_t* get_compiled_tpl(dict(wsr_tpl_t*)* partials, fstr_t tpl_path) {
    wsr_tpl_t** tpl_ptr = dict_read(partials, wsr_tpl_t*, tpl_path);
    if (tpl_ptr == 0)
        throw_eio(concs("template [", tpl_path, "]not compiled"), wsr_not_cpl);
    return *tpl_ptr;
}

static fstr_t tpl_filename(fstr_t tpl_id) {
    fstr_t filename;
    if (fstr_prefixes(tpl_id, "head@") || fstr_prefixes(tpl_id, "foot@")) {
        if (!fstr_divide(tpl_id, "@", 0, &filename))
            throw_eio(concs("invalid template id [", tpl_id, "]"), wsr_tpl_invalid);
    } else
        filename = tpl_id;
    return filename;
}

static fstr_mem_t* read_tpl_file(wsr_tpl_ctx_t* ctx, fstr_t filename) {
    fstr_t raw_tpl_path = concs(ctx->root_tpl_path, "/", filename);
    if (!rio_file_exists(raw_tpl_path))
        throw_eio(concs("could not find template [", filename, "]"), wsr_tpl_invalid);
    return rio_read_file_contents(raw_tpl_path);
}

static void inner_compile_tpl(wsr_tpl_ctx_t* ctx, dict(wsr_tpl_t*)* partials, fstr_t tpl_id) { sub_heap_txn(heap) {
    typedef struct tpl_part {
        wsr_elem_type_t type;
        union {
            fstr_t id;
            fstr_t html;
        } val;
    } tpl_part_t;
    typedef struct virt_tpl {
        fstr_t id;
        list(tpl_part_t)* parts;
    } virt_tpl_t;
    DBGFN("compiling: [", tpl_id ,"]");
    fstr_t filename = tpl_filename(tpl_id);
    fstr_mem_t* raw_tpl_mem = read_tpl_file(ctx, filename);
    bool expect_wrapper = !fstr_equal(tpl_id, filename);
    bool is_wrapper = false;
    list(fstr_t)* wrapper_stack = new_list(fstr_t);
    // First parse out all wsr-tpl tags so we can tell if this is a wrapper.
    list(tpl_part_t)* parts = new_list(tpl_part_t);
    list(virt_tpl_t)* v_templates = new_list(virt_tpl_t);
    for (fstr_t tpl = fss(raw_tpl_mem), html; fstr_iterate(&tpl, "<{", &html);) {
        if (html.len > 0) {
            tpl_part_t part = {
                .type = WSR_ELEM_STATIC,
                .val.html = html,
            };
            list_push_end(parts, tpl_part_t, part);
        }
        fstr_t tpl_tag;
        if (!fstr_iterate_trim(&tpl, "}>", &tpl_tag))
            break;
        // Dynamic element reference.
        if (fstr_prefixes(tpl_tag, "$")) {
            tpl_part_t part = {
                .type = WSR_ELEM_PARTIAL,
                .val.id = fstr_trim(fstr_sslice(tpl_tag, 1, -1)),
            };
            list_push_end(parts, tpl_part_t, part);
        // Include file as element.
        } else if (fstr_prefixes(tpl_tag, "/")) {
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .val.id = tpl_tag,
            };
            list_push_end(parts, tpl_part_t, part);
        // Begin a new wrapping.
        } else if (fstr_prefixes(tpl_tag, "wrap:")) {
            fstr_t tpl_path;
            fstr_divide(tpl_tag, "wrap:", 0, &tpl_path);
            list_push_end(wrapper_stack, fstr_t, tpl_path);
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .val.id = concs("head@", tpl_path),
            };
            list_push_end(parts, tpl_part_t, part);
        // Finnish a wrapping.
        } else if (fstr_prefixes(tpl_tag, "!wrap")) {
            if (list_count(wrapper_stack, fstr_t) < 1)
                throw_eio(concs("template [,", tpl_id, "] contains invalid <{!wrap}>"), wsr_tpl_invalid);
            fstr_t wrapper_id = list_pop_end(wrapper_stack, fstr_t);
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .val.id = concs("foot@", wrapper_id),
            };
            list_push_end(parts, tpl_part_t, part);
        // This template defines a wrapper, we are now done building the header,
        // start building the footer.
        } else if (fstr_equal(tpl_tag, "wrap_content")) {
            if (is_wrapper)
                throw_eio(concs("template [,", tpl_id, "] contains more than one <{wrap_content}>"), wsr_tpl_invalid);
            is_wrapper = true;
            // Everything until now was the header.
            virt_tpl_t header = {
                .id = concs("head@", filename),
                .parts = parts,
            };
            list_push_end(v_templates, virt_tpl_t, header);
            parts = new_list(tpl_part_t);
        } else {
            throw_eio(concs("did not understand tpl tag [", tpl_tag, "]"), wsr_tpl_invalid);
        }
    }
    if (expect_wrapper && !is_wrapper)
        throw_eio(concs("expected wrapper template in [", filename, "]"), wsr_tpl_invalid);
    fstr_t last_tpl_id = is_wrapper? concs("foot@", filename): filename;
    virt_tpl_t tpl = {
        .id = last_tpl_id,
        .parts = parts,
    };
    list_push_end(v_templates, virt_tpl_t, tpl);
    // Time to build element-trees for all templates in file.
    list_foreach(v_templates, virt_tpl_t, v_tpl) {
        list(wsr_elem_t)* elems = new_list(wsr_elem_t);
        list_foreach(v_tpl.parts, tpl_part_t, part) {
            switch (part.type) {{
            } case WSR_ELEM_STATIC: {
                wsr_elem_t elem = {
                    .type = part.type,
                    .val.html = part.val.html,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_PARTIAL: {
                wsr_elem_t elem = {
                    .type = part.type,
                    .val.partial_key = part.val.id,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_INCLUDE: {
                wsr_tpl_t* tpl;
                switch_heap (heap) {
                    tpl = get_tpl_from_file(ctx, partials, part.val.id);
                }
                wsr_elem_t elem = {
                    .type = WSR_ELEM_INCLUDE,
                    .val.tpl = tpl,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            }}
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
            /// Insert all tags this file declares.
            DBGFN("inserting tpl [", v_tpl.id,"]");
            (void)dict_insert(partials, wsr_tpl_t*, v_tpl.id, tpl);
        }
    }
}}

static void compile_tpl_file(wsr_tpl_ctx_t* ctx, dict(wsr_tpl_t*)* partials, fstr_t tpl_path) {
    try {
        (void) get_compiled_tpl(partials, tpl_path);
    } catch_eio(wsr_not_cpl, e){
        inner_compile_tpl(ctx, partials, tpl_path);
    }
}

static wsr_tpl_t* get_tpl_from_file(wsr_tpl_ctx_t* ctx, dict(wsr_tpl_t*)* partials_in, fstr_t tpl_path) {
    dict(wsr_tpl_t*)* partials = partials_in;
    if (partials == 0)
        partials = (ctx->precompile)? ctx->precompiled_partials: new_dict(wsr_tpl_t*);
    compile_tpl_file(ctx, partials, tpl_path);
    return get_compiled_tpl(partials, tpl_path);
}

static void tpl_execute(wsr_tpl_ctx_t* ctx, wsr_tpl_t* tpl, dict(html_t*)* partials, html_t* buf, fstr_t tpl_path) {
    for (size_t i = 0; i < tpl->n_elems; i++) {
        wsr_elem_t elem = tpl->elems[i];
        switch (elem.type) {{
        } case WSR_ELEM_STATIC: {
            html_append(elem.val.html, buf);
            break;
        } case WSR_ELEM_INCLUDE: {
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
    wsr_tpl_t* template = ctx->precompile? get_compiled_tpl(ctx->precompiled_partials, tpl_path): get_tpl_from_file(ctx, 0, tpl_path);
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
            compile_tpl_file(ctx, ctx->precompiled_partials, tpl_rel_path);
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
