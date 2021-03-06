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
    WSR_ELEM_INLINE,
    WSR_ELEM_PRINT,
    WSR_ELEM_PRINT_RAW,
    WSR_ELEM_PRINT_JSON,
    WSR_ELEM_IF,
    WSR_ELEM_FOREACH,
    WSR_ELEM_SET,
    WSR_ELEM_CALL,
} wsr_elem_type_t;

typedef struct wsr_elem {
    wsr_elem_type_t type;
    fstr_t html;
    struct wsr_tpl* tpl;
    struct wsr_tpl* tpl_else;
    fstr_t partial_key;
    fstr_t jkey_get;
    fstr_t jkey_setk;
    fstr_t jkey_setv;
    bool json_encode;
    bool has_jval;
    json_value_t jval;
    tpl_cb_t tpl_cb;
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

/// Takes raw json and encodes it as "script json", i.e. json that is safe to
/// print in a <script> tag anywhere generating a single unambiguous expression
/// that is valid Javascript affecting HTML5 parsing while preserving the exact
/// semantic meaning of the JSON expression in Javascript.
/// This also requires the function to escape certain Unicode characters that are
/// valid in JSON but not valid in Javascript.
fstr_mem_t* wsr_json_script_escape(fstr_t raw_json) { sub_heap {
    list(fstr_t)* toks = new_list(fstr_t, "(");
    for (;;) {
        fstr_t ok_json, replace;
        do {{
            fstr_t json_left = raw_json;
            #pragma re2c(raw_json): \
                  ^ (.*) {ok_json} </ {@escape_script} \
                | ^ (.*) {ok_json} <! {@data_double_escape} \
                | ^ (.*) {ok_json} -> {@escape_comment} \
                | ^ (.*) {ok_json} [\xe2][\x80][\xa8] {@uc_line_separator} \
                | ^ (.*) {ok_json} [\xe2][\x80][\xa9] {@uc_paragraph_separator}
            ok_json = json_left;
            replace = "";
            break;
        } escape_script: {
            // Stops escaping the <script> tag.
            replace = "<\\/";
            break;
        } data_double_escape: {
            // Stops escaping the <script> tag using the obscure HTML "script data double escaped state".
            replace = "<\\!";
            break;
        } escape_comment: {
            // Stops escaping the script if it's <!-- commented out -->.
            replace = "-\\>";
            break;
        } uc_line_separator: {
            // The "line separator" (U+2028) character is not valid Javascript.
            replace = "\\u2028";
            break;
        } uc_paragraph_separator: {
            // The "paragraph separator" (U+2029) character is not valid Javascript.
            replace = "\\u2029";
            break;
        }} while (false);
        list_push_end(toks, fstr_t, ok_json);
        if (replace.len == 0)
            break;
        list_push_end(toks, fstr_t, replace);
    }
    list_push_end(toks, fstr_t, ")");
    return escape(fstr_implode(toks, ""));
}}

static wsr_tpl_t* get_compiled_tpl(dict(wsr_tpl_t*)* partials, fstr_t tpl_path) {
    wsr_tpl_t** tpl_ptr = dict_read(partials, wsr_tpl_t*, tpl_path);
    if (tpl_ptr == 0)
        throw_eio(concs("template [", tpl_path, "] not compiled"), wsr_not_cpl);
    return *tpl_ptr;
}

static fstr_t tpl_filename(fstr_t tpl_id, bool* out_expect_wrapper) {
    if (fstr_prefixes(tpl_id, "head@") || fstr_prefixes(tpl_id, "foot@")) {
        fstr_t file_name;
        if (!fstr_divide(tpl_id, "@", 0, &file_name))
            throw_eio(concs("invalid template id [", tpl_id, "]"), wsr_tpl_invalid);
        *out_expect_wrapper = true;
        return file_name;
    } else {
        *out_expect_wrapper = false;
        return tpl_id;
    }
}

static fstr_mem_t* read_tpl_file(wsr_tpl_ctx_t* ctx, fstr_t filename) {
    fstr_t raw_tpl_path = concs(ctx->root_tpl_path, "/", filename);
    if (!rio_file_exists(raw_tpl_path))
        throw_eio(concs("could not find template [", filename, "]"), wsr_tpl_invalid);
    return rio_read_file_contents(raw_tpl_path);
}

static void throw_invalid_tag_info(fstr_t tpl_id, fstr_t tpl_tag, fstr_t info) {
    throw_eio(concs("template [,", tpl_id, "] contains invalid \"{", tpl_tag, "}\"", (info.len > 0? " ": ""), info), wsr_tpl_invalid);
}

static void throw_invalid_tag(fstr_t tpl_id, fstr_t tpl_tag) {
    return throw_invalid_tag_info(tpl_id, tpl_tag, "");
}

typedef struct tpl_part {
    wsr_elem_type_t type;
    fstr_t html;
    fstr_t tpl_path;
    fstr_t partial_key;
    fstr_t jkey_get;
    fstr_t jkey_setk;
    fstr_t jkey_setv;
    bool has_jval;
    json_value_t jval;
    tpl_cb_t tpl_cb;
    struct virt_tpl* virt_tpl;
    struct virt_tpl* virt_tpl2;
} tpl_part_t;

typedef struct virt_tpl {
    fstr_t id;
    list(tpl_part_t)* parts;
    wsr_tpl_t* real_tpl;
} virt_tpl_t;

static void inner_compile_tpl(wsr_tpl_ctx_t* ctx, dict(wsr_tpl_t*)* partials, fstr_t tpl_id) { sub_heap_txn(heap) {
    typedef enum {
        STACKED_WRAP,
        STACKED_INLINE,
        STACKED_IF,
        STACKED_FOREACH,
    } stack_class_t;
    typedef struct {
        stack_class_t class;
        union {
            struct {
                fstr_t tpl_path;
            } wrap;
            struct {
                fstr_t partial_key;
                list(tpl_part_t)* prev_parts;
            } inl;
            struct {
                fstr_t jkey_get;
                fstr_t jkey_setk;
                fstr_t jkey_setv;
                list(tpl_part_t)* prev_parts;
            } fore;
            struct {
                fstr_t partial_key;
                fstr_t jkey_get;
                bool has_jval;
                json_value_t jval;
                list(tpl_part_t)* prev_parts;
                struct virt_tpl* pre_else_vt;
            } ife;
        };
    } stack_elem_t;
    DBGFN("compiling: [", tpl_id ,"]");
    bool expect_wrapper;
    fstr_t tpl_file_name = tpl_filename(tpl_id, &expect_wrapper);
    fstr_mem_t* raw_tpl_mem = read_tpl_file(ctx, tpl_file_name);
    bool is_wrapper = false;
    list(stack_elem_t)* wrapper_stack = new_list(stack_elem_t);
    // First parse out all wsr-tpl tags so we can tell if this is a wrapper.
    list(tpl_part_t)* parts = new_list(tpl_part_t);
    list(virt_tpl_t*)* v_templates = new_list(virt_tpl_t*);
    for (fstr_t tpl = fss(raw_tpl_mem);;) {
        fstr_t html, tpl_tag;
        {
            fstr_t tpl_tail = tpl;
            #pragma re2c(tpl): \
                  ^ (.*){html} [\{]      ([\.!\$@/#]+ [^\{\}]+){tpl_tag}      [\}] {@m_start_tag} \
                | ^ (.*){html} [\{] [\|] ([\.!\$@/#]+ .+      ){tpl_tag} [\|] [\}] {@m_start_tag}
            html = tpl_tail;
            tpl_tag = "";
            m_start_tag:;
        }
        if (html.len > 0) {
            tpl_part_t part = {
                .type = WSR_ELEM_STATIC,
                .html = html,
            };
            list_push_end(parts, tpl_part_t, part);
        }
        if (tpl_tag.len == 0)
            break;
        // Comment.
        if (fstr_prefixes(tpl_tag, "#")) {
            continue;
        // Dynamic partial reference.
        } else if (fstr_prefixes(tpl_tag, "$")) {
            tpl_part_t part = {
                .type = WSR_ELEM_PARTIAL,
                .partial_key = fstr_trim(fstr_slice(tpl_tag, 1, -1)),
            };
            list_push_end(parts, tpl_part_t, part);
        // Dynamic jdata reference.
        } else if (fstr_prefixes(tpl_tag, "@")) {
            tpl_part_t part;
            fstr_t raw_suffix = "|raw";
            fstr_t json_suffix = "|script-json";
            if (fstr_suffixes(tpl_tag, raw_suffix)) {
                part = (tpl_part_t) {
                    .type = WSR_ELEM_PRINT_RAW,
                    .jkey_get = fstr_trim(fstr_slice(tpl_tag, 1, -raw_suffix.len - 1)),
                };
            } else if (fstr_suffixes(tpl_tag, json_suffix)) {
                // JSON that is only safe to use inside <script> tags.
                part = (tpl_part_t) {
                    .type = WSR_ELEM_PRINT_JSON,
                    .jkey_get = fstr_trim(fstr_slice(tpl_tag, 1, -json_suffix.len - 1)),
                };
            } else {
                part = (tpl_part_t) {
                    .type = WSR_ELEM_PRINT,
                    .jkey_get = fstr_trim(fstr_slice(tpl_tag, 1, -1)),
                };
            }
            list_push_end(parts, tpl_part_t, part);
        // Include file as element.
        } else if (fstr_prefixes(tpl_tag, "/")) {
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .tpl_path = tpl_tag,
            };
            list_push_end(parts, tpl_part_t, part);
        // Begin a new wrapping.
        } else if (fstr_prefixes(tpl_tag, ".wrap:")) {
            fstr_t tpl_path;
            fstr_divide(tpl_tag, ".wrap:", 0, &tpl_path);
            stack_elem_t se = {.class = STACKED_WRAP, .wrap.tpl_path = tpl_path};
            list_push_end(wrapper_stack, stack_elem_t, se);
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .tpl_path = concs("head@", tpl_path),
            };
            list_push_end(parts, tpl_part_t, part);
        // Finnish a wrapping.
        } else if (fstr_equal(tpl_tag, "!wrap")) {
            if (list_count(wrapper_stack, stack_elem_t) < 1)
                throw_invalid_tag(tpl_id, tpl_tag);
            stack_elem_t se = list_pop_end(wrapper_stack, stack_elem_t);
            if (se.class != STACKED_WRAP)
                throw_invalid_tag(tpl_id, tpl_tag);
            tpl_part_t part = {
                .type = WSR_ELEM_INCLUDE,
                .tpl_path = concs("foot@", se.wrap.tpl_path),
            };
            list_push_end(parts, tpl_part_t, part);
        // This template defines a wrapper, we are now done building the
        // header, start building the footer.
        } else if (fstr_equal(tpl_tag, ".wrap_content")) {
            if (is_wrapper)
                throw_eio(concs("template [,", tpl_id, "] contains more than one <{wrap_content}>"), wsr_tpl_invalid);
            is_wrapper = true;
            // Everything until now was the header.
            virt_tpl_t header = {
                .id = concs("head@", tpl_file_name),
                .parts = parts,
            };
            list_push_end(v_templates, virt_tpl_t*, cln(&header));
            parts = new_list(tpl_part_t);
        // Begin an inline partial.
        } else if (fstr_prefixes(tpl_tag, ".inline:$")) {
            fstr_t partial_key;
            fstr_divide(tpl_tag, ".inline:$", 0, &partial_key);
            // Stack new parts context.
            stack_elem_t se = {.class = STACKED_INLINE, .inl.partial_key = partial_key, .inl.prev_parts = parts};
            list_push_end(wrapper_stack, stack_elem_t, se);
            parts = new_list(tpl_part_t);
        // Finish the inline partial.
        } else if (fstr_equal(tpl_tag, "!inline")) {
            if (list_count(wrapper_stack, stack_elem_t) < 1)
                throw_invalid_tag(tpl_id, tpl_tag);
            stack_elem_t se = list_pop_end(wrapper_stack, stack_elem_t);
            if (se.class != STACKED_INLINE)
                throw_invalid_tag(tpl_id, tpl_tag);
            // Add the inline partial as a virtual template.
            virt_tpl_t* v_tpl = new(virt_tpl_t);
            v_tpl->id = "";
            v_tpl->parts = parts;
            v_tpl->real_tpl = 0;
            list_push_end(v_templates, virt_tpl_t*, v_tpl);
            // Pop the parts context.
            parts = se.inl.prev_parts;
            // Add the inline template part that refers to the corresponding v template.
            tpl_part_t part = {
                .type = WSR_ELEM_INLINE,
                .partial_key = se.inl.partial_key,
                .virt_tpl = v_tpl,
            };
            list_push_end(parts, tpl_part_t, part);
        // Begin an if.
        } else if (fstr_prefixes(tpl_tag, ".if:")) {
            fstr_t if_args;
            fstr_divide(tpl_tag, ".if:", 0, &if_args);
            stack_elem_t se = {.class = STACKED_IF, .ife.pre_else_vt = 0};
            fstr_t var_arg, cmp_arg;
            if (fstr_divide(if_args, ":", &var_arg, &cmp_arg)) {
                // Have if comparison argument.
                se.ife.has_jval = true;
                fstr_t ns_hint = fstr_slice(cmp_arg, 0, 1);
                if (fstr_equal(ns_hint, "@")) {
                    // Wrap reference in array.
                    se.ife.jval = jarr_new(jstr(fstr_slice(cmp_arg, 1, -1)));
                } else {
                    // Static value.
                    try {
                        se.ife.jval = json_parse(cmp_arg)->value;
                    } catch_eio (json_parse, e, ev) {
                        throw_eio_fwd(concs("failed to parse if cmp expr [", cmp_arg, "]"), wsr_tpl_invalid, e);
                    }
                    if (se.ife.jval.type == JSON_ARRAY || se.ife.jval.type == JSON_OBJECT)
                        throw_eio("comparing with array or object type is unsupported", wsr_tpl_invalid);
                }
            } else {
                // Have no comparison argument. Pure truthy check.
                se.ife.has_jval = false;
                var_arg = if_args;
            }
            fstr_t ns_hint = fstr_slice(var_arg, 0, 1);
            if (fstr_equal(ns_hint, "$")) {
                se.ife.partial_key = fstr_slice(var_arg, 1, -1);
                if (se.ife.has_jval)
                    throw_eio("comparing partials with literal value is unsupported", wsr_tpl_invalid);
            } else if (fstr_equal(ns_hint, "@")) {
                se.ife.jkey_get = fstr_slice(var_arg, 1, -1);
            } else {
                throw_eio(concs("missing ns hint in if expr [", tpl_tag, "]"), wsr_tpl_invalid);
            }
            // Stack new if context.
            se.ife.prev_parts = parts;
            list_push_end(wrapper_stack, stack_elem_t, se);
            parts = new_list(tpl_part_t);
        // Begin an else or end if.
        } else if (fstr_equal(tpl_tag, ".else") || fstr_prefixes(tpl_tag, "!if")) {
            if (list_count(wrapper_stack, stack_elem_t) < 1)
                throw_invalid_tag(tpl_id, tpl_tag);
            stack_elem_t se = list_pop_end(wrapper_stack, stack_elem_t);
            if (se.class != STACKED_IF)
                throw_invalid_tag(tpl_id, tpl_tag);
            bool is_else = fstr_equal(tpl_tag, ".else");
            if (is_else && se.ife.pre_else_vt != 0)
                throw_eio(concs("duplicate else"), wsr_tpl_invalid);
            // Add the if branch as a virtual template.
            virt_tpl_t* v_tpl = new(virt_tpl_t);
            v_tpl->id = "";
            v_tpl->parts = parts;
            v_tpl->real_tpl = 0;
            list_push_end(v_templates, virt_tpl_t*, v_tpl);
            if (is_else) {
                // Stack new if context.
                se.ife.pre_else_vt = v_tpl;
                list_push_end(wrapper_stack, stack_elem_t, se);
                parts = new_list(tpl_part_t);
            } else {
                // Pop the parts context.
                parts = se.ife.prev_parts;
                // Add the if template part that refers to the corresponding v template.
                tpl_part_t part = {
                    .type = WSR_ELEM_IF,
                    .partial_key = se.ife.partial_key,
                    .jkey_get = se.ife.jkey_get,
                    .has_jval = se.ife.has_jval,
                    .jval = se.ife.jval,
                    .virt_tpl = (se.ife.pre_else_vt != 0? se.ife.pre_else_vt: v_tpl),
                    .virt_tpl2 = (se.ife.pre_else_vt != 0? v_tpl: 0),
                };
                list_push_end(parts, tpl_part_t, part);
            }
        // Begin a foreach.
        } else if (fstr_prefixes(tpl_tag, ".foreach:@")) {
            fstr_t foreach_args;
            fstr_divide(tpl_tag, ".foreach:@", 0, &foreach_args);
            fstr_t jkey_get, jkey_set_args;
            if (!fstr_divide(foreach_args, ":@", &jkey_get, &jkey_set_args))
                throw_eio(concs("invalid tpl tag foreach syntax [", tpl_tag, "]"), wsr_tpl_invalid);
            fstr_t jkey_setk, jkey_setv;
            if (!fstr_divide(jkey_set_args, ":@", &jkey_setk, &jkey_setv)) {
                jkey_setk = "";
                jkey_setv = jkey_set_args;
            }
            // Stack new parts context.
            stack_elem_t se = {
                .class = STACKED_FOREACH,
                .fore.jkey_get = jkey_get,
                .fore.jkey_setk = jkey_setk,
                .fore.jkey_setv = jkey_setv,
                .fore.prev_parts = parts,
            };
            list_push_end(wrapper_stack, stack_elem_t, se);
            parts = new_list(tpl_part_t);
        // End the foreach.
        } else if (fstr_equal(tpl_tag, "!foreach")) {
            if (list_count(wrapper_stack, stack_elem_t) < 1)
                throw_invalid_tag(tpl_id, tpl_tag);
            stack_elem_t se = list_pop_end(wrapper_stack, stack_elem_t);
            if (se.class != STACKED_FOREACH)
                throw_invalid_tag(tpl_id, tpl_tag);
            // Add the foreach partial as a virtual template.
            virt_tpl_t* v_tpl = new(virt_tpl_t);
            v_tpl->id = "";
            v_tpl->parts = parts;
            v_tpl->real_tpl = 0;
            list_push_end(v_templates, virt_tpl_t*, v_tpl);
            // Pop the parts context.
            parts = se.fore.prev_parts;
            // Add the foreach template part that refers to the corresponding v template.
            tpl_part_t part = {
                .type = WSR_ELEM_FOREACH,
                .jkey_get = se.fore.jkey_get,
                .jkey_setk = se.fore.jkey_setk,
                .jkey_setv = se.fore.jkey_setv,
                .virt_tpl = v_tpl,
            };
            list_push_end(parts, tpl_part_t, part);
        // Begin a template set request.
        // This statement is useful to pass data into includes which allows
        // includes to work like functions that render HTML dynamically.
        } else if (fstr_prefixes(tpl_tag, ".set:@")) {
            fstr_t set_tag_args;
            fstr_divide(tpl_tag, ".set:@", 0, &set_tag_args);
            fstr_t jkey_setk, getv;
            if (!fstr_divide(set_tag_args, ":", &jkey_setk, &getv))
                throw_invalid_tag(tpl_id, tpl_tag);
            bool has_jval;
            fstr_t jkey_get;
            json_value_t jval;
            if (fstr_prefixes(getv, "@")) {
                has_jval = false;
                fstr_divide(getv, "@", 0, &jkey_get);
            } else {
                has_jval = true;
                try {
                    jval = json_parse(getv)->value;
                } catch_eio (json_parse, e, ev) {
                    throw_eio_fwd(concs("failed to parse set expr [", getv, "]"), wsr_tpl_invalid, e);
                }
            }
            // Add the callback.
            tpl_part_t part = {
                .type = WSR_ELEM_SET,
                .jkey_get = jkey_get,
                .jkey_setk = jkey_setk,
                .has_jval = has_jval,
                .jval = jval,
            };
            list_push_end(parts, tpl_part_t, part);
        // Begin a template callback request.
        // This statement is useful to allow the template to request the data it
        // needs to render allowing vastly less context to read and understand them.
        } else if (fstr_prefixes(tpl_tag, ".call:")) {
            fstr_t call_tag_args;
            fstr_divide(tpl_tag, ".call:", 0, &call_tag_args);
            fstr_t result_jkey, call_fn_arg;
            if (!fstr_divide(call_tag_args, ":", &result_jkey, &call_fn_arg))
                throw_invalid_tag(tpl_id, tpl_tag);
            if (result_jkey.len > 0) {
                if (!fstr_prefixes(result_jkey, "@"))
                    throw_invalid_tag(tpl_id, tpl_tag);
                result_jkey = fstr_slice(result_jkey, 1, -1);
            }
            fstr_t call_fn, call_arg;
            if (!fstr_divide(call_fn_arg, ":", &call_fn, &call_arg))
                throw_invalid_tag(tpl_id, tpl_tag);
            // Lookup the callback.
            tpl_cb_t* tpl_cb = dict_read(ctx->tpl_cbs, tpl_cb_t, call_fn);
            if (tpl_cb == 0)
                throw_invalid_tag_info(tpl_id, tpl_tag, concs("no such callback [", call_fn, "] declared"));
            // Trim whitespace from call arg lines as this is usually useless template indent.
            list(fstr_t)* trimmed_lines = new_list(fstr_t);
            for (fstr_t line; fstr_iterate_trim(&call_arg, "\n", &line);)
                list_push_end(trimmed_lines, fstr_t, line);
            fstr_t trimmed_call_arg;
            switch_heap (heap) {
                trimmed_call_arg = fss(fstr_implode(trimmed_lines, "\n"));
            }
            // Add the callback.
            tpl_part_t part = {
                .type = WSR_ELEM_CALL,
                .jkey_get = trimmed_call_arg,
                .jkey_setk = result_jkey,
                .tpl_cb = *tpl_cb,
            };
            list_push_end(parts, tpl_part_t, part);
        } else {
            throw_eio(concs("did not understand tpl tag [", tpl_tag, "]"), wsr_tpl_invalid);
        }
    }
    if (list_count(wrapper_stack, stack_elem_t) > 0)
        throw_eio(concs("end of template unexpectedly reached [", tpl_file_name, "]"), wsr_tpl_invalid);
    if (expect_wrapper && !is_wrapper)
        throw_eio(concs("expected wrapper template in [", tpl_file_name, "]"), wsr_tpl_invalid);
    fstr_t last_tpl_id = is_wrapper? concs("foot@", tpl_file_name): tpl_file_name;
    virt_tpl_t main_tpl = {
        .id = last_tpl_id,
        .parts = parts,
    };
    list_push_end(v_templates, virt_tpl_t*, cln(&main_tpl));
    // Time to build element-trees for all templates in file.
    list_foreach(v_templates, virt_tpl_t*, v_tpl) {
        list(wsr_elem_t)* elems = new_list(wsr_elem_t);
        list_foreach(v_tpl->parts, tpl_part_t, part) {
            switch (part.type) {{
            } case WSR_ELEM_STATIC: {
                wsr_elem_t elem = {
                    .type = part.type,
                    .html = part.html,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_PARTIAL: {
                wsr_elem_t elem = {
                    .type = part.type,
                    .partial_key = part.partial_key
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_INCLUDE: {
                wsr_tpl_t* tpl;
                switch_heap (heap) {
                    tpl = get_tpl_from_file(ctx, partials, part.tpl_path);
                }
                wsr_elem_t elem = {
                    .type = WSR_ELEM_INCLUDE,
                    .tpl = tpl,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_INLINE: {
                wsr_tpl_t* r_tpl = part.virt_tpl->real_tpl;
                assert(r_tpl != 0);
                wsr_elem_t elem = {
                    .type = WSR_ELEM_INLINE,
                    .tpl = r_tpl,
                    .partial_key = part.partial_key,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_PRINT: { // fall through
            } case WSR_ELEM_PRINT_RAW: {
            } case WSR_ELEM_PRINT_JSON: {
                wsr_elem_t elem = {
                    .type = part.type,
                    .jkey_get = part.jkey_get,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_IF: {
                wsr_tpl_t* r_tpl = part.virt_tpl->real_tpl;
                assert(r_tpl != 0);
                wsr_tpl_t* r_tpl_else;
                if (part.virt_tpl2 != 0) {
                    r_tpl_else = part.virt_tpl2->real_tpl;
                    assert(r_tpl_else != 0);
                } else {
                    r_tpl_else = 0;
                }
                wsr_elem_t elem = {
                    .type = WSR_ELEM_IF,
                    .tpl = r_tpl,
                    .tpl_else = r_tpl_else,
                    .partial_key = part.partial_key,
                    .jkey_get = part.jkey_get,
                    .has_jval = part.has_jval,
                };
                if (elem.has_jval) switch_heap(heap) {
                    elem.jval = json_clone(part.jval, true);
                }
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_FOREACH: {
                wsr_tpl_t* r_tpl = part.virt_tpl->real_tpl;
                assert(r_tpl != 0);
                wsr_elem_t elem = {
                    .type = WSR_ELEM_FOREACH,
                    .tpl = r_tpl,
                    .jkey_get = part.jkey_get,
                    .jkey_setk = part.jkey_setk,
                    .jkey_setv = part.jkey_setv,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_SET: {
                wsr_elem_t elem = {
                    .type = WSR_ELEM_SET,
                    .jkey_get = part.jkey_get,
                    .jkey_setk = part.jkey_setk,
                    .has_jval = part.has_jval,
                };
                if (elem.has_jval) switch_heap(heap) {
                    elem.jval = json_clone(part.jval, true);
                }
                list_push_end(elems, wsr_elem_t, elem);
                break;
            } case WSR_ELEM_CALL: {
                wsr_elem_t elem = {
                    .type = WSR_ELEM_CALL,
                    .jkey_get = part.jkey_get,
                    .jkey_setk = part.jkey_setk,
                    .tpl_cb = part.tpl_cb,
                };
                list_push_end(elems, wsr_elem_t, elem);
                break;
            }}
        }
        switch_heap (heap) {
            import_list(raw_tpl_mem);
            size_t n_elems = list_count(elems, wsr_elem_t);
            wsr_tpl_t* r_tpl = lwt_alloc_new(sizeof(wsr_tpl_t) + sizeof(wsr_elem_t) * n_elems);
            r_tpl->n_elems = n_elems;
            size_t i = 0;
            list_foreach(elems, wsr_elem_t, elem) {
                r_tpl->elems[i] = elem;
                i++;
            }
            // Insert all tags this file declares.
            if (v_tpl->id.len > 0) {
                (void) dict_insert(partials, wsr_tpl_t*, v_tpl->id, r_tpl);
            }
            // Index real template for this virtual template.
            v_tpl->real_tpl = r_tpl;
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

static void tpl_append_html(html_t* html, html_t* buf) {
    for (size_t i = 0; i < html->n_total; i++)
        html_append_iov(html->iov[i], buf);
}

static void tpl_append_partial(wsr_tpl_ctx_t* ctx, fstr_t partial_key, dict(html_t*)* partial_index, html_t* buf) {
    html_t** partial_ptr = dict_read(partial_index, html_t*, partial_key);
    if (partial_ptr == 0)
        return;
    tpl_append_html(*partial_ptr, buf);
}

static html_t* new_inline_buf(dict(html_t*)* inlines, fstr_t partial_key) {
    html_t** inline_buf_ptr = dict_read(inlines, html_t*, partial_key);
    if (inline_buf_ptr == 0) {
        html_t* inline_buf = wsr_tpl_start();
        (void) dict_insert(inlines, html_t*, partial_key, inline_buf);
        return inline_buf;
    } else {
        return *inline_buf_ptr;
    }
}

static json_value_t wsr_jdata_get_raw(json_value_t jdata, fstr_t jkey, bool objinit) {
    if (jkey.len == 0)
        return jnull;
    for (fstr_t jkey_part; fstr_iterate_trim(&jkey, ".", &jkey_part);) {
        json_value_t child;
        if (jdata.type == JSON_ARRAY) {
            size_t n = fs2ui(jkey_part);
            if (n >= vec_count(jdata.array_value, json_value_t)) {
                if (objinit) {
                    child = jobj_new();
                    vec_set(jdata.array_value, json_value_t, n, child);
                } else {
                    return jnull;
                }
            } else {
                child = vec_get(jdata.array_value, json_value_t, n);
            }
        } else {
            child = JSON_LREF(jdata, jkey_part);
            if (child.type == JSON_NULL) {
                if (objinit) {
                    child = jobj_new();
                    JSON_SET(jdata, jkey_part, child);
                } else {
                    return jnull;
                }
            }
        }
        jdata = child;
    }
    return jdata;
}

json_value_t wsr_jdata_get(json_value_t jdata, fstr_t jkey) {
    return wsr_jdata_get_raw(jdata, jkey, false);
}

void wsr_jdata_put(json_value_t jdata, fstr_t jkey, json_value_t val) {
    if (jkey.len == 0)
        return;
    fstr_t g_jkey, s_key;
    if (fstr_rdivide(jkey, ".", &g_jkey, &s_key)) {
        jdata = wsr_jdata_get_raw(jdata, g_jkey, true);
    } else {
        s_key = jkey;
    }
    if (jdata.type != JSON_OBJECT)
        return;
    if (val.type == JSON_OBJECT) {
        // Deep copy object to get rid of remote heap references.
        // This is required arguable due to a design issue in librcd.
        val = json_clone(val, false);
    }
    JSON_SET(jdata, s_key, val);
}

static bool partial_has_content(html_t* partial) {
    for (size_t i = 0; i < partial->n_total; i++) {
        if (partial->iov[i].iov_len > 0)
            return true;
    }
    return false;
}

static bool tpl_if_partial(dict(html_t*)* partial_index, fstr_t partial_key) {
    html_t** partial = dict_read(partial_index, html_t*, partial_key);
    return (partial != 0 && partial_has_content(*partial));
}

static void tpl_execute(wsr_tpl_ctx_t* ctx, wsr_tpl_t* tpl, dict(html_t*)* partials, dict(html_t*)* inlines, json_value_t jdata, html_t* buf, fstr_t tpl_path, void* arg_ptr) {
    for (size_t i = 0; i < tpl->n_elems; i++) {
        wsr_elem_t elem = tpl->elems[i];
        switch (elem.type) {{
        } case WSR_ELEM_STATIC: {
            html_append(elem.html, buf);
            break;
        } case WSR_ELEM_INCLUDE: {
            tpl_execute(ctx, elem.tpl, partials, inlines, jdata, buf, tpl_path, arg_ptr);
            break;
        } case WSR_ELEM_PARTIAL: {
            tpl_append_partial(ctx, elem.partial_key, partials, buf);
            tpl_append_partial(ctx, elem.partial_key, inlines, buf);
            break;
        } case WSR_ELEM_INLINE: {
            html_t* inline_buf = new_inline_buf(inlines, elem.partial_key);
            tpl_execute(ctx, elem.tpl, partials, inlines, jdata, inline_buf, tpl_path, arg_ptr);
            break;
        } case WSR_ELEM_PRINT: {
            json_value_t value = wsr_jdata_get(jdata, elem.jkey_get);
            if (value.type == JSON_STRING) {
                tpl_append_html(wsr_html_escape(value.string_value), buf);
            } else if (value.type == JSON_NUMBER) {
                html_append(fss(fstr_from_double(value.number_value)), buf);
            } else if (value.type != JSON_NULL) {
                html_append(json_serial_type(value.type), buf);
            }
            break;
        } case WSR_ELEM_PRINT_JSON: {
            // Print json value for use inside <script> tag.
            json_value_t value = wsr_jdata_get(jdata, elem.jkey_get);
            fstr_t script_json;
            sub_heap {
                fstr_t raw_json = fss(json_stringify(value));
                script_json = fss(escape(wsr_json_script_escape(raw_json)));
            }
            tpl_append_html(HRAW(script_json), buf);
            break;
        } case WSR_ELEM_PRINT_RAW: {
            json_value_t value = wsr_jdata_get(jdata, elem.jkey_get);
            if (value.type == JSON_STRING) {
                tpl_append_html(wsr_html_raw(value.string_value), buf);
            }
            break;
        } case WSR_ELEM_IF: {
            bool truthy;
            if (elem.partial_key.len > 0) {
                assert(!elem.has_jval);
                truthy = tpl_if_partial(partials, elem.partial_key) || tpl_if_partial(inlines, elem.partial_key);
            } else {
                json_value_t jv = wsr_jdata_get(jdata, elem.jkey_get);
                if (elem.has_jval) {
                    json_value_t jv2;
                    if (elem.jval.type == JSON_ARRAY) {
                        // Resolve dynamic reference.
                        fstr_t key = jstrv(vec_get(elem.jval.array_value, json_value_t, 0));
                        jv2 = wsr_jdata_get(jdata, key);
                    } else {
                        // Static reference.
                        jv2 = elem.jval;
                    }
                    truthy = json_cmp(jv, jv2);
                } else {
                    truthy = !json_is_empty(jv);
                }
            }
            if (truthy) {
                tpl_execute(ctx, elem.tpl, partials, inlines, jdata, buf, tpl_path, arg_ptr);
            } else if (elem.tpl_else != 0) {
                tpl_execute(ctx, elem.tpl_else, partials, inlines, jdata, buf, tpl_path, arg_ptr);
            }
            break;
        } case WSR_ELEM_FOREACH: {
            json_value_t value = wsr_jdata_get(jdata, elem.jkey_get);
            if (value.type == JSON_ARRAY) {
                vec_foreach(value.array_value, json_value_t, i, value) {
                    wsr_jdata_put(jdata, elem.jkey_setv, value);
                    tpl_execute(ctx, elem.tpl, partials, inlines, jdata, buf, tpl_path, arg_ptr);
                }
            } else if (value.type == JSON_OBJECT) {
                dict_foreach(value.object_value, json_value_t, key, value) {
                    wsr_jdata_put(jdata, elem.jkey_setk, jstr(key));
                    wsr_jdata_put(jdata, elem.jkey_setv, value);
                    tpl_execute(ctx, elem.tpl, partials, inlines, jdata, buf, tpl_path, arg_ptr);
                }
            }
            break;
        } case WSR_ELEM_SET: {
            json_value_t value = (elem.has_jval? elem.jval: wsr_jdata_get(jdata, elem.jkey_get));
            wsr_jdata_put(jdata, elem.jkey_setk, value);
            break;
        } case WSR_ELEM_CALL: {
            json_value_t value = elem.tpl_cb(elem.jkey_get, jdata, arg_ptr);
            if (elem.jkey_setk.len > 0)
                wsr_jdata_put(jdata, elem.jkey_setk, value);
            break;
        }}
    }
}

void wsr_tpl_render_jd(wsr_tpl_ctx_t* ctx, fstr_t tpl_path, dict(html_t*)* partials, json_value_t jdata, html_t* buf, void* arg_ptr) {
    DBGFN("[", tpl_path, "]: ", jdata);
    wsr_tpl_t* template = ctx->precompile? get_compiled_tpl(ctx->precompiled_partials, tpl_path): get_tpl_from_file(ctx, 0, tpl_path);
    dict(html_t*)* inlines = new_dict(html_t*);
    if (jdata.type != JSON_OBJECT) {
        // We cannot understand jdata other than object, force object.
        jdata = jobj_new();
    }
    tpl_execute(ctx, template, partials, inlines, jdata, buf, tpl_path, arg_ptr);
}

void wsr_tpl_render(wsr_tpl_ctx_t* ctx, fstr_t tpl_path, dict(html_t*)* partials, html_t* buf, void* arg_ptr) {
    wsr_tpl_render_jd(ctx, tpl_path, partials, jnull, buf, arg_ptr);
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

fstr_mem_t* wsr_tpl_dump(html_t* html) {
    fstr_mem_t* mem = fstr_alloc(wsr_tpl_length(html));
    fstr_t tail_buf = fss(mem);
    for (size_t i = 0; i < html->n_total; i++) {
        fstr_t str = {.str = html->iov[i].iov_base, .len = html->iov[i].iov_len};
        fstr_cpy_over(tail_buf, str, &tail_buf, 0);
    }
    return mem;
}

static inline fstr_t flush_tail_buf(rio_t* write_h, fstr_t buf, fstr_t buf_tail) {
    fstr_t chunk = fstr_detail(buf, buf_tail);
    if (chunk.len > 0)
        rio_write(write_h, chunk);
    return buf;
}

void wsr_tpl_writev(rio_t* write_h, html_t* html) {
    struct iovec* iov = html->iov;
    int32_t fd = rio_get_fd_write(write_h);
    if (fd < 0) {
        // Rio stream is not associated with file descriptor.
        // Concatenate small chunks before sending.
        fstr_t buf = fss(fstr_alloc_buffer(0x1000));
        fstr_t buf_tail = buf;
        for (size_t i = 0; i < html->n_total; i++) {
            struct iovec iov = html->iov[i];
            fstr_t chunk = {.str = iov.iov_base, .len = iov.iov_len};
            if (chunk.len > buf_tail.len) {
                // Flush any existing buffered chunk.
                buf_tail = flush_tail_buf(write_h, buf, buf_tail);
            }
            if (chunk.len > buf_tail.len) {
                // Send chunk immediately.
                rio_write(write_h, chunk);
            } else {
                // Copy chunk to tail buffer.
                fstr_cpy_over(buf_tail, chunk, &buf_tail, 0);
            }
        }
        // Flush any final buffered chunk.
        flush_tail_buf(write_h, buf, buf_tail);
    } else {
        // Rio stream has file descriptor, write to it directly with writev.
        size_t n_left = html->n_total;
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

wsr_tpl_ctx_t* wsr_tpl_init(fstr_t root_tpl_path, bool precompile, dict(tpl_cb_t)* tpl_cbs) {
    wsr_tpl_ctx_t* ctx = new(wsr_tpl_ctx_t);
    ctx->root_tpl_path = fsc(root_tpl_path);
    ctx->precompile = precompile;
    ctx->tpl_cbs = tpl_cbs;
    if (precompile) {
        ctx->precompiled_partials = new_dict(wsr_tpl_t*);
        compile_templates_at(ctx, "");
    }
    return ctx;
}
