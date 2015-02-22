/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WSR_TPL_H
#define	WSR_TPL_H

#include "json.h"

#define HRAW(raw_html) wsr_html_raw(raw_html)

#define HC(...) ({ \
    html_t _htmls = {__VA_ARGS__}; \
    size_t _n_htmls = LENGTHOF(_htmls); \
    wsr_html_conc(_n_htmls, _htmls); \
})

#define H(x) wsr_html_escape(x)

typedef struct html html_t;

typedef json_value_t (*tpl_cb_t)(fstr_t tpl_arg, json_value_t jdata, void* arg_ptr);

typedef struct wsr_tpl_ctx {
    fstr_t root_tpl_path;
    bool strict;
    bool precompile;
    dict(wsr_tpl_t*)* precompiled_partials;
    dict(tpl_cb_t)* tpl_cbs;
} wsr_tpl_ctx_t;

dict(html_t);

list(html_t);

dict(tpl_cb_t);

html_t* wsr_html_raw(fstr_t raw_html);

html_t* wsr_html_conc(size_t n_html, html_t* htmls);

html_t* wsr_html_implode(list(html_t*)* htmls);

html_t* wsr_html_escape(fstr_t str);

fstr_mem_t* wsr_json_script_escape(fstr_t raw_json);

json_value_t wsr_jdata_get(json_value_t jdata, fstr_t jkey);

void wsr_jdata_put(json_value_t jdata, fstr_t jkey, json_value_t val);

void wsr_tpl_render_jd(wsr_tpl_ctx_t* ctx, fstr_t tpl_path, dict(html_t*)* partials, json_value_t jdata, html_t* buf, void* arg_ptr);

void wsr_tpl_render(wsr_tpl_ctx_t* ctx, fstr_t tpl_path, dict(html_t*)* partials, html_t* buf, void* arg_ptr);

html_t* wsr_tpl_start();

size_t wsr_tpl_length(html_t* html);

fstr_mem_t* wsr_tpl_dump(html_t* html);

/// Writes all html to the specified file or socket with direct writev(2) call.
/// The html structure is destroyed by the call and should not be used
/// afterwards.
void wsr_tpl_writev(rio_t* write_h, html_t* html);

wsr_tpl_ctx_t* wsr_tpl_init(fstr_t root_tpl_path, bool precompile, dict(tpl_cb_t)* tpl_cbs);

#endif	/* WSR_TPL_H */
