
/*
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sha1.h>


typedef enum {
    NGX_UB_OFF = 0,
    NGX_UB_VIEW,
    NGX_UB_CONSUME_ACCESS,
    NGX_UB_CONSUME_CONTENT
} ngx_http_ub_mode_t;


typedef struct {
    ngx_uint_t  mode;
    ngx_uint_t  log_level;
} ngx_http_ub_loc_conf_t;


typedef struct {
    ngx_http_ub_mode_t  mode;
    ngx_sha1_t          sha1;
    u_char              digest[20];
    off_t               bytes_total;
    unsigned            started:1;
    unsigned            done:1;
} ngx_http_ub_ctx_t;


static ngx_int_t ngx_http_ub_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_ub_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_ub_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ub_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_ub(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ub_log_level(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_ub_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_ub_access_handler(ngx_http_request_t *r);
static void ngx_http_ub_access_post(ngx_http_request_t *r);
static void ngx_http_ub_access_read(ngx_http_request_t *r);
static void ngx_http_ub_access_resume(ngx_http_request_t *r);
static ngx_int_t ngx_http_ub_content_handler(ngx_http_request_t *r);
static void ngx_http_ub_content_post(ngx_http_request_t *r);
static void ngx_http_ub_content_read(ngx_http_request_t *r);
static ngx_int_t ngx_http_ub_send_response(ngx_http_request_t *r);

static ngx_int_t ngx_http_ub_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ub_variable_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ub_variable_size(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ub_variable_state(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_ub_ctx_t *ngx_http_ub_get_or_create_ctx(ngx_http_request_t *r,
    ngx_http_ub_mode_t mode);
static ngx_int_t ngx_http_ub_finalize_digest(ngx_http_request_t *r,
    ngx_http_ub_ctx_t *ctx);
static void ngx_http_ub_mark_body_consumed(ngx_http_request_t *r);
static u_char *ngx_http_ub_hex(ngx_pool_t *pool, u_char digest[20]);


static ngx_http_request_body_filter_pt  ngx_http_next_request_body_filter;


static ngx_command_t  ngx_http_ub_commands[] = {

    { ngx_string("unbuffered_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_ub,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("unbuffered_body_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_ub_log_level,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ub_module_ctx = {
    ngx_http_ub_preconfiguration,          /* preconfiguration */
    ngx_http_ub_postconfiguration,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ub_create_loc_conf,           /* create location configuration */
    ngx_http_ub_merge_loc_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_unbuffered_body_module = {
    NGX_MODULE_V1,
    &ngx_http_ub_module_ctx,               /* module context */
    ngx_http_ub_commands,                  /* module directives */
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


static ngx_http_variable_t  ngx_http_ub_vars[] = {

    { ngx_string("unbuffered_body_sha1"), NULL, ngx_http_ub_variable_sha1,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("unbuffered_body_size"), NULL, ngx_http_ub_variable_size,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("unbuffered_body_state"), NULL, ngx_http_ub_variable_state,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_ub_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_ub_add_variables(cf);
}


static ngx_int_t
ngx_http_ub_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_ub_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_ub_content_handler;

    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_ub_request_body_filter;

    return NGX_OK;
}


static void *
ngx_http_ub_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ub_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ub_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_CONF_UNSET_UINT;
    conf->log_level = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_ub_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ub_loc_conf_t *prev = parent;
    ngx_http_ub_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, NGX_UB_OFF);
    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_INFO);

    return NGX_CONF_OK;
}


static char *
ngx_http_ub(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ub_loc_conf_t *lcf = conf;

    ngx_str_t  *value;

    if (lcf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->mode = NGX_UB_OFF;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "view") == 0) {
        lcf->mode = NGX_UB_VIEW;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "consume_access") == 0) {
        lcf->mode = NGX_UB_CONSUME_ACCESS;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "consume_content") == 0) {
        lcf->mode = NGX_UB_CONSUME_CONTENT;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%V\" in \"%V\" directive",
                       &value[1], &cmd->name);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_ub_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ub_loc_conf_t *lcf = conf;

    ngx_str_t  *value;

    if (lcf->log_level != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "info") == 0) {
        lcf->log_level = NGX_LOG_INFO;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "notice") == 0) {
        lcf->log_level = NGX_LOG_NOTICE;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "warn") == 0) {
        lcf->log_level = NGX_LOG_WARN;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "error") == 0) {
        lcf->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%V\" in \"%V\" directive",
                       &value[1], &cmd->name);

    return NGX_CONF_ERROR;
}


/*
 * This filter is required for view mode; consume modes use it to avoid a
 * separate pass over buffers saved in r->request_body->bufs.
 */
static ngx_int_t
ngx_http_ub_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                   n;
    ngx_int_t                saw_last_buf;
    ngx_chain_t             *cl;
    ngx_http_ub_ctx_t       *ctx;
    ngx_http_ub_loc_conf_t  *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_unbuffered_body_module);

    if (lcf == NULL || lcf->mode == NGX_UB_OFF || r != r->main) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ctx = ngx_http_ub_get_or_create_ctx(r, lcf->mode);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    saw_last_buf = 0;

    for (cl = in; cl != NULL; cl = cl->next) {
        n = cl->buf->last - cl->buf->pos;

        if (n > 0) {
            ngx_sha1_update(&ctx->sha1, cl->buf->pos, n);
            ctx->bytes_total += n;
        }

        if (cl->buf->last_buf && !ctx->done) {
            saw_last_buf = 1;

            if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (ctx->mode == NGX_UB_VIEW) {
        return ngx_http_next_request_body_filter(r, in);
    }

    /*
     * Consume mode drains each buffer after hashing, so no later request-body
     * filter can save or forward bytes this module has taken ownership of.
     */
    for (cl = in; cl != NULL; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
    }

    /*
     * last_saved tells nginx that the final request-body buffer has already
     * been handled; otherwise unbuffered reading may wait for a body tail that
     * this module consumed intentionally.
     */
    if (saw_last_buf && r->request_body != NULL) {
        r->request_body->last_saved = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ub_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                rc;
    ngx_http_ub_ctx_t       *ctx;
    ngx_http_ub_loc_conf_t  *lcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_unbuffered_body_module);
    if (lcf->mode != NGX_UB_CONSUME_ACCESS) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx != NULL && ctx->done) {
        return NGX_DECLINED;
    }

    if (ctx != NULL && ctx->started) {
        return NGX_DONE;
    }

    ctx = ngx_http_ub_get_or_create_ctx(r, NGX_UB_CONSUME_ACCESS);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->started = 1;
    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_ub_access_post);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_DONE);

    if (!ctx->done && !r->reading_body) {
        if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ctx->done) {
        return NGX_DECLINED;
    }

    return NGX_DONE;
}


static void
ngx_http_ub_access_post(ngx_http_request_t *r)
{
    if (r->reading_body) {
        r->read_event_handler = ngx_http_ub_access_read;
    }
}


static void
ngx_http_ub_access_read(ngx_http_request_t *r)
{
    ngx_int_t           rc;
    ngx_http_ub_ctx_t  *ctx;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_read_unbuffered_request_body(r);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc == NGX_AGAIN) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx != NULL && !ctx->done) {
        if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    ngx_http_ub_access_resume(r);
}


static void
ngx_http_ub_access_resume(ngx_http_request_t *r)
{
    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    ngx_http_core_run_phases(r);
}


static ngx_int_t
ngx_http_ub_content_handler(ngx_http_request_t *r)
{
    ngx_int_t                rc;
    ngx_http_ub_ctx_t       *ctx;
    ngx_http_ub_loc_conf_t  *lcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_unbuffered_body_module);
    if (lcf->mode != NGX_UB_CONSUME_CONTENT) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx != NULL && ctx->started) {
        return NGX_DONE;
    }

    ctx = ngx_http_ub_get_or_create_ctx(r, NGX_UB_CONSUME_CONTENT);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->started = 1;
    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_ub_content_post);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (!ctx->done && !r->reading_body) {
        if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ctx->done) {
        ngx_http_finalize_request(r, ngx_http_ub_send_response(r));
    }

    return NGX_DONE;
}


static void
ngx_http_ub_content_post(ngx_http_request_t *r)
{
    if (r->reading_body) {
        r->read_event_handler = ngx_http_ub_content_read;
    }
}


#if 0 /* Alternative, no request-body filter design for consumption. */
static ngx_int_t
ngx_http_ub_consume_saved_body(ngx_http_request_t *r, ngx_http_ub_ctx_t *ctx)
{
    size_t                    n;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_request_body_t  *rb;

    if (ctx == NULL || r->request_body == NULL) {
        return NGX_OK;
    }

    rb = r->request_body;

    for (cl = rb->bufs; cl != NULL; cl = cl->next) {
        b = cl->buf;
        n = b->last - b->pos;

        if (n > 0) {
            ngx_sha1_update(&ctx->sha1, b->pos, n);
            ctx->bytes_total += n;
        }

        b->pos = b->last;

        if (b->last_buf && !ctx->done) {
            if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    rb->bufs = NULL;

    return NGX_OK;
}
#endif


static void
ngx_http_ub_content_read(ngx_http_request_t *r)
{
    ngx_int_t           rc;
    ngx_http_ub_ctx_t  *ctx;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_read_unbuffered_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return;
    }

#if 0 /* Alternative, no request-body filter design for consumption. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);

    if (ngx_http_ub_consume_saved_body(r, ctx) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
#endif

    if (rc == NGX_AGAIN) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx != NULL && !ctx->done) {
        if (ngx_http_ub_finalize_digest(r, ctx) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    ngx_http_finalize_request(r, ngx_http_ub_send_response(r));
}


static ngx_int_t
ngx_http_ub_send_response(ngx_http_request_t *r)
{
    u_char              *hex;
    ngx_buf_t           *b;
    ngx_int_t            rc;
    ngx_chain_t          out;
    ngx_http_ub_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx == NULL || !ctx->done) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hex = ngx_http_ub_hex(r->pool, ctx->digest);
    if (hex == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, sizeof("sha1=") - 1 + 40
                                     + sizeof(" size=") - 1
                                     + NGX_OFF_T_LEN + 1);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->last, "sha1=%*s size=%O\n",
                          40, hex, ctx->bytes_total);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/plain");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_ub_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ub_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ub_variable_sha1(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char             *hex;
    ngx_http_ub_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx == NULL || !ctx->done) {
        v->not_found = 1;
        return NGX_OK;
    }

    hex = ngx_http_ub_hex(r->pool, ctx->digest);
    if (hex == NULL) {
        return NGX_ERROR;
    }

    v->len = 40;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = hex;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ub_variable_size(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char             *p;
    ngx_http_ub_ctx_t  *ctx;

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);

    v->len = ngx_sprintf(p, "%O", ctx == NULL ? 0 : ctx->bytes_total) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ub_variable_state(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                 state;
    ngx_http_ub_ctx_t        *ctx;
    ngx_http_ub_loc_conf_t   *lcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);

    if (ctx != NULL && ctx->done) {
        ngx_str_set(&state, "done");

    } else if (ctx != NULL
               && (ctx->mode == NGX_UB_CONSUME_ACCESS
                   || ctx->mode == NGX_UB_CONSUME_CONTENT))
    {
        ngx_str_set(&state, "consume");

    } else {
        lcf = ngx_http_get_module_loc_conf(r,
                                           ngx_http_unbuffered_body_module);

        if (lcf == NULL || lcf->mode == NGX_UB_OFF) {
            ngx_str_set(&state, "off");

        } else if (lcf->mode == NGX_UB_VIEW) {
            ngx_str_set(&state, "view");

        } else {
            ngx_str_set(&state, "consume");
        }
    }

    v->len = state.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = state.data;

    return NGX_OK;
}


static ngx_http_ub_ctx_t *
ngx_http_ub_get_or_create_ctx(ngx_http_request_t *r, ngx_http_ub_mode_t mode)
{
    ngx_http_ub_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_unbuffered_body_module);
    if (ctx != NULL) {
        return ctx;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ub_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->mode = mode;
    ngx_sha1_init(&ctx->sha1);

    ngx_http_set_ctx(r, ctx, ngx_http_unbuffered_body_module);

    return ctx;
}


static ngx_int_t
ngx_http_ub_finalize_digest(ngx_http_request_t *r, ngx_http_ub_ctx_t *ctx)
{
    u_char                  *hex;
    ngx_http_ub_loc_conf_t  *lcf;

    if (ctx->done) {
        return NGX_OK;
    }

    ngx_sha1_final(ctx->digest, &ctx->sha1);
    ctx->done = 1;

    if (ctx->mode == NGX_UB_CONSUME_ACCESS
        || ctx->mode == NGX_UB_CONSUME_CONTENT)
    {
        ngx_http_ub_mark_body_consumed(r);
    }

    hex = ngx_http_ub_hex(r->pool, ctx->digest);
    if (hex == NULL) {
        return NGX_ERROR;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_unbuffered_body_module);

    ngx_log_error(lcf->log_level, r->connection->log, 0,
                  "unbuffered_body: sha1=%*s size=%O",
                  40, hex, ctx->bytes_total);

    return NGX_OK;
}


static void
ngx_http_ub_mark_body_consumed(ngx_http_request_t *r)
{
    r->headers_in.content_length_n = 0;
}


static u_char *
ngx_http_ub_hex(ngx_pool_t *pool, u_char digest[20])
{
    u_char  *hex;

    hex = ngx_pnalloc(pool, 40);
    if (hex == NULL) {
        return NULL;
    }

    ngx_hex_dump(hex, digest, 20);

    return hex;
}
