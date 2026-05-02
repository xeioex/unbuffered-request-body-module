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


#define NGX_HTTP_ASYNC_BODY_POST   0
#define NGX_HTTP_ASYNC_BODY_DELAY  1


typedef struct {
    ngx_flag_t    enabled;
    size_t        read_size;
    size_t        abandon_after;
    ngx_uint_t    poll;
    ngx_msec_t    delay;
    ngx_flag_t    debug;
} ngx_http_async_body_loc_conf_t;


/*
 * Module lifecycle.  This is intentionally separate from request-body input
 * state: ACTIVE can still mean reading, waiting for readability, or draining
 * an already received batch.
 */
typedef enum {
    /*
     * The async consumer may run, consume ctx->in, pull more request body data,
     * and schedule itself for later work.
     */
    NGX_HTTP_ASYNC_BODY_ACTIVE = 0,

    /*
     * Response/finalization has started.  Posted or timer callbacks may still
     * exist, but they must not re-enter body consumption or schedule more work.
     */
    NGX_HTTP_ASYNC_BODY_FINALIZING,

    /*
     * The response digest has been finalized.  Response generation can be
     * called again without finalizing SHA-1 a second time.
     */
    NGX_HTTP_ASYNC_BODY_DONE
} ngx_http_async_body_phase_t;


typedef struct {
    ngx_http_request_t  *request;
    ngx_log_t           *log;

    ngx_sha1_t    sha1;
    u_char        digest[20];

    ngx_chain_t  *in;

    off_t         bytes_total;
    size_t        in_bytes;
    size_t        in_bytes_max;

    ngx_event_t   consumer;

    ngx_http_async_body_phase_t  phase;

    /*
     * reading_done latches nginx's body-reader terminal state.  It can become
     * true while ctx->in still holds the final batch, so it is not a lifecycle
     * phase.
     */
    unsigned      reading_done:1;
    /*
     * waiting_read records that this module installed its read handler and is
     * waiting for readability; cleanup uses it to restore blocked reading.
     */
    unsigned      waiting_read:1;
} ngx_http_async_body_ctx_t;


static ngx_int_t ngx_http_async_body_handler(ngx_http_request_t *r);
static void ngx_http_async_body_post_handler(ngx_http_request_t *r);
static void ngx_http_async_body_read_handler(ngx_http_request_t *r);
static void ngx_http_async_body_consumer_event(ngx_event_t *ev);
static void ngx_http_async_body_cleanup(void *data);

static ngx_int_t ngx_http_async_body_init_ctx(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t **ctxp);
static ngx_int_t ngx_http_async_body_add_cleanup(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static ngx_int_t ngx_http_async_body_take_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static void ngx_http_async_body_pop_batch_link(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_uint_t *empty_bufsp);
static void ngx_http_async_body_consume_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static void ngx_http_async_body_enter_finalizing(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static void ngx_http_async_body_enter_done(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static ngx_uint_t ngx_http_async_body_should_abandon(
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static void ngx_http_async_body_abandon(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static void ngx_http_async_body_drop_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static void ngx_http_async_body_schedule(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf, ngx_uint_t force_post);
static void ngx_http_async_body_wait_readable(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static void ngx_http_async_body_block_reading(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf);
static ngx_int_t ngx_http_async_body_send_response(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static ngx_int_t ngx_http_async_body_add_debug_headers(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx);
static ngx_int_t ngx_http_async_body_add_header(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value);
static u_char *ngx_http_async_body_hex(ngx_pool_t *pool, u_char digest[20]);

static ngx_int_t ngx_http_async_body_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_async_body_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_async_body_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_async_body_poll(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_async_body_commands[] = {

    { ngx_string("async_body_consume"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_async_body_loc_conf_t, enabled),
      NULL },

    { ngx_string("async_body_read_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_async_body_loc_conf_t, read_size),
      NULL },

    { ngx_string("async_body_abandon_after"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_async_body_loc_conf_t, abandon_after),
      NULL },

    { ngx_string("async_body_poll"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_async_body_poll,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("async_body_debug"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_async_body_loc_conf_t, debug),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_async_body_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_async_body_postconfiguration, /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_async_body_create_loc_conf,   /* create location configuration */
    ngx_http_async_body_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_async_body_module = {
    NGX_MODULE_V1,
    &ngx_http_async_body_module_ctx,       /* module context */
    ngx_http_async_body_commands,          /* module directives */
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


static ngx_int_t
ngx_http_async_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_async_body_ctx_t       *ctx;
    ngx_http_async_body_loc_conf_t  *conf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);
    if (!conf->enabled) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_async_body_module);
    if (ctx != NULL) {
        return NGX_DONE;
    }

    if (ngx_http_async_body_init_ctx(r, &ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body_no_buffering = 1;

    if (conf->debug) {
        if (conf->poll == NGX_HTTP_ASYNC_BODY_POST) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "async body: start read_size=%uz poll=post",
                          conf->read_size);

        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "async body: start read_size=%uz poll=delay:%M",
                          conf->read_size, conf->delay);
        }
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_async_body_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


/*
 * The post handler is called once by ngx_http_read_client_request_body()
 * to hand off the initial request-body state.  It is responsible for taking
 * batches from nginx, scheduling the consumer, and managing the reading state
 * machine transitions.  It is never responsible for consuming batches itself.
 */
static void
ngx_http_async_body_post_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_async_body_ctx_t       *ctx;
    ngx_http_async_body_loc_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_async_body_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);

    rc = ngx_http_async_body_take_batch(r, ctx, conf);
    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->reading_body) {
        if (ctx->in != NULL) {
            ngx_http_async_body_block_reading(r, ctx, conf);

        } else {
            ngx_http_async_body_wait_readable(r, ctx, conf);
        }

    } else {
        ctx->reading_done = 1;
    }

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: post handler reading_body=%ui "
                      "in=%uz total=%O done=%ui waiting=%ui",
                      r->reading_body, ctx->in_bytes, ctx->bytes_total,
                      (ngx_uint_t) (ctx->reading_done != 0),
                      (ngx_uint_t) (ctx->waiting_read != 0));
    }

    ngx_http_async_body_schedule(r, ctx, conf, ctx->reading_done);
}


/*
 * The read handler is responsible for scheduling the consumer when readability
 * arrives, and for handling read timeouts.  It is never responsible for
 * pulling batches itself; that is the consumer event's job once it wakes up.
 */
static void
ngx_http_async_body_read_handler(ngx_http_request_t *r)
{
    ngx_http_async_body_ctx_t       *ctx;
    ngx_http_async_body_loc_conf_t  *conf;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_async_body_module);
    if (ctx == NULL || ctx->phase != NGX_HTTP_ASYNC_BODY_ACTIVE) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);

    ctx->waiting_read = 0;
    r->read_event_handler = ngx_http_block_reading;
    ngx_http_block_reading(r);

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: readable");
    }

    ngx_http_async_body_schedule(r, ctx, conf, 1);
}


/*
 * The consumer event is the main driver of the async body state machine.
 * It consumes the current batch, performs subsequent nginx request-body pulls
 * only after that batch drains, and finalizes the request once the stream ends.
 */
static void
ngx_http_async_body_consumer_event(ngx_event_t *ev)
{
    ngx_int_t                        rc;
    ngx_http_request_t              *r;
    ngx_http_async_body_ctx_t       *ctx;
    ngx_http_async_body_loc_conf_t  *conf;

    r = ev->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_async_body_module);
    if (ctx == NULL || ctx->phase != NGX_HTTP_ASYNC_BODY_ACTIVE) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);

    for ( ;; ) {
        if (ctx->in != NULL) {
            ngx_http_async_body_consume_batch(r, ctx, conf);

            if (ngx_http_async_body_should_abandon(ctx, conf)) {
                /* Models abrupt stop of consumption */
                ngx_http_async_body_enter_finalizing(r, ctx);
                ngx_http_async_body_abandon(r, ctx, conf);

                rc = ngx_http_async_body_send_response(r, ctx);
                ngx_http_finalize_request(r, rc);
                return;
            }

            if (ctx->in != NULL) {
                /* Didn't finish the batch; reschedule to continue consuming. */
                ngx_http_async_body_schedule(r, ctx, conf, 0);
                return;
            }
        }

        /* A drained batch plus reading_done means the guest stream ended. */
        if (ctx->reading_done) {
            ngx_http_async_body_enter_finalizing(r, ctx);

            if (conf->debug) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "async body: finalize total=%O",
                              ctx->bytes_total);
            }

            ngx_http_finalize_request(r,
                                      ngx_http_async_body_send_response(r,
                                                                        ctx));
            return;
        }

        if (!r->reading_body) {
            ctx->reading_done = 1;
            continue;
        }

        /* The next nginx body pull is allowed only after the batch drains. */
        rc = ngx_http_read_unbuffered_request_body(r);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_finalize_request(r, rc);
            return;
        }

        if (ngx_http_async_body_take_batch(r, ctx, conf) == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NGX_OK || !r->reading_body
            || r->connection->error || r->connection->close)
        {
            ctx->reading_done = 1;
        }

        if (conf->debug) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "async body: pull rc=%i reading_body=%ui "
                          "in=%uz total=%O done=%ui",
                          rc, r->reading_body, ctx->in_bytes,
                          ctx->bytes_total,
                          (ngx_uint_t) (ctx->reading_done != 0));
        }

        if (ctx->in != NULL) {
            /* NGX_AGAIN may rearm readability without delivering a batch. */
            ngx_http_async_body_block_reading(r, ctx, conf);
            continue;
        }

        if (ctx->reading_done) {
            continue;
        }

        /* Readability only wakes the consumer; it never pulls by itself. */
        ngx_http_async_body_wait_readable(r, ctx, conf);
        return;
    }
}


static void
ngx_http_async_body_cleanup(void *data)
{
    ngx_http_request_t              *r;
    ngx_http_async_body_ctx_t       *ctx = data;
    ngx_http_async_body_loc_conf_t  *conf;

    r = ctx->request;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                      "async body: cleanup timer=%ui posted=%ui "
                      "in=%uz total=%O done=%ui finalizing=%ui "
                      "waiting=%ui",
                      ctx->consumer.timer_set, ctx->consumer.posted,
                      ctx->in_bytes, ctx->bytes_total,
                      (ngx_uint_t)
                          (ctx->phase == NGX_HTTP_ASYNC_BODY_DONE),
                      (ngx_uint_t)
                          (ctx->phase == NGX_HTTP_ASYNC_BODY_FINALIZING),
                      (ngx_uint_t) (ctx->waiting_read != 0));
    }

    if (ctx->consumer.timer_set) {
        ngx_del_timer(&ctx->consumer);
    }

    if (ctx->consumer.posted) {
        ngx_delete_posted_event(&ctx->consumer);
    }

    if (ctx->waiting_read) {
        r->read_event_handler = ngx_http_block_reading;
        ctx->waiting_read = 0;
    }

    ngx_http_async_body_drop_batch(r, ctx);
}


static ngx_int_t
ngx_http_async_body_init_ctx(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t **ctxp)
{
    ngx_http_async_body_ctx_t  *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_async_body_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->request = r;
    ctx->log = r->connection->log;

    ngx_sha1_init(&ctx->sha1);

    ctx->consumer.handler = ngx_http_async_body_consumer_event;
    ctx->consumer.data = r;
    ctx->consumer.log = ctx->log;

    if (ngx_http_async_body_add_cleanup(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_async_body_module);

    *ctxp = ctx;

    return NGX_OK;
}


static ngx_int_t
ngx_http_async_body_add_cleanup(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_async_body_cleanup;
    cln->data = ctx;

    return NGX_OK;
}


static ngx_int_t
ngx_http_async_body_take_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_http_async_body_loc_conf_t *conf)
{
    off_t                     size, added;
    ngx_uint_t                nbufs, empty, last_buf;
    ngx_chain_t              *cl, *in;
    ngx_http_request_body_t  *rb;

    if (ctx->in != NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "async body: new batch arrived before old batch "
                      "was drained");
        return NGX_ERROR;
    }

    rb = r->request_body;
    if (rb == NULL || rb->bufs == NULL) {
        return NGX_DECLINED;
    }

    in = rb->bufs;
    rb->bufs = NULL;

    ctx->in = in;
    ctx->in_bytes = 0;

    added = 0;
    nbufs = 0;
    empty = 0;
    last_buf = 0;

    for (cl = in; cl != NULL; cl = cl->next) {
        nbufs++;

        size = ngx_buf_size(cl->buf);

        if (size > 0) {
            added += size;
            ctx->in_bytes += (size_t) size;

        } else {
            empty++;
        }

        if (cl->buf->last_buf) {
            last_buf = 1;
        }
    }

    if (ctx->in_bytes > ctx->in_bytes_max) {
        ctx->in_bytes_max = ctx->in_bytes;
    }

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: batch received bytes=%O bufs=%ui "
                      "empty=%ui in=%uz max=%uz last=%ui",
                      added, nbufs, empty, ctx->in_bytes,
                      ctx->in_bytes_max, last_buf);
    }

    return NGX_OK;
}


/*
 * Consume as a nginx request-body compatible consumer: ctx->in owns only the
 * detached rb->bufs chain links, while the request-body source still owns the
 * ngx_buf_t objects.  Advance b->pos as bytes are consumed and free only links
 * whose buffers have been drained.
 */
static void
ngx_http_async_body_consume_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_http_async_body_loc_conf_t *conf)
{
    size_t        n, size, remaining, batch_before, consumed;
    ngx_uint_t    consumed_bufs, empty_bufs;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    remaining = conf->read_size;
    batch_before = ctx->in_bytes;

    consumed = 0;
    consumed_bufs = 0;
    empty_bufs = 0;

    while (ctx->in != NULL && remaining > 0) {
        cl = ctx->in;
        b = cl->buf;
        size = ngx_buf_size(b);

        if (size == 0) {
            /*
             * Empty heads may appear at batch boundaries, especially as final
             * empty last_buf markers from nginx body filters.
             */
            ngx_http_async_body_pop_batch_link(r, ctx, &empty_bufs);
            continue;
        }

        n = ngx_min(size, remaining);

        ngx_sha1_update(&ctx->sha1, b->pos, n);

        /* Consumer-side progress signal for source-side buffer reuse. */
        b->pos += n;
        ctx->bytes_total += n;
        ctx->in_bytes -= n;

        remaining -= n;
        consumed += n;

        if (b->pos == b->last) {
            consumed_bufs++;
            ngx_http_async_body_pop_batch_link(r, ctx, NULL);
        }
    }

    /*
     * Hitting the guest read limit can expose trailing empty markers
     * without another data-consuming iteration.  Drop them on the same
     * tick so finalize/refill decisions see the real head state.
     */
    while (ctx->in != NULL && ngx_buf_size(ctx->in->buf) == 0)
    {
        ngx_http_async_body_pop_batch_link(r, ctx, &empty_bufs);
    }

    if (conf->debug && (consumed != 0 || empty_bufs != 0)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: consume bytes=%uz bufs=%ui "
                      "empty=%ui batch=%uz->%uz total=%O done=%ui",
                      consumed, consumed_bufs, empty_bufs, batch_before,
                      ctx->in_bytes, ctx->bytes_total,
                      (ngx_uint_t) (ctx->reading_done != 0));
    }
}


static void
ngx_http_async_body_enter_finalizing(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    if (ctx->phase != NGX_HTTP_ASYNC_BODY_ACTIVE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "async body: invalid finalizing transition phase=%ui",
                      (ngx_uint_t) ctx->phase);
    }

    ctx->phase = NGX_HTTP_ASYNC_BODY_FINALIZING;
}


static void
ngx_http_async_body_enter_done(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    if (ctx->phase == NGX_HTTP_ASYNC_BODY_DONE) {
        return;
    }

    if (ctx->phase != NGX_HTTP_ASYNC_BODY_FINALIZING) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "async body: invalid done transition phase=%ui",
                      (ngx_uint_t) ctx->phase);
    }

    ctx->phase = NGX_HTTP_ASYNC_BODY_DONE;
}


static void
ngx_http_async_body_pop_batch_link(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_uint_t *empty_bufsp)
{
    ngx_chain_t  *cl;

    cl = ctx->in;

    if (empty_bufsp != NULL) {
        (*empty_bufsp)++;
    }

    ctx->in = cl->next;

    cl->next = NULL;
    ngx_free_chain(r->pool, cl);
}


static ngx_uint_t
ngx_http_async_body_should_abandon(ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf)
{
    if (conf->abandon_after == NGX_CONF_UNSET_SIZE) {
        return 0;
    }

    return !ctx->reading_done
           && ctx->bytes_total >= (off_t) conf->abandon_after;
}


static void
ngx_http_async_body_abandon(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_http_async_body_loc_conf_t *conf)
{
    r->keepalive = 0;

    ngx_http_async_body_block_reading(r, ctx, conf);
    ngx_http_async_body_drop_batch(r, ctx);

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: abandon total=%O",
                      ctx->bytes_total);
    }
}


static void
ngx_http_async_body_drop_batch(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    while (ctx->in != NULL) {
        cl = ctx->in;

        ctx->in = cl->next;

        cl->next = NULL;
        ngx_free_chain(r->pool, cl);
    }

    ctx->in_bytes = 0;
}


static void
ngx_http_async_body_schedule(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx,
    ngx_http_async_body_loc_conf_t *conf, ngx_uint_t force_post)
{
    if (ctx->phase != NGX_HTTP_ASYNC_BODY_ACTIVE || ctx->consumer.posted
        || ctx->consumer.timer_set)
    {
        return;
    }

    if (force_post || conf->poll == NGX_HTTP_ASYNC_BODY_POST) {
        if (conf->debug) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "async body: schedule consumer mode=post "
                          "force=%ui in=%uz done=%ui",
                          force_post, ctx->in_bytes,
                          (ngx_uint_t) (ctx->reading_done != 0));
        }

        ngx_post_event(&ctx->consumer, &ngx_posted_events);
        return;
    }

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: schedule consumer mode=delay "
                      "delay=%M in=%uz done=%ui",
                      conf->delay, ctx->in_bytes,
                      (ngx_uint_t) (ctx->reading_done != 0));
    }

    ngx_add_timer(&ctx->consumer, conf->delay);
}


static void
ngx_http_async_body_wait_readable(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_http_async_body_loc_conf_t *conf)
{
    if (!r->reading_body) {
        return;
    }

    if (ctx->waiting_read) {
        return;
    }

    ctx->waiting_read = 1;
    r->read_event_handler = ngx_http_async_body_read_handler;

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: wait readable");
    }
}


static void
ngx_http_async_body_block_reading(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx, ngx_http_async_body_loc_conf_t *conf)
{
    ctx->waiting_read = 0;
    r->read_event_handler = ngx_http_block_reading;
    ngx_http_block_reading(r);

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: block reading in=%uz total=%O",
                      ctx->in_bytes, ctx->bytes_total);
    }
}


static ngx_int_t
ngx_http_async_body_send_response(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    u_char                          *hex;
    ngx_buf_t                       *b;
    ngx_int_t                        rc;
    ngx_chain_t                      out;
    ngx_http_async_body_loc_conf_t  *conf;

    if (ctx->phase != NGX_HTTP_ASYNC_BODY_DONE) {
        ngx_sha1_final(ctx->digest, &ctx->sha1);
        ngx_http_async_body_enter_done(r, ctx);
    }

    hex = ngx_http_async_body_hex(r->pool, ctx->digest);
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

    conf = ngx_http_get_module_loc_conf(r, ngx_http_async_body_module);

    if (conf->debug) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "async body: done size=%O in_max=%uz",
                      ctx->bytes_total, ctx->in_bytes_max);
    }

    if (ngx_http_async_body_add_debug_headers(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_async_body_add_debug_headers(ngx_http_request_t *r,
    ngx_http_async_body_ctx_t *ctx)
{
    u_char     *p;
    ngx_str_t  key, value;

    p = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    value.data = p;
    value.len = ngx_sprintf(p, "%uz", ctx->in_bytes_max) - p;
    ngx_str_set(&key, "X-Async-Body-In-Max");

    if (ngx_http_async_body_add_header(r, &key, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_str_set(&key, "X-Async-Body-Reading-Done");

    if (ctx->reading_done) {
        ngx_str_set(&value, "1");

    } else {
        ngx_str_set(&value, "0");
    }

    return ngx_http_async_body_add_header(r, &key, &value);
}


static ngx_int_t
ngx_http_async_body_add_header(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key = *key;
    h->value = *value;

    return NGX_OK;
}


static u_char *
ngx_http_async_body_hex(ngx_pool_t *pool, u_char digest[20])
{
    u_char  *hex;

    hex = ngx_pnalloc(pool, 40);
    if (hex == NULL) {
        return NULL;
    }

    ngx_hex_dump(hex, digest, 20);

    return hex;
}


static ngx_int_t
ngx_http_async_body_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_async_body_handler;

    return NGX_OK;
}


static void *
ngx_http_async_body_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_async_body_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_async_body_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->read_size = NGX_CONF_UNSET_SIZE;
    conf->abandon_after = NGX_CONF_UNSET_SIZE;
    conf->poll = NGX_CONF_UNSET_UINT;
    conf->delay = NGX_CONF_UNSET_MSEC;
    conf->debug = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_async_body_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_async_body_loc_conf_t *prev = parent;
    ngx_http_async_body_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_size_value(conf->read_size, prev->read_size, 4096);
    ngx_conf_merge_size_value(conf->abandon_after, prev->abandon_after,
                              NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->poll, prev->poll,
                              NGX_HTTP_ASYNC_BODY_POST);
    ngx_conf_merge_msec_value(conf->delay, prev->delay, 0);
    ngx_conf_merge_value(conf->debug, prev->debug, 0);

    if (conf->read_size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"async_body_read_size\" must be greater "
                           "than 0");
        return NGX_CONF_ERROR;
    }

    if (conf->abandon_after == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"async_body_abandon_after\" must be greater "
                           "than 0");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_async_body_poll(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   s, *value;
    ngx_int_t   delay;

    ngx_http_async_body_loc_conf_t *lcf = conf;

    if (lcf->poll != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "post") == 0) {
        lcf->poll = NGX_HTTP_ASYNC_BODY_POST;
        lcf->delay = 0;
        return NGX_CONF_OK;
    }

    if (value[1].len > sizeof("delay:") - 1
        && ngx_strncmp(value[1].data, "delay:", sizeof("delay:") - 1) == 0)
    {
        s.data = value[1].data + sizeof("delay:") - 1;
        s.len = value[1].len - (sizeof("delay:") - 1);

        delay = ngx_parse_time(&s, 0);
        if (delay == NGX_ERROR) {
            goto invalid;
        }

        lcf->poll = NGX_HTTP_ASYNC_BODY_DELAY;
        lcf->delay = (ngx_msec_t) delay;
        return NGX_CONF_OK;
    }

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%V\" in \"%V\" directive",
                       &value[1], &cmd->name);

    return NGX_CONF_ERROR;
}
