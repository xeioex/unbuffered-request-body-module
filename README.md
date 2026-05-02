# nginx unbuffered request body modules

Independent nginx core HTTP modules for experimenting with request bodies
through nginx's unbuffered request body path.

The addon builds two modules:

- `ngx_http_unbuffered_body_module`: observes or immediately consumes request
  body buffers from the request body filter path.
- `ngx_http_async_body_module`: content-only playground for application-paced
  asynchronous body consumption with pull-driven, single-batch delivery.

## Directives

### `ngx_http_unbuffered_body_module`

```nginx
unbuffered_body off | view | consume_access | consume_content;
unbuffered_body_log_level info | notice | warn | error;
```

`unbuffered_body` defaults to `off`.

Modes:

- `off`: leave request body handling unchanged.
- `view`: hash the body while passing it to later request body consumers.
- `consume_access`: consume and hash the body in the access phase, then
  continue normal request processing with the body marked as empty.
- `consume_content`: consume and hash the body in the content phase and return
  a plain-text response containing the SHA-1 digest and body size.

`unbuffered_body_log_level` controls the level used for the digest log line.
It defaults to `info`.

### `ngx_http_async_body_module`

```nginx
async_body_consume on | off;
async_body_read_size <size>;
async_body_abandon_after <size>;
async_body_poll post | delay:<time>;
async_body_debug on | off;
```

Defaults:

- `async_body_consume off`
- `async_body_read_size 4k`
- `async_body_abandon_after unset`
- `async_body_poll post`
- `async_body_debug off`

When enabled, the async module is a content handler. It takes ownership of
request body consumption and keeps at most one in-flight nginx body-delivery
batch at a time. The consumer event is the only owner of
`ngx_http_read_unbuffered_request_body()`, consumes at most
`async_body_read_size` bytes per tick, and does not build a module-owned
producer queue.

The response is plain text:

```text
sha1=<hex> size=<n>
```

`async_body_poll post` schedules the next consumer tick immediately through
the event loop. `async_body_poll delay:<time>` delays each consumer tick and
is useful for making slow-consumer pacing visible in tests.

`async_body_abandon_after <size>` makes the async handler stop consuming after
at least that many body bytes have been processed. It closes keepalive, drops
the remaining in-flight batch, and returns the digest and size for the bytes
consumed so far. This is intended for testing abrupt application-side stops.

With `async_body_debug on`, the response includes test-oriented headers:

- `X-Async-Body-In-Max`: maximum in-flight batch size observed.
- `X-Async-Body-Reading-Done`: whether nginx body reading completed.

## Variables

- `$unbuffered_body_sha1`: lowercase hex SHA-1 digest after the body is done.
- `$unbuffered_body_size`: number of body bytes seen by the module.
- `$unbuffered_body_state`: `off`, `view`, `consume`, or `done`.

## Build

```sh
cd /path/to/nginx
./auto/configure --add-module=/path/to/unbuffered-request-body-module
make -j4
```

For debug builds:

```sh
cd /path/to/nginx
./auto/configure \
    --with-debug \
    --add-module=/path/to/unbuffered-request-body-module
make -j4
```

## Tests

The tests use nginx-tests' `Test::Nginx` library.

```sh
cd /path/to/unbuffered-request-body-module
TEST_NGINX_BINARY=/path/to/nginx/objs/nginx \
prove -I /path/to/nginx-tests/lib -v t/*.t
```

Notable async coverage includes:

- `t/async_body.t`: general async consumption behavior and pacing
- `t/async_body_refill.t`: draining one batch and refilling the next

## Example

```nginx
location /body {
    unbuffered_body consume_content;
}

location /async-body {
    async_body_consume on;
    async_body_read_size 4k;
    async_body_poll delay:10ms;
    async_body_debug on;
}

location /proxy {
    unbuffered_body view;
    proxy_request_buffering off;
    proxy_pass http://backend;
    add_header X-Body-Sha1 $unbuffered_body_sha1 always;
    add_header X-Body-Size $unbuffered_body_size always;
}
```

## Async Reproduction

Configure nginx with the async module and run it locally as follows:

```nginx
...

http {
    client_body_buffer_size 128k;
    client_max_body_size 0;

    server {
        listen 8000;

        location /async_trickle {
            async_body_consume on;
            async_body_read_size 16k;
            async_body_poll delay:2s;
            async_body_debug on;
        }

        location /async_greedy {
            async_body_consume on;
            async_body_read_size 64k;
            async_body_poll post;
            async_body_debug on;
        }
    }
}
```

```sh
# Producer 1k/s, consumer about 8k/s: consumer waits for the client.
curl -X POST 127.0.0.1:8000/async_trickle \
    --data-binary @<(head -c 10000 /dev/zero | tr '\0' 'A') \
    --limit-rate 1k

```

```sh
# Producer 64k/s, consumer about 8k/s: queued data drains over time.
curl -X POST 127.0.0.1:8000/async_trickle \
    --data-binary @<(head -c 160000 /dev/zero | tr '\0' 'A') \
    --limit-rate 64k
```

# /async_greedy, 10MB body.  Producer capped at 1MB/s; consumer posts 64k ticks.
```sh
# Producer unrestricted locally; greedy consumer posts 64k ticks immediately.
curl -X POST 127.0.0.1:8000/async_greedy \
    --data-binary @<(head -c 10000000 /dev/zero | tr '\0' 'A')
```

# /async_greedy, 10MB body.  Producer unrestricted; consumer posts 64k ticks.
```sh
# Producer unrestricted locally; greedy consumer posts 64k ticks immediately.
curl -X POST 127.0.0.1:8000/async_greedy \
    --data-binary @<(head -c 10000000 /dev/zero | tr '\0' 'A')
```

