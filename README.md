# nginx unbuffered request body module

An independent nginx core HTTP module for observing or consuming request
bodies through nginx's unbuffered request body path.

## Directives

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
TEST_NGINX_BINARY=/path/to/nginx/objs/nginx prove -v t/*.t
```

## Example

```nginx
location /body {
    unbuffered_body consume_content;
}

location /proxy {
    unbuffered_body view;
    proxy_request_buffering off;
    proxy_pass http://backend;
    add_header X-Body-Sha1 $unbuffered_body_sha1 always;
    add_header X-Body-Size $unbuffered_body_size always;
}
```
