#!/usr/bin/perl

# Tests for refilling async body batches after draining one batch.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/ sha1_hex /;
use Socket qw/ CRLF /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    client_body_buffer_size 16k;
    client_max_body_size 0;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /async-refill {
            async_body_consume on;
            async_body_read_size 1k;
            async_body_poll delay:1ms;
            async_body_debug on;
        }
    }
}

EOF

$t->run();

###############################################################################

my $body = 'x' x (64 * 1024);
my $response = http_body('/async-refill', $body);
my $log = $t->read_file('error.log');
my $batches = () = $log =~ /async body: batch received bytes=/g;

like($response, response_re($body), 'refill response digest');
cmp_ok(debug_header($response, 'X-Async-Body-In-Max'), '>=', 16384,
    'refill batch max reaches body buffer size');
is(debug_header($response, 'X-Async-Body-Reading-Done'), 1,
    'refill reading done');
cmp_ok($batches, '>=', 2, 'refill path receives multiple batches');

my $exact_chunked = 'z' x (16 * 1024);

like(http_chunked('/async-refill', $exact_chunked),
    response_re($exact_chunked), 'refill exact chunked body buffer size');

unlike($log, qr/\[alert\]|AddressSanitizer/ms,
    'refill log has no alerts or sanitizer reports');
unlike($log, qr/async body: .* (?:done|waiting|finalizing)=\d{2,}/ms,
    'refill log booleans stay single-digit');

###############################################################################

sub response_re {
    my ($body) = @_;
    my $sha1 = sha1_hex($body);
    my $size = length($body);

    return qr/sha1=$sha1 size=$size\x0d?$/ms;
}

sub debug_header {
    my ($response, $name) = @_;

    return $1 if $response =~ /^$name:\s*(\d+)\x0d?$/mi;
    return undef;
}

sub http_body {
    my ($uri, $body) = @_;

    return http(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . length($body) . CRLF . CRLF
        . $body
    );
}

sub http_chunked {
    my ($uri, $body) = @_;

    return http(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Transfer-Encoding: chunked" . CRLF . CRLF
        . sprintf("%x", length($body)) . CRLF
        . $body . CRLF
        . "0" . CRLF . CRLF
    );
}

###############################################################################
