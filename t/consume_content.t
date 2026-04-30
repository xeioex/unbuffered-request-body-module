#!/usr/bin/perl

# Tests for consume_content mode.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/ sha1_hex /;
use Socket qw/ CRLF /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../../nginx-tests/lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /content {
            unbuffered_body consume_content;
        }
    }
}

EOF

$t->run();

###############################################################################

my @bodies = ('', 'hello', '0123456789' x 512);

for my $body (@bodies) {
    like(http_body('/content', $body), response_re($body),
        'content length ' . length($body));
}

for my $body (@bodies) {
    like(http_chunked('/content', $body), response_re($body),
        'chunked ' . length($body));
}

like(http_body('/content', 'hello'), qr/Content-Type: text\/plain/ms,
    'content type');

like(http_body('/content', 'hello'), qr/Content-Length: 53\x0d?$/ms,
    'content length header');

like(http_get('/content'), response_re(''), 'get empty body');

http_body('/content', 'hello');
like($t->read_file('error.log'), qr/unbuffered_body: sha1=/ms,
    'digest logged');

###############################################################################

sub response_re {
    my ($body) = @_;
    my $sha1 = sha1_hex($body);
    my $size = length($body);

    return qr/sha1=$sha1 size=$size\x0d?$/ms;
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
