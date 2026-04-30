#!/usr/bin/perl

# Tests for consume_access mode.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(13);

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

        location /access {
            unbuffered_body consume_access;
            proxy_pass http://127.0.0.1:8081/echo;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
            add_header X-Body-Size $unbuffered_body_size always;
            add_header X-Body-State $unbuffered_body_state always;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /echo {
            return 200 "cl=$http_content_length te=$http_transfer_encoding\n";
        }
    }
}

EOF

$t->run();

###############################################################################

my @bodies = ('', 'hello', '0123456789' x 512);

for my $body (@bodies) {
    my $r = http_body('/access', $body);
    like($r, qr/X-Body-Sha1: @{[ sha1_hex($body) ]}\x0d?$/ms,
        'sha1 content length ' . length($body));
    like($r, qr/X-Body-Size: @{[ length($body) ]}\x0d?$/ms,
        'size content length ' . length($body));
    like($r, qr/X-Body-State: done\x0d?$/ms,
        'state content length ' . length($body));
}

like(http_body('/access', 'hello'), qr/^cl=0 te=\x0d?$/m,
    'upstream sees empty content length body');

my $chunked = http_chunked('/access', 'hello');
like($chunked, qr/X-Body-Sha1: @{[ sha1_hex('hello') ]}\x0d?$/ms,
    'sha1 chunked');
like($chunked, qr/X-Body-Size: 5\x0d?$/ms, 'size chunked');
like($chunked, qr/^cl=0 te=\x0d?$/m, 'upstream sees empty chunked body');

###############################################################################

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
