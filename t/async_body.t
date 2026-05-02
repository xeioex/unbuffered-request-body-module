#!/usr/bin/perl

# Tests for async body consumer mode.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/ sha1_hex /;
use IO::Socket::INET;
use Socket qw/ CRLF /;
use Test::More;
use Time::HiRes qw/ time /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(37);

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

        location /async {
            async_body_consume on;
            async_body_debug on;
        }

        location /async-delay {
            async_body_consume on;
            async_body_read_size 4k;
            async_body_poll delay:10ms;
            async_body_debug on;
        }

        location /async-post-small {
            async_body_consume on;
            async_body_read_size 4k;
            async_body_poll post;
            async_body_debug on;
        }

        location /async-abandon {
            async_body_consume on;
            async_body_read_size 1k;
            async_body_abandon_after 4k;
            async_body_debug on;
        }

        location /async-timeout {
            async_body_consume on;
            async_body_read_size 1k;
            client_body_timeout 100ms;
            async_body_debug on;
        }
    }
}

EOF

$t->run();

###############################################################################

my @bodies = ('', 'hello', '0123456789' x 512);

for my $body (@bodies) {
    like(http_body('/async', $body), response_re($body),
        'content length ' . length($body));
}

like(http_chunked('/async', 'chunked body'), response_re('chunked body'),
    'chunked body');

my $exact_chunk = 'x' x 4096;
my $exact_response = http_chunked('/async-delay', $exact_chunk);

like($exact_response, response_re($exact_chunk),
    'chunked exact consumer chunk followed by empty last buffer');
is(debug_header($exact_response, 'X-Async-Body-In-Max'), 4096,
    'debug exact batch max');

my $empty_response = http_get('/async');

like($empty_response, response_re(''), 'get empty body');
is(debug_header($empty_response, 'X-Async-Body-In-Max'), 0,
    'debug empty body batch max');
like(http_body('/async', 'hello'), qr/Content-Type: text\/plain/ms,
    'content type');

like(http_body('/async', 'hello'), qr/Content-Length: 53\x0d?$/ms,
    'content length header');

like(http_head('/async'), qr/200 OK/ms, 'head request');

like(http_head_body('/async', 'head body'), qr/200 OK/ms,
    'head request with content length');

like(malformed_chunked('/async'), qr/400 Bad Request/ms,
    'malformed chunked body');

like(malformed_delayed_chunked('/async-delay'), qr/400 Bad Request/ms,
    'malformed delayed chunked body');

my $delayed = 'x' x (1024 * 1024);
my $start = time();
my $response = http_body('/async-delay', $delayed);
my $elapsed = time() - $start;

like($response, response_re($delayed), 'delayed digest');
cmp_ok($elapsed, '<', 10, 'delayed consumer completes in broad band');
cmp_ok(debug_header($response, 'X-Async-Body-In-Max'), '>=', 4096,
    'debug batch max records body data');
is(debug_header($response, 'X-Async-Body-Reading-Done'), 1,
    'debug reading done');

my $post_start = time();
my $post_response = http_body('/async-post-small', $delayed);
my $post_elapsed = time() - $post_start;

like($post_response, response_re($delayed), 'post poll digest');
cmp_ok($post_elapsed, '<', 1.5, 'post poll small batch completes fast');
cmp_ok($elapsed, '>', $post_elapsed + 0.5,
    'delayed poll paces response');
cmp_ok(debug_header($post_response, 'X-Async-Body-In-Max'), '>=', 4096,
    'post poll batch max records body data');

my $chunked_slow = 'chunked slow ' x 21846;

like(http_chunked('/async-delay', $chunked_slow), response_re($chunked_slow),
    'chunked slow consumer');

my ($r1, $r2) = http_keepalive('/async', 'one', 'two');

like($r1, response_re('one'), 'keepalive first request');
like($r2, response_re('two'), 'keepalive second request');

like(http_expect_continue('/async', 'expect body'), response_re('expect body'),
    'expect continue request body');

my $abandon_body = 'a' x (64 * 1024);
my ($ar1, $ar2) =
    http_abandon_keepalive('/async-abandon', $abandon_body, 'next', 0);

like($ar1, response_re(substr($abandon_body, 0, 4096)),
    'abandon content length digest');
is($ar2, '', 'abandon content length closes keepalive');

my $abandon_chunked = 'b' x (64 * 1024);
my ($acr1, $acr2) =
    http_abandon_keepalive('/async-abandon', $abandon_chunked, 'next', 1);

like($acr1, response_re(substr($abandon_chunked, 0, 4096)),
    'abandon chunked digest');
is($acr2, '', 'abandon chunked closes keepalive');

is(http_timeout_wait_body('/async-timeout'), '',
    'read timeout closes waiting body connection');

close_before_body('/async-delay', 1024 * 1024);
like(http_body('/async', 'after wait cleanup'),
    response_re('after wait cleanup'), 'waiting read cleanup recovery');

partial_content_length('/async-delay', 'partial', 1024 * 1024);
like(http_body('/async', 'after abort'), response_re('after abort'),
    'delayed client abort recovery');

like($t->read_file('error.log'), qr/async body: cleanup .*waiting=1/ms,
    'cleanup records waiting read state');

like($t->read_file('error.log'),
    qr/http finalize request: 408, "\/async-timeout/ms,
    'read timeout finalizes request');

unlike($t->read_file('error.log'), qr/\[alert\]|AddressSanitizer/ms,
    'no alerts or sanitizer reports');

unlike($t->read_file('error.log'), qr/busy buffers/ms,
    'no busy buffers alerts');

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


sub http_head_body {
    my ($uri, $body) = @_;

    return http(
        "HEAD $uri HTTP/1.1" . CRLF
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


sub http_expect_continue {
    my ($uri, $body) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Expect: 100-continue" . CRLF
        . "Content-Length: " . length($body) . CRLF . CRLF;

    my $continue = read_headers($s);

    print $s $body;

    return $continue . read_response($s);
}


sub malformed_chunked {
    my ($uri) = @_;

    return http(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Transfer-Encoding: chunked" . CRLF . CRLF
        . "x" . CRLF
    );
}


sub http_timeout_wait_body {
    my ($uri) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: 1024" . CRLF . CRLF;

    return read_all($s);
}


sub close_before_body {
    my ($uri, $length) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . $length . CRLF . CRLF;

    close $s;
}


sub malformed_delayed_chunked {
    my ($uri) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Transfer-Encoding: chunked" . CRLF . CRLF
        . "5" . CRLF
        . "hello" . CRLF
        . "x" . CRLF;

    return read_all($s);
}


sub partial_content_length {
    my ($uri, $body, $length) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . $length . CRLF . CRLF
        . $body;

    close $s;
}


sub http_keepalive {
    my ($uri, $body1, $body2) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: keep-alive" . CRLF
        . "Content-Length: " . length($body1) . CRLF . CRLF
        . $body1;

    my $r1 = read_response($s);

    print $s "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . length($body2) . CRLF . CRLF
        . $body2;

    my $r2 = read_response($s);
    close $s;

    return ($r1, $r2);
}


sub http_abandon_keepalive {
    my ($uri, $body1, $body2, $chunked) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);

    my $first;

    if ($chunked) {
        $first = "POST $uri HTTP/1.1" . CRLF
            . "Host: localhost" . CRLF
            . "Connection: keep-alive" . CRLF
            . "Transfer-Encoding: chunked" . CRLF . CRLF
            . sprintf("%x", length($body1)) . CRLF
            . $body1 . CRLF
            . "0" . CRLF . CRLF;

    } else {
        $first = "POST $uri HTTP/1.1" . CRLF
            . "Host: localhost" . CRLF
            . "Connection: keep-alive" . CRLF
            . "Content-Length: " . length($body1) . CRLF . CRLF
            . $body1;
    }

    print $s $first
        . "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . length($body2) . CRLF . CRLF
        . $body2;

    my $r1 = read_response($s);
    my $r2 = read_optional_response($s);
    close $s;

    return ($r1, $r2);
}


sub read_response {
    my ($s) = @_;
    my ($buf, $body) = ('', '');
    my $headers = read_headers($s);

    die "missing content length\n"
        unless $headers =~ /^Content-Length:\s*(\d+)\x0d?$/mi;

    my $length = $1;

    while (length($body) < $length) {
        die "unexpected eof while reading body\n"
            unless sysread($s, $buf, $length - length($body));

        $body .= $buf;
    }

    return $headers . $body;
}


sub read_headers {
    my ($s) = @_;
    my ($buf, $headers) = ('', '');

    while ($headers !~ /\x0d?\x0a\x0d?\x0a/s) {
        die "unexpected eof while reading headers\n"
            unless sysread($s, $buf, 1);

        $headers .= $buf;
    }

    return $headers;
}


sub read_optional_response {
    my ($s) = @_;

    my $r = eval { read_response($s) };

    return defined $r ? $r : '';
}


sub read_all {
    my ($s) = @_;
    my $r = '';

    while (my $line = <$s>) {
        $r .= $line;
    }

    close $s;

    return $r;
}

###############################################################################
