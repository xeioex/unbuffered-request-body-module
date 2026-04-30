#!/usr/bin/perl

# Tricky request body transfer tests.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/ sha1_hex /;
use IO::Socket::INET;
use Socket qw/ CRLF /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../../nginx-tests/lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(11);

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

        location /access {
            unbuffered_body consume_access;
            proxy_pass http://127.0.0.1:8081/echo;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
            add_header X-Body-Size $unbuffered_body_size always;
            add_header X-Body-State $unbuffered_body_state always;
        }

        location /view {
            unbuffered_body view;
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8081/echo;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
        }
    }
}

EOF

$t->run_daemon(\&http_read_body_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $body = join('', map { chr(65 + ($_ % 26)) } 0 .. 127);

like(slow_chunked('/content', [ split //, $body ]), response_re($body),
    'content many one byte chunks');

like(raw_content_length('/content', $body), response_re($body),
    'content slow content length');

my $chunked_view = slow_chunked('/view', [ 'ab', 'cde', 'f' ],
    chunk_ext => ';foo=bar',
    trailer => 'X-Trailer: value' . CRLF);

like($chunked_view, qr/X-Body-Sha1: @{[ sha1_hex('abcdef') ]}\x0d?$/ms,
    'view chunk extensions sha1');
like($chunked_view, qr/^size=6 sha1=@{[ sha1_hex('abcdef') ]}\x0d?$/m,
    'view chunk extensions upstream');

my $access = slow_chunked('/access', [ split //, 'chunked-access' ]);

like($access, qr/X-Body-Sha1: @{[ sha1_hex('chunked-access') ]}\x0d?$/ms,
    'access many chunks sha1');
like($access, qr/X-Body-Size: 14\x0d?$/ms, 'access many chunks size');
like($access, qr/X-Body-State: done\x0d?$/ms, 'access many chunks state');
like($access, qr/^size=0 sha1=@{[ sha1_hex('') ]}\x0d?$/m,
    'access many chunks consumed upstream');

like(raw_content_length('/content', ''), response_re(''),
    'empty explicit content length');

like(malformed_chunked('/content'), qr/400 Bad Request/ms,
    'content malformed delayed chunked');

like(malformed_chunked('/access'), qr/400 Bad Request/ms,
    'access malformed delayed chunked');

###############################################################################

sub response_re {
    my ($body) = @_;
    my $sha1 = sha1_hex($body);
    my $size = length($body);

    return qr/sha1=$sha1 size=$size\x0d?$/ms;
}

sub raw_content_length {
    my ($uri, $body) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    )
        or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);
    $s->write(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Content-Length: " . length($body) . CRLF . CRLF
    );

    for my $ch (split //, $body) {
        select undef, undef, undef, 0.002;
        $s->write($ch);
    }

    return read_all($s);
}

sub malformed_chunked {
    my ($uri) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    )
        or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);
    $s->write(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Transfer-Encoding: chunked" . CRLF . CRLF
    );

    select undef, undef, undef, 0.05;
    $s->write("x" . CRLF);

    return read_all($s);
}

sub slow_chunked {
    my ($uri, $chunks, %opts) = @_;

    my $s = IO::Socket::INET->new(
        Proto => 'tcp',
        PeerAddr => '127.0.0.1:' . port(8080)
    )
        or die "Can't connect to nginx: $!\n";

    $s->autoflush(1);
    $s->write(
        "POST $uri HTTP/1.1" . CRLF
        . "Host: localhost" . CRLF
        . "Connection: close" . CRLF
        . "Transfer-Encoding: chunked" . CRLF . CRLF
    );

    for my $chunk (@$chunks) {
        select undef, undef, undef, 0.002;
        $s->write(sprintf("%x", length($chunk)));
        $s->write($opts{chunk_ext}) if defined $opts{chunk_ext};
        $s->write(CRLF . $chunk . CRLF);
    }

    $s->write("0" . CRLF);
    $s->write($opts{trailer}) if defined $opts{trailer};
    $s->write(CRLF);

    return read_all($s);
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

sub http_read_body_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalAddr => '127.0.0.1:' . port(8081),
        Listen => 5,
        Reuse => 1
    )
        or die "Can't create listening socket: $!\n";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my %headers;

        while (my $line = <$client>) {
            last if $line =~ /^\x0d?\x0a?$/;

            if ($line =~ /^([^:]+):\s*(.*?)\x0d?\x0a?$/) {
                $headers{lc $1} = $2;
            }
        }

        my $upstream_body = '';

        if (defined $headers{'content-length'}) {
            read($client, $upstream_body, $headers{'content-length'});

        } elsif (defined $headers{'transfer-encoding'}
                 && $headers{'transfer-encoding'} =~ /chunked/i)
        {
            $upstream_body = read_chunked($client);
        }

        my $payload = 'size=' . length($upstream_body)
            . ' sha1=' . sha1_hex($upstream_body) . CRLF;

        print $client 'HTTP/1.1 200 OK' . CRLF;
        print $client 'Connection: close' . CRLF;
        print $client 'Content-Length: ' . length($payload) . CRLF;
        print $client CRLF;
        print $client $payload;

        close $client;
    }
}

sub read_chunked {
    my ($client) = @_;
    my $body = '';

    while (my $line = <$client>) {
        $line =~ s/\x0d?\x0a$//;
        $line =~ s/;.*//;
        my $size = hex($line);
        last if $size == 0;

        my $chunk = '';
        read($client, $chunk, $size);
        $body .= $chunk;
        <$client>;
    }

    return $body;
}

###############################################################################
