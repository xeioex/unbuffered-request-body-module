#!/usr/bin/perl

# Client abort tests while reading request bodies.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

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
            add_header X-Body-State $unbuffered_body_state always;
        }
    }
}

EOF

$t->run_daemon(\&http_read_body_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

partial_content_length('/content', 'partial', 1024);
like(raw_content_length('/content', 'after'), response_re('after'),
    'content client abort recovery');

partial_content_length('/access', 'partial', 1024);
like(raw_content_length('/access', 'after'), qr/X-Body-State: done\x0d?$/ms,
    'access client abort recovery');

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
        . $body
    );

    return read_all($s);
}

sub partial_content_length {
    my ($uri, $body, $length) = @_;

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
        . "Content-Length: " . $length . CRLF . CRLF
        . $body
    );

    close $s;

    select undef, undef, undef, 0.1;
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
        my $payload = 'ok' . CRLF;

        print $client 'HTTP/1.1 200 OK' . CRLF;
        print $client 'Connection: close' . CRLF;
        print $client 'Content-Length: ' . length($payload) . CRLF;
        print $client CRLF;
        print $client $payload;

        close $client;
    }
}

###############################################################################
