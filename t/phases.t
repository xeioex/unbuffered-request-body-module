#!/usr/bin/perl

# Phase interaction tests.

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

my $t = Test::Nginx->new()->has(qw/http proxy auth_request/)->plan(5);

$t->write_file('auth_static', 'ok');

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

        location /content-decline {
            unbuffered_body view;
        }

        location /off-proxy {
            unbuffered_body off;
            proxy_pass http://127.0.0.1:8081/echo;
        }

        location /subrequest {
            auth_request /auth-static;
            proxy_pass http://127.0.0.1:8081/echo;
        }

        location = /auth-static {
            unbuffered_body consume_content;
            alias %%TESTDIR%%/auth_static;
        }
    }
}

EOF

$t->run_daemon(\&http_read_body_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $off_proxy = raw_content_length('/off-proxy', 'plain body');
like($off_proxy, qr/^size=10 sha1=@{[ sha1_hex('plain body') ]}\x0d?$/m,
    'off proxy passes body');
unlike($off_proxy, qr/unbuffered_body/ms, 'off proxy no module output');

like(http_get('/content-decline'), qr/404 Not Found/ms,
    'content handler declined');

like(http_get('/subrequest'), qr/^size=0 sha1=@{[ sha1_hex('') ]}\x0d?$/m,
    'subrequest declined');

like(http_head('/content'), qr/200 OK/ms, 'content head request');

###############################################################################

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

        my $body = '';

        if (defined $headers{'content-length'}) {
            read($client, $body, $headers{'content-length'});
        }

        my $payload = 'size=' . length($body)
            . ' sha1=' . sha1_hex($body) . CRLF;

        print $client 'HTTP/1.1 200 OK' . CRLF;
        print $client 'Connection: close' . CRLF;
        print $client 'Content-Length: ' . length($payload) . CRLF;
        print $client CRLF;
        print $client $payload;

        close $client;
    }
}

###############################################################################
