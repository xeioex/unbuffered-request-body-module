#!/usr/bin/perl

# Tests for view mode.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(8);

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

        location /view {
            unbuffered_body view;
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8081;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
            add_header X-Body-Size $unbuffered_body_size always;
            add_header X-Body-State $unbuffered_body_state always;
        }
    }
}

EOF

$t->run_daemon(\&http_read_body_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my @bodies = ('', 'hello', '0123456789' x 512);

for my $body (@bodies) {
    my $r = http_body('/view', $body);
    like($r, qr/X-Body-Sha1: @{[ sha1_hex($body) ]}\x0d?$/ms,
        'sha1 content length ' . length($body));
    like($r, qr/^size=@{[ length($body) ]} sha1=@{[ sha1_hex($body) ]}\x0d?$/m,
        'upstream body content length ' . length($body));
}

my $chunked = http_chunked('/view', 'hello');
like($chunked, qr/X-Body-Sha1: @{[ sha1_hex('hello') ]}\x0d?$/ms,
    'sha1 chunked');
like($chunked, qr/^size=5 sha1=@{[ sha1_hex('hello') ]}\x0d?$/m,
    'upstream body chunked');

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

        } elsif (defined $headers{'transfer-encoding'}
                 && $headers{'transfer-encoding'} =~ /chunked/i)
        {
            $body = read_chunked($client);
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

sub read_chunked {
    my ($client) = @_;
    my $body = '';

    while (my $line = <$client>) {
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
