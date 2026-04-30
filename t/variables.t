#!/usr/bin/perl

# Variable state tests.

###############################################################################

use warnings;
use strict;

use IO::Socket::INET;
use Socket qw/ CRLF /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../../nginx-tests/lib';
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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /off {
            unbuffered_body off;
            add_header X-Body-State $unbuffered_body_state always;
            add_header X-Body-Size $unbuffered_body_size always;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
            return 200 "ok\n";
        }

        location /view {
            unbuffered_body view;
            add_header X-Body-State $unbuffered_body_state always;
            add_header X-Body-Size $unbuffered_body_size always;
            add_header X-Body-Sha1 $unbuffered_body_sha1 always;
            return 200 "ok\n";
        }

        location /consume {
            unbuffered_body consume_access;
            return 200 "$unbuffered_body_state\n";
        }
    }
}

EOF

$t->run();

###############################################################################

my $off = http_get('/off');
like($off, qr/X-Body-State: off\x0d?$/ms, 'state off before body');
like($off, qr/X-Body-Size: 0\x0d?$/ms, 'size off before body');
unlike($off, qr/X-Body-Sha1:/ms, 'sha1 off before body');

my $view = raw_content_length('/view', 'ignored');
like($view, qr/X-Body-State: view\x0d?$/ms, 'state view before body');
like($view, qr/X-Body-Size: 0\x0d?$/ms, 'size view before body');
unlike($view, qr/X-Body-Sha1:/ms, 'sha1 view before body');

like(http_get('/consume'), qr/^consume\x0d?$/m,
    'state consume before body');

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

###############################################################################
