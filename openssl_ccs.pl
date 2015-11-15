#!/usr/bin/perl
#
# Test for OpenSSL CVE-2014-0224
#
# This sends Change Cipher Spec record too early and observes server reply to
# see if it responds with alert (i.e. if it's patched)

use strict;
#use warnings;

use IO::Socket;


if (!defined($ARGV[0])) {
	print STDERR "usage: $0 hostname [port]\n";
	exit 1;
}

my $host = $ARGV[0];
my $port = 443;

if (defined($ARGV[1])) {
	$port = $ARGV[1];
}

my $sock= new IO::Socket::INET(
		PeerAddr	=>	$host,
		PeerPort	=>	$port,
		Proto		=> 'tcp',
	) or die "error: Could not create socket: $!\n";


# create client hello packet
sub make_clienthello {
	my $data = '';

	$data .= "\x16\x03\x01";	# hs + ver
	$data .= "\x00\x5f";		# len 1

	$data .= "\x01";			# client hello
	$data .= "\x00\x00\x5b";	# len 2
	$data .= "\x03\x01";		# ver

	# random
	$data .= pack('N', time());
	for (my $i = 0; $i < 7; $i++) {
		$data .= pack('N', int(rand(0xffffffff)));
	}

	$data .= "\x00";			# session id len

	# ciphers
	$data .= "\x00\x2c";
	$data .= "\x00\x39\x00\x38\x00\x35\x00\x16\x00\x13\x00\x0a";
	$data .= "\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x2f\x00\x96";
	$data .= "\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14";
	$data .= "\x00\x11\x00\x08\x00\x06\x00\x03";

	$data .= "\x02\x01\x00";	# compression

	# renegotiation_info extension
	$data .= "\x00\x05\xff\x01\x00\x01\x00";

	return $data;
}

# send client hello
my $pkt = make_clienthello();
print $sock $pkt;

# send change cipher spec
$pkt = "\x14\x03\x01\x00\x01\x01";
print $sock $pkt;


# simple parsing of response, only to print record types
sub print_pkt_details {
	my $pkt = shift;
	my $pktlen = shift;

	my $idx = 0;

	while ($idx < $pktlen) {
		# get record type
		my $rectype = ord(substr($pkt, $idx, 1));
		my $reclen = unpack("n", substr($pkt, $idx + 3, 2));
		#print "rectype: $rectype, reclen $reclen\n";
		
		if ($rectype == 22) {
			# handshake record
			my $hstype = ord(substr($pkt, $idx + 5, 1));
			#print "hstype: $hstype\n";

			if ($hstype == 2) {
				print "- Handshake - Server Hello\n";
			} elsif ($hstype == 11) {
				print "- Handshake - Certificate\n";
			} elsif ($hstype == 12) {
				print "- Handshake - Server Key Exhange\n";
			} elsif ($hstype == 14) {
				print "- Handshake - Server Hello Done\n";
			} else {
				print "- Handshake - unknown ($hstype)\n";
			}
		}

		elsif ($rectype == 21) {
			# alert record
			my $alertdesc = ord(substr($pkt, $idx + 6, 1));

			if ($alertdesc == 10) {
				print "- Alert - Unexpected Message\n";
				return 2;
			} else {
				print "- Alert - unknown ($alertdesc)\n";
				return 1;
			}
		}

		$idx += $reclen + 5;
	}

	return 0;
}

my $timeout = 5;
my $chunksize = 1024;
my $rv = 1;

$pkt = '';
my $pktlen = 0;

while (1) {
	my $part;
	my $ret;

	# read with timeout
	eval {
        local $SIG{ALRM} = sub { die "alarm\n" };
        alarm $timeout;
		$ret = sysread($sock, $part, $chunksize);
        alarm 0;
    };

    if ($@) {
        die unless $@ eq "alarm\n";   # propagate unexpected errors

        # timed out
		print "FAIL Remote host is affected\n";
		last;
    }

	if (!defined($ret)) {
		print STDERR "sysread error: $!\n";
	}

	if ($ret == 0) {
		print "ERROR Remote side closed connection\n";
		last;
	}

	$pkt .= $part;
	$pktlen += $ret;

	next if ($ret == $chunksize);

	print "Got server response, size: $pktlen\n";

	$ret = print_pkt_details($pkt, $pktlen);
	if ($ret > 0) {
		if ($ret == 2) {
			print "PASS Remote host is not affected\n";
			$rv = 1;
		} elsif ($ret == 1) {
			print "ERROR Remote host is probably not affected\n";
		}
		last;
	}

	$pkt = '';
	$pktlen = 0;
}

close($sock);
exit ($rv);

