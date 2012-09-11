#!/usr/local/bin/perl -w
package SSOD;

# Provides a SSO Daemon to enable password synchronization between
# Microsoft's Active Directory and virtually anything.
#
# ZeWaren / Erwan Martin <public@fzwte.net>, http://zewaren.net
# License: MIT

use constant SSOD_SECRET => "8MRQH_Pa62637f3fG]3T";
use constant SSOD_TCP_HOST => "192.168.42.20";
use constant SSOD_TCP_PORT => 6677;
use constant SSOD_DEBUG_MODE => 0;

use strict;
use warnings;

if (!SSOD_DEBUG_MODE) {
    use base qw(Net::Server::Fork);
}
else {
    use IO::Socket::INET;
}
use Crypt::Random qw( makerandom_octet );
use Digest::SHA1  qw(sha1 sha1_hex sha1_base64);
use Crypt::ECB;
use Crypt::DES;
use MIME::Base64 qw(encode_base64);
use Log::Log4perl;

require perlssod_deskey;

use constant ERROR_SUCCESS => 0;
use constant ERROR_FILE_NOT_FOUND => 1;
use constant ERROR_LOCK_VIOLATION => 2;
use constant ERROR_CANNOT_OPEN_FILE => 3;
use constant ERROR_PASSWORD_NOT_UPDATED => 4;
use constant ERROR_PROTOCOL => 5;
use constant ERROR_BAD_USER_NAME => 6;
use constant ERROR_DECRYPTING => 7;
use constant ERROR_VERSION_NOT_SUPPORTED => 8;
use constant ERROR_BAD_PASSWORD => 9;
use constant ERROR_CANNOT_MAKE_MAPS => 10;
use constant ERROR_WRITE_FAULT => 11;
use constant ERROR_NO_USER_ENTRY => 12;
use constant ERROR_USER_LOGIN_DISABLED => 13;
use constant ERROR_USER_REFUSED => 14;
use constant ERROR_PASSWORD_EXPIRED => 15;
use constant ERROR_PASSWORD_CANT_CHANGE => 16;
use constant ERROR_HISTORY_CONFLICT => 17;
use constant ERROR_TOO_SHORT => 18;
use constant ERROR_TOO_RECENT => 19;
use constant ERROR_BAD_PASSWORD_FILE => 20;
use constant ERROR_BAD_SHADOW_FILE => 21;
use constant ERROR_COMPUTING_LASTCHG_FIELD => 22;
use constant ERROR_VERSION_NUMBER_MISMATCH => 23;
use constant ERROR_PASSWORD_LENGTH_LESS => 24;
use constant ERROR_UPDATE_PASSWORD_FILE => 25;
use constant LAST_ERROR_NUMBER => 25;

#
# is called when a new password change is notified
#
sub data_received_callback {
    my ($username, $password) = @_;

    my $logger = Log::Log4perl->get_logger();
    $logger->info(sprintf("Inside callback with user %s and password %s.", $username, $password));
    return 1;
}

#
# htonl
#
sub htonl_ssod {
    my @a = unpack('C*', pack('L', @_));
    return ($a[3]    )|
           ($a[2]<< 8)|
           ($a[1]<<16)|
           ($a[0]<<24);
}

#
# makes the hash from the secret and the two random strings
#
sub make_hash {
    my ($r1, $r2, $secret) = @_;
    my ($sha1, $bytes);

    $sha1 = Digest::SHA1->new;
    $sha1->add_bits($r1, 8*8);
    $sha1->add($secret);
    $sha1->add_bits($r2, 8*8);
    $sha1->add_bits("\x00\x00\x00\x00", 4*8);
    $sha1->add_bits("\x00\x00\x00\x00", 4*8);

    return $sha1->digest;
}

#
# extends the hash to get a 24 byte key
#
sub extend_hash_for_key {
    my ($bytes) = @_;
    my @bytes_a  = split //, $bytes;

    my $h1 = Digest::SHA1->new;
    my $h2 = Digest::SHA1->new;
    my @rgbBuff1 = ("\x36") x 64;
    my @rgbBuff2 = ("\x5C") x 64;

    for my $i (0..19) {
        $rgbBuff1[$i] = $rgbBuff1[$i] ^ $bytes_a[$i];
        $rgbBuff2[$i] = $rgbBuff2[$i] ^ $bytes_a[$i];
    }

    my $rgbBuff1 = pack('A' x 64, @rgbBuff1);
    my $rgbBuff2 = pack('A' x 64, @rgbBuff2);

    $h1->add_bits($rgbBuff1, 64*8);
    $h2->add_bits($rgbBuff2, 64*8);

    my $s1 = $h1->digest;
    my $s2 = $h2->digest;

    my $s = (substr $s1, 0, 20).(substr $s2, 0, 4);
    return $s;
}

#
# generates the checksum
#
sub generate_hash_for_verification {
    my ($KeyTable, $dwVersion, $dwMsgLength, $dwMsgType, $username, $password) = @_;

    my $sha1 = Digest::SHA1->new;
    $sha1->add_bits($KeyTable, 3*32*4*8);
    $sha1->add_bits(pack("L", $dwVersion), 4*8);
    $sha1->add_bits(pack("L", $dwMsgLength), 4*8);
    $sha1->add_bits(pack("L", $dwMsgType), 4*8);
    $sha1->add($username);
    $sha1->add($password);
    return $sha1->digest;
}

#
# triple des
#
sub triple_des_ssod {
    my ($pbIn, $key) = @_;

    my $crypt = Crypt::ECB->new;
    $crypt->padding(PADDING_NONE);
    $crypt->cipher('DES') || die $crypt->errstring;

    $crypt->key(substr($key, 16, 8));
    my $rgbEnc1 = $crypt->decrypt($pbIn);
    $crypt->key(substr($key, 8, 8));
    my $rgbEnc2 = $crypt->encrypt($rgbEnc1);
    $crypt->key(substr($key, 0, 8));
    my $enc = $crypt->decrypt($rgbEnc2);

    return $enc;
}

#
# handle a password change request
#
sub handle_request {
    my ($client_socket) = @_;
    my $logger = Log::Log4perl->get_logger();

    binmode $client_socket;

    $logger->debug("Sending random string.");
    my $r1 = makerandom_octet ( Size => 8*8 );
    print $client_socket pack("A8", $r1);

    $logger->debug("Reading packet.");
    my ($buffer, $version, $message_size, $message);
    read $client_socket, $buffer, 4;
    $version = unpack('N', $buffer);

    if ($version != 0) {
        $logger->error("Packet version is unsuported.");
        return ERROR_VERSION_NOT_SUPPORTED;
    }

    read $client_socket, $buffer, 4;
    $message_size = unpack('N', $buffer);

    read $client_socket, $buffer, ($message_size - 8);
    $message = $buffer;

    my( $message_type, $r2, $string ) = unpack( 'N A8 A*', $buffer );

    $logger->debug("Computing key.");
    my $h = make_hash $r1, $r2, SSOD_SECRET;
    my $key = extend_hash_for_key( $h );

    $logger->debug("Decrypting buffer.");
    my $count = 0;
    my $decrypted_buffer = '';
    while($count < length($string)) {
        $decrypted_buffer = $decrypted_buffer . triple_des_ssod(substr($string, $count, 8), $key);
        $count = $count + 8;
    }

    my ($username, $password, $message_check_data) = split(/\0/, $decrypted_buffer);

    $logger->debug("Checking packet checksum.");
    my @DESTable1 = des_get_key_table(substr($key, 0, 8));
    my @DESTable2 = des_get_key_table(substr($key, 8, 16));
    my @DESTable3 = des_get_key_table(substr($key, 16, 24));
    my @DES3Table;

    push @DES3Table, htonl_ssod($_) foreach (@DESTable1);
    push @DES3Table, htonl_ssod($_) foreach (@DESTable2);
    push @DES3Table, htonl_ssod($_) foreach (@DESTable3);

    $message_size = htonl_ssod($message_size);
    my $message_check_calculated = generate_hash_for_verification(pack('L*', @DES3Table), $version, $message_size, $message_type, $username, $password);

    if (!(encode_base64($message_check_calculated) eq encode_base64($message_check_data))) {
        $logger->error(sprintf("Error decrypting packet."));
        return ERROR_DECRYPTING;
    }

    $logger->info(sprintf("Calling callback with user %s.", $username));
    my $res = data_received_callback($username, $password);
    return ERROR_UPDATE_PASSWORD_FILE if (!$res);
    return ERROR_SUCCESS;
}

#
# process a network connection
#
sub process_request {
    my $self = shift;
    my $socket = $self->{server}->{client};
    my $logger = Log::Log4perl->get_logger();

    my $error = handle_request($socket);
    $logger->debug(sprintf("Error is %d", $error));

    my $version_number = 0;
    my $message_type = 1;
    my $message_size = 4*4;

    my $response_buffer = pack("N N N N", $version_number, $message_size, $message_type, $error);    
    print $socket $response_buffer;
}

#
# let's rock
#
if (!SSOD_DEBUG_MODE) {
    my $log_conf = q(
        log4perl.rootLogger              = INFO, LOGFILE
        log4perl.appender.LOGFILE           = Log::Log4perl::Appender::File
        log4perl.appender.LOGFILE.filename  = /var/log/pssod.log
        log4perl.appender.LOGFILE.mode      = append
        log4perl.appender.LOGFILE.layout    = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.LOGFILE.layout.ConversionPattern = %d %p %m %n
    );
    Log::Log4perl::init(\$log_conf);
    my $logger = Log::Log4perl->get_logger();

    $logger->info("Starting pSSOd.");
    SSOD->run(host => SSOD_TCP_HOST, port => SSOD_TCP_PORT, ipv => '4');
}
else {
    #Single connection version. Useful for debugging.
    my $log_conf = q(
        log4perl.rootLogger              = INFO, SCREEN
        log4perl.appender.SCREEN         = Log::Log4perl::Appender::Screen
        log4perl.appender.SCREEN.stderr  = 0
        log4perl.appender.SCREEN.layout  = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.SCREEN.layout.ConversionPattern = %d %p %m %n
    );
    Log::Log4perl::init(\$log_conf);
    my $logger = Log::Log4perl->get_logger();

    $logger->info("Starting pSSOd.");

    my $socket = new IO::Socket::INET (
        LocalHost => SSOD_TCP_HOST,
        LocalPort => SSOD_TCP_PORT,
        Proto => 'tcp',
        Listen => 5,
        Reuse => 1
    ) or die "Could not create socket: $!\n";

    my $client_socket = $socket->accept();

    my $error = handle_request $client_socket;
    $logger->debug(sprintf("Error is %d", $error));

    my $version_number = 0;
    my $message_type = 1;
    my $message_size = 4*4;

    my $response_buffer = pack("N N N N", $version_number, $message_size, $message_type, $error);    
    print $client_socket $response_buffer;

    while (<$client_socket>) {
        print "some unexpected data arrived\n";
    }

    $socket->close();
}

