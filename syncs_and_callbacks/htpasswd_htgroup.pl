#Do not run this file directly.
exit;

#
# Code to be used with pSSOd to synchronize AD with htpasswd and htgroup files
#
# ZeWaren / Erwan Martin <public@fzwte.net>, http://zewaren.net
# License: MIT

#------------------------------------------------------------------------------
# Copy this part into perlsync.pl
#------------------------------------------------------------------------------

use constant HTPASSWD_FILE => '.htpasswd';
use constant HTGROUP_FILE  => '.htgroup';

#
#Synchronize into htpasswd
#
use Data::Dumper;
use Apache::Htpasswd;
use Crypt::Random qw( makerandom_octet );
use MIME::Base64 qw( encode_base64 );

my $fh = new Apache::Htpasswd(HTPASSWD_FILE);
my $old_users = {};
foreach $a ($fh->fetchUsers()) {
  $old_users->{$a} = 0;
}

#adds the new user
foreach my $auser ( keys %$users ) {
  if (!exists $old_users->{$users->{$auser}->{'accountname'}}) {
    #new user: create it with a random password
    my @random_array = ();
    push @random_array, int(rand(255)) for (0..7);
    my $new_password = encode_base64(pack('C*', @random_array));
    $fh->htpasswd($users->{$auser}->{'accountname'}, $new_password);
  }
  $fh->writeInfo($users->{$auser}->{'accountname'}, $users->{$auser}->{'name'});
  $old_users->{$users->{$auser}->{'accountname'}} = 1;
}

#delete the removed users
foreach $a ( keys %$old_users ) {
  if (!$old_users->{$a}) {
    $fh->htDelete($a);
  }
}

#
#Synchronize into htgroup
#
use Apache::Htgroup;

unlink(HTGROUP_FILE) if (-e HTGROUP_FILE);
$fh = Apache::Htgroup->new();
foreach my $agroup ( keys %$groups_to_send ) {
  foreach my $uname (@{ $groups_to_send->{$agroup}->{'users'} }) {
    $fh->adduser( $uname, $agroup );
  }
}
$fh->save(HTGROUP_FILE);

#------------------------------------------------------------------------------
# Copy this part into perlssod.pl
#------------------------------------------------------------------------------

use constant HTPASSWD_FILE => '.htpasswd';

sub data_received_callback {
    my ($username, $password) = @_;
    my $logger = Log::Log4perl->get_logger();
    $logger->info(sprintf("Updating htpasswd file for user %s.", $username));

    use Apache::Htpasswd;
    my $fh = new Apache::Htpasswd(HTPASSWD_FILE);
    my @users = $fh->fetchUsers();
    return 0 if !(grep $_ eq $username, @users);

    $fh->htpasswd($username, $password, {'overwrite' => 1});
    return 1;
}
