#Do not run this file directly.
exit;

#
# Code to be used with pSSOd to synchronize AD with a SQL Database.
#
# ZeWaren / Erwan Martin <public@fzwte.net>, http://zewaren.net
# License: MIT

#------------------------------------------------------------------------------
# Create yourself a database with these queries if you need an example
#------------------------------------------------------------------------------
=mysql
CREATE DATABASE IF NOT EXISTS some_database;
USE some_database;

CREATE TABLE IF NOT EXISTS groups (
  name varchar(50) NOT NULL,
  description varchar(250) DEFAULT NULL,
  synced tinyint(4) DEFAULT NULL,
  PRIMARY KEY (name)
);

CREATE TABLE IF NOT EXISTS groups_users (
  group_name varchar(50) NOT NULL DEFAULT '',
  user_name varchar(50) NOT NULL DEFAULT '',
  PRIMARY KEY (group_name,user_name)
);

CREATE TABLE IF NOT EXISTS users (
  username varchar(50) NOT NULL,
  name varchar(250) DEFAULT NULL,
  password varchar(50) NOT NULL,
  synced tinyint(4) NOT NULL,
  PRIMARY KEY (username)
);
=cut

#------------------------------------------------------------------------------
# Copy this part into perlsync.pl
#------------------------------------------------------------------------------

#
#Synchronize into database
#

use constant DBI_URN => 'DBI:mysql:some_database';
use constant DBI_USER => 'asqluser';
use constant DBI_PASSWORD => 'asqluser';

use DBI;
my $dbh = DBI->connect(DBI_URN, DBI_USER, DBI_PASSWORD) or die "Couldn't connect to database: " . DBI->errstr;

#Users
$dbh->do('UPDATE users SET synced = 0');
my $sth = $dbh->prepare('REPLACE INTO users SET username = ?, name = ?, synced = 1') or die "Couldn't prepare statement: " . $dbh->errstr;
foreach my $auser ( keys %$users ) {
	$sth->execute($users->{$auser}->{'accountname'}, $users->{$auser}->{'name'});
}
$sth->finish;
$dbh->do('DELETE FROM users WHERE synced = 0;');

#Groups
$dbh->do('UPDATE groups SET synced = 0');
$sth = $dbh->prepare('REPLACE INTO groups SET name = ?, description = ?, synced = 1') or die "Couldn't prepare statement: " . $dbh->errstr;
foreach my $agroup ( keys %$groups_to_send ) {
	$sth->execute($agroup, $groups_to_send->{$agroup}->{'description'});
}
$sth->finish;
$dbh->do('DELETE FROM groups WHERE synced = 0');

#Group contents
$dbh->do('DELETE FROM groups_users');
$sth = $dbh->prepare('INSERT INTO groups_users SET user_name = ?, group_name = ?') or die "Couldn't prepare statement: " . $dbh->errstr;
foreach my $agroup ( keys %$groups_to_send ) {
	foreach my $uname (@{ $groups_to_send->{$agroup}->{'users'} }) {
		$sth->execute($uname, $agroup);
	}
}
$sth->finish;

$dbh->disconnect();

#------------------------------------------------------------------------------
# Copy this part into perlssod.pl
#------------------------------------------------------------------------------

use constant DBI_URN => 'DBI:mysql:some_database';
use constant DBI_USER => 'asqluser';
use constant DBI_PASSWORD => 'asqluser';

sub data_received_callback {
    my ($username, $password) = @_;

    my $logger = Log::Log4perl->get_logger();
    $logger->info(sprintf("Updating database for user %s.", $username));

    use DBI;
    my $dbh = DBI->connect(DBI_URN, DBI_USER, DBI_PASSWORD);
    if (!$dbh) {
        $logger->error("Couldn't connect to database: " . DBI->errstr);
        return 0;
    }
    $dbh->do('UPDATE users SET password = ? WHERE username = ? ', undef, $password, $username);
    $dbh->disconnect();
    return 1;
}

