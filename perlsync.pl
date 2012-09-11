#!/usr/local/bin/perl

#
# Fetch users and groups from an Active Directory server.
# 
# ZeWaren / Erwan Martin <public@fzwte.net>, http://zewaren.net
# License: MIT

use constant LDAP_HOST => "192.168.42.10";
use constant LDAP_USER => "aduser\@grandopen.zwm.fr";
use constant LDAP_PASSWORD => "abcd1234___";
use constant LDAP_BASE => "DC=grandopen,DC=zwm,DC=fr";

use strict;
use warnings;

use Net::LDAP;
my $ldapsrc = Net::LDAP->new(LDAP_HOST) or die "$@";
my $mesg = $ldapsrc->bind(LDAP_USER, password=>LDAP_PASSWORD, version => 3);
my $base = LDAP_BASE;

#
#Fetch groups from AD
#
my $base_groups = "CN=Users".",$base";
my $filter_groups = "(objectClass=group)";
my $attrs_groups = ["sAMAccountName", "member", "description"];

my $result = $ldapsrc->search (base => "$base_groups", scope => "sub", filter => "$filter_groups", attrs => $attrs_groups);
my $entr;
my @entries = $result->entries;
my $groups = {};
foreach $entr ( @entries ) {
   my $agroup = {'name' => '', 'members' => []};

   my $attr;
   foreach $attr ( sort $entr->attributes ) {
     next if ( $attr =~ /;binary$/ );
     $agroup->{'members'} = $entr->get_value ( $attr, asref => 1 ) if ($attr =~ 'member');
     $agroup->{'name'} = $entr->get_value ( $attr ) if ($attr =~ 'sAMAccountName');
     $agroup->{'description'} = $entr->get_value ( $attr ) if ($attr =~ 'description');
   }
   $groups->{$entr->dn} = $agroup;
}

#
#Fetch users from AD
#
my $base_users = "CN=Users".",$base";
my $filter_users = "(objectClass=user)";
my $attrs_users = ["sAMAccountName", "name"];

$result = $ldapsrc->search (base => "$base_users", scope => "sub", filter => "$filter_users", attrs => $attrs_users);
@entries = $result->entries;
my $users = {};
foreach $entr ( @entries ) {
  my $auser = {'accountname' => '', 'name' => []};
  my $attr;
  foreach $attr ( sort $entr->attributes ) {
    next if ( $attr =~ /;binary$/ );
    $auser->{'name'} = $entr->get_value ( $attr ) if ($attr =~ 'name');
    $auser->{'accountname'} = $entr->get_value ( $attr ) if ($attr =~ 'sAMAccountName');
  }
  $users->{$entr->dn} = $auser;
}

#
#Construct the groups to synchronize
#
my $groups_to_send = {};
foreach my $agroup ( keys %$groups ) {
    #next unless (grep { $_ eq $groups->{$agroup}->{'name'} } @groups_to_sync);
    my $group_logins = [];
    foreach my $amember (@{ $groups->{$agroup}->{'members'} }) {
        push @$group_logins, $users->{$amember}->{"accountname"} if $users->{$amember};
    }
    $groups_to_send->{$groups->{$agroup}->{'name'}} = {'users' => $group_logins, 'description' => $groups->{$agroup}->{'description'}};
}

#
#Do something with the users and groups here.
#
