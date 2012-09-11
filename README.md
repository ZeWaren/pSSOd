pSSOd
=====

pSSOd is a collection of scripts that you can use to synchronize an Active Directory database (including passwords) with virtually everything, be it a sql database, an openldap server, a text file, or a samba passdb file.

How does it work
----------------

pSSOd is composed of several perl scripts:

+  `perlsync.pl`: fetches the user and groups from AD (excluding passwords, since you just can't).
+  `perlssod.pl`: provides a server for the *Password Synchronization* module from the role *Microsoft Identity Management for UNIX*, so you can get plain text passwords when they change.

For now, you can find more information at: [http://zewaren.net/site/?q=node/92](http://zewaren.net/site/?q=node/92).

Installation
------------

Copy the perl files where you desire and run/start them as you wish. 

`perlsync.pl` can be called periodically using cron if you run it on an UNIX platform.

### Dependencies
You will need Perl and the following modules:

+ `Net::LDAP`
+ `Digest::SHA1`
+ `Crypt::ECB`
+ `Crypt::DES`
+ `MIME::Base64`
+ `Log::Log4perl`
+ `Data::Dumper` (if you first want to dump the data)
+ `DBI` and the relevant drivers (if you want to store the information into a SQL database)
+ `Apache::Htpasswd` and `Apache::Htgroup` (if you want to store the information into htpasswd and htgroup files)

#### Debian (squeeze)
Install the following packages using aptitude or dpkg:

+ `libnet-ldap-perl`
+ `libnet-server-perl`
+ `libdigest-sha1-perl`
+ `libcrypt-ecb-perl`
+ `libcrypt-des-perl`
+ `liblog-log4perl-perl`
+ `libdbi-perl` and the relevant drivers (`libdbd-mysql-perl`, `libdbd-pg-perl`, `libdbd-sqlite3-perl`, etc.) (if you want to store the information into a SQL database)
+ `libapache-htpasswd-perl` (if you want to store the information into htpasswd and htgroup files)

Install the following modules using cpan:

+ `Apache::Htgroup` (if you want to store the information into htpasswd and htgroup files)

#### FreeBSD (8 and later)
Install the following ports:

+ `net/p5-perl-ldap`
+ `net/p5-Net-Server`
+ `security/p5-Digest-SHA1`
+ `security/p5-Crypt-ECB`
+ `security/p5-Crypt-DES`
+ `devel/p5-Log-Log4perl`
+ `databases/p5-DBI` and the relevant drivers (`databases/p5-DBD-mysql`, `databases/p5-DBD-Pg`, `databases/p5-DBD-SQLite`, etc.) (if you want to store the information into a SQL database)
+ `security/p5-Apache-Htpasswd` and `www/p5-Apache-Htgroup` (if you want to store the information into htpasswd and htgroup files)


Non technical information
-------------------------
pSSOd was written in September 2012 by: ZeWaren / Erwan Martin <<public@fzwte.net>>.

It is licensed under the MIT License.

