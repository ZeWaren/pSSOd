pSSOd
=====

pSSOd is a collection of scripts that you can use to synchronize an Active Directory database (including passwords) with virtually everything, be it a sql database, an openldap server, a text file, or a samba passdb file.

How does it work
----------------

pSSOd is composed of several perl scripts:

+  `perlsync.pl`: fetches the user and groups from AD (excluding passwords, since you just can't).
+  `perlssod.pl`: provides a server for the *Password Synchronization* module from the role *Microsoft Identity Management for UNIX*, so you can get plain text passwords when they change.

For now, you can find more information at: [http://zewaren.net/site/?q=node/92]().

Non technical information
-------------------------
pSSOd was written in September 2012 by: ZeWaren / Erwan Martin <public@fzwte.net>.

It is licensed under the MIT License.

