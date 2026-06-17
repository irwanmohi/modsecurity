#!/usr/bin/perl
# save_ipblock.cgi
# Apply the IP blocklist from ipblock.cgi.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'ipbl_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

my @ips = split(/[\s,]+/, $in{'ips'});
my ($ok, $err) = &set_ip_blocklist(\@ips);
$ok || &error($err);
&redirect("index.cgi");
