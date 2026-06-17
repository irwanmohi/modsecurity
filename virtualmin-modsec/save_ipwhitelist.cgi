#!/usr/bin/perl
# save_ipwhitelist.cgi
# Apply the trusted-IP whitelist from ipwhitelist.cgi.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'ip_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

# Accept IPs separated by newlines, spaces or commas.
my @ips = split(/[\s,]+/, $in{'ips'});
my ($ok, $err) = &set_ip_whitelist(\@ips);
$ok || &error($err);
&redirect("index.cgi");
