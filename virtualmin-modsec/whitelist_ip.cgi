#!/usr/bin/perl
# whitelist_ip.cgi
# Confirm and add an IP to the trusted whitelist (bypasses ModSecurity).

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'byip_wlerr'});
&can_access("toggle") || &error($text{'eng_eacl'});

my $ip = $in{'ip'};

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'byip_wl'}, "");
	print &ui_form_start("whitelist_ip.cgi", "post");
	print &ui_hidden("ip", $ip);
	print &ui_hidden("confirm", 1);
	print "<p>",&text('byip_wlsure', &html_escape($ip)),"</p>\n";
	print &ui_form_end([ [ undef, $text{'byip_wl'} ] ]);
	&modsec_footer("byip.cgi", $text{'byip_return'});
	exit;
	}

&require_post();
my ($ok, $err) = &add_ip_whitelist($ip);
&error($err) if (!$ok);
&redirect("byip.cgi");
