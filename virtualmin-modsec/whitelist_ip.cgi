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
	print &ui_confirmation_form(
		"whitelist_ip.cgi",
		&text('byip_wlsure', &html_escape($ip)),
		[ [ "ip", $ip ] ],
		[ [ "confirm", $text{'byip_wl'} ] ]);
	&modsec_footer("byip.cgi", $text{'byip_return'});
	exit;
	}

my ($ok, $err) = &add_ip_whitelist($ip);
&error($err) if (!$ok);
&redirect("byip.cgi");
