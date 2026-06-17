#!/usr/bin/perl
# block_ip.cgi
# Confirm and add an IP to the blocklist (denied with 403).

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'byip_blerr'});
&can_access("toggle") || &error($text{'eng_eacl'});

my $ip = $in{'ip'};

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'byip_bl'}, "");
	print &ui_confirmation_form(
		"block_ip.cgi",
		&text('byip_blsure', &html_escape($ip)),
		[ [ "ip", $ip ] ],
		[ [ "confirm", $text{'byip_bl'} ] ]);
	&modsec_footer("byip.cgi", $text{'byip_return'});
	exit;
	}

my ($ok, $err) = &add_ip_blocklist($ip);
&error($err) if (!$ok);
&redirect("byip.cgi");
