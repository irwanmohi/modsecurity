#!/usr/bin/perl
# remove_path.cgi
# Remove one per-path engine rule and reload.
#
# Reached by a link, so the first request only offers the confirmation and the
# removal itself requires a POST from that form. Dropping a path rule restores
# the site-wide engine mode for that path, which may start blocking an admin
# area that was deliberately left in DetectionOnly.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'path_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

my $genid = $in{'genid'};
$genid =~ /^\d+$/ || &error($text{'exc_badid'});

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'path_title'}, "");
	print &ui_form_start("remove_path.cgi", "post");
	print &ui_hidden("genid", $genid);
	print &ui_hidden("confirm", 1);
	print "<p>",&text('path_rusure', $genid),"</p>\n";
	print &ui_form_end([ [ undef, $text{'path_remove'} ] ]);
	&modsec_footer("paths.cgi", $text{'path_return'});
	exit;
	}

&require_post();
my ($ok, $err) = &remove_path_engine($genid);
$ok || &error($err);
&redirect("paths.cgi");
