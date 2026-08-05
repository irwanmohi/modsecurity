#!/usr/bin/perl
# remove_exclusion.cgi
# Remove a previously-applied exclusion and reload Apache.
#
# Reached by a link, so the first request only offers the confirmation; the
# removal itself requires a POST from that form. Removing an exclusion puts a
# rule back into effect, which can start blocking a site that was working, so
# it is worth a deliberate second step as well as being the safer shape.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'exc_rmerr'});
&can_access("remove") || &error($text{'allow_eacl'});

my $genid = $in{'genid'};
$genid =~ /^\d+$/ || &error($text{'exc_badid'});

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'exc_title'}, "");
	print &ui_form_start("remove_exclusion.cgi", "post");
	print &ui_hidden("genid", $genid);
	print &ui_hidden("confirm", 1);
	print "<p>",&text('exc_rusure', $genid),"</p>\n";
	print &ui_form_end([ [ undef, $text{'exc_remove'} ] ]);
	&modsec_footer("list_exclusions.cgi", $text{'exc_return'});
	exit;
	}

&require_post();
my ($ok, $err) = &remove_exclusion($genid);
&error($err) if (!$ok);
&redirect("list_exclusions.cgi");
