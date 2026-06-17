#!/usr/bin/perl
# list_exclusions.cgi
# Show all currently-applied exclusions with an option to remove each.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'exc_title'}, "");

my @ex = &list_exclusions();
if (!@ex) {
	print "<p>",$text{'exc_none'},"</p>\n";
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}

my @rows;
foreach my $e (@ex) {
	my $rm = &can_access("remove") ?
		&ui_link("remove_exclusion.cgi?genid=".&urlize($e->{'genid'}),
			 $text{'exc_remove'}) : "";
	push(@rows, [
		"<b>$e->{'ruleid'}</b>",
		&html_escape($e->{'domain'} || $text{'exc_alldoms'}),
		$rm,
		]);
	}
print &ui_columns_table(
	[ $text{'index_ruleid'}, $text{'index_domain'}, "" ],
	100, \@rows);

&ui_print_footer("index.cgi", $text{'index_return'});
