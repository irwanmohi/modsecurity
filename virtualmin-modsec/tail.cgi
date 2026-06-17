#!/usr/bin/perl
# tail.cgi
# Live view of the most recent ModSecurity events, auto-refreshing.

require './modsec-lib.pl';
&ReadParse();

my $refresh = $in{'refresh'};
$refresh = 5 if ($refresh !~ /^\d+$/);
my $limit = 50;

# Inject a meta-refresh into the page head (0 = no auto refresh).
my $head = $refresh ? "<meta http-equiv=\"refresh\" content=\"$refresh\">" : "";
&ui_print_header(undef, $text{'tail_title'}, "", undef, 1, 1, 0, undef, undef,
		 $head);

# Refresh interval chooser.
print &ui_form_start("tail.cgi", "get");
print $text{'tail_every'}," ";
print &ui_select("refresh", $refresh,
	[ [ 0, $text{'tail_off'} ], [ 2, "2s" ], [ 5, "5s" ],
	  [ 10, "10s" ], [ 30, "30s" ] ]);
print " ",&ui_submit($text{'tail_apply'});
print &ui_form_end();

my @events = reverse &parse_blocks();   # newest first
if (!@events) {
	print "<p>",$text{'tail_none'},"</p>\n";
	&modsec_footer("index.cgi", $text{'index_return'});
	exit;
	}
@events = @events[0 .. $limit - 1] if (@events > $limit);

my @rows;
foreach my $e (@events) {
	my $badge = $e->{'action'} eq 'warning' ? $text{'index_warn'}
		   : "<font color=#cc0000>$text{'index_block'}</font>";
	push(@rows, [
		&html_escape($e->{'time'}),
		$badge,
		"<b>".&html_escape($e->{'id'})."</b>",
		&html_escape($e->{'hostname'} || "-"),
		&html_escape($e->{'client'} || "-"),
		"<tt>".&html_escape($e->{'uri'})."</tt>",
		&html_escape($e->{'msg'}),
		]);
	}
print &ui_columns_table(
	[ $text{'tail_time'}, $text{'index_block'}, $text{'index_ruleid'},
	  $text{'index_domain'}, $text{'tail_client'}, $text{'index_uri'},
	  $text{'index_message'} ],
	100, \@rows);

&modsec_footer("index.cgi", $text{'index_return'});
