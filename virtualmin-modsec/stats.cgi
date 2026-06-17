#!/usr/bin/perl
# stats.cgi
# Simple attack statistics: top rules, top domains, and blocked-vs-warning.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'stats_title'}, "");

my @events = &parse_blocks();
if (!@events) {
	print "<p>",$text{'stats_none'},"</p>\n";
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}

# Aggregate.
my (%byrule, %bydom, %byaction);
foreach my $e (@events) {
	$byrule{$e->{'id'}}++;
	$bydom{$e->{'hostname'} || "-"}++;
	$byaction{$e->{'action'}}++;
	}

# bar_table(\%counts, $label_heading, $limit) -> HTML table with proportional bars.
sub bar_table
{
my ($counts, $heading, $limit) = @_;
my @keys = sort { $counts->{$b} <=> $counts->{$a} } keys %$counts;
@keys = @keys[0 .. $limit - 1] if (@keys > $limit);
my $max = $counts->{$keys[0]} || 1;
my @rows;
foreach my $k (@keys) {
	my $w = int(220 * $counts->{$k} / $max) || 1;
	push(@rows, [
		&html_escape($k),
		$counts->{$k},
		"<div style='background:#3a7d5d;height:13px;width:${w}px'></div>",
		]);
	}
return &ui_columns_table([ $heading, $text{'stats_count'}, "" ], 100, \@rows);
}

print &ui_table_start($text{'stats_total'}, "width=100%", 2);
print &ui_table_row($text{'stats_events'}, scalar(@events));
print &ui_table_row($text{'index_block'},  ($byaction{'blocked'} || 0));
print &ui_table_row($text{'index_warn'},   ($byaction{'warning'} || 0));
print &ui_table_end();

print "<h3>",$text{'stats_toprules'},"</h3>\n";
print &bar_table(\%byrule, $text{'index_ruleid'}, 10);

print "<h3>",$text{'stats_topdomains'},"</h3>\n";
print &bar_table(\%bydom, $text{'index_domain'}, 10);

&ui_print_footer("index.cgi", $text{'index_return'});
