#!/usr/bin/perl
# index.cgi
# Dashboard: show ModSecurity engine state and blocked/triggered rules,
# grouped by rule id and Virtualmin domain.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'index_title'}, "", "intro", 1, 1);

# --- Engine status banner ---
my $state = &get_engine_state();
my $statetext = $state ? $state : $text{'index_unknown'};
print &ui_table_start($text{'index_status'}, "width=100%", 2);
print &ui_table_row($text{'index_engine'}, "<b>$statetext</b>");
print &ui_table_row($text{'index_conf'}, "<tt>$config{'modsec_conf'}</tt>");
print &ui_table_end();
print "<p>",&ui_link("engine.cgi", $text{'index_settings'}),"</p>\n";

# --- Blocked rules table ---
my @events = &parse_blocks();
if (!@events) {
	print &text('index_none', "<tt>$config{'error_log'}</tt>"),"<p>\n";
	&ui_print_footer("/", $text{'index'});
	exit;
	}
my @groups = &group_blocks(\@events);

# Domain filter
my %domseen;
$domseen{$_->{'hostname'}}++ foreach (@groups);
my @domlist = sort grep { $_ ne "" } keys %domseen;
my $filter = $in{'domain'};

print &ui_form_start("index.cgi", "get");
print $text{'index_filterby'}," ";
print &ui_select("domain", $filter,
	[ [ "", $text{'index_alldoms'} ], map { [ $_, $_ ] } @domlist ]);
print " ",&ui_submit($text{'index_filter'});
print &ui_form_end();

my @rows;
foreach my $g (@groups) {
	next if ($filter ne "" && $g->{'hostname'} ne $filter);
	my $allow = &ui_link("allow.cgi?id=".&urlize($g->{'id'}).
			     "&domain=".&urlize($g->{'hostname'}),
			     $text{'index_allow'});
	my $badge = $g->{'action'} eq 'warning' ?
		$text{'index_warn'} : "<font color=#cc0000>$text{'index_block'}</font>";
	push(@rows, [
		"<b>$g->{'id'}</b>",
		&html_escape($g->{'hostname'} || "-"),
		$g->{'count'},
		&html_escape($g->{'msg'}),
		"<tt>".&html_escape($g->{'last_uri'})."</tt>",
		$allow,
		]);
	}

print &ui_columns_table(
	[ $text{'index_ruleid'}, $text{'index_domain'}, $text{'index_hits'},
	  $text{'index_message'}, $text{'index_uri'}, "" ],
	100, \@rows);

# Link to existing exclusions
print "<p>",&ui_link("list_exclusions.cgi", $text{'index_managed'}),"</p>\n";

&ui_print_footer("/", $text{'index'});
