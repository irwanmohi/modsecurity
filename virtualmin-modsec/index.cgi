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
my @logs = &log_files();
print &ui_table_row($text{'index_logs'},
	scalar(@logs)." &nbsp; <font size=-1><a href=logs.cgi>"
	.$text{'index_logs_view'}."</a></font>");
print &ui_table_end();
print "<p>",&ui_link("engine.cgi", $text{'index_settings'}),
      " &nbsp;|&nbsp; ",&ui_link("domains.cgi", $text{'index_perdomain'}),
      " &nbsp;|&nbsp; ",&ui_link("ipwhitelist.cgi", $text{'index_ipwhitelist'}),
      " &nbsp;|&nbsp; ",&ui_link("tail.cgi", $text{'index_livelog'}),
      " &nbsp;|&nbsp; ",&ui_link("stats.cgi", $text{'index_stats'}),
      " &nbsp;|&nbsp; ",&ui_link("backups.cgi", $text{'index_backups'}),"</p>\n";

# --- Blocked rules table ---
my @events = &parse_blocks();
if (!@events) {
	my $n = scalar(&log_files());
	print &text('index_none', $n),"<p>\n";
	&modsec_footer("/", $text{'index'});
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

# Hide groups already fully allowed (whole-rule exclusions, global or matching
# this domain). Per-parameter exclusions don't count as fully allowed.
my %allowed;
foreach my $e (&list_exclusions()) {
	next if ($e->{'target'});
	$allowed{$e->{'ruleid'}."\0".($e->{'domain'} || "")} = 1;
	}
my $hidden = 0;

my @rows;
foreach my $g (@groups) {
	next if ($filter ne "" && $g->{'hostname'} ne $filter);
	if ($allowed{$g->{'id'}."\0"} ||
	    $allowed{$g->{'id'}."\0".($g->{'hostname'} || "")}) {
		$hidden++;
		next;
		}
	my $allow = &ui_link("allow.cgi?id=".&urlize($g->{'id'}).
			     "&domain=".&urlize($g->{'hostname'}),
			     $text{'index_allow'});
	my $badge = $g->{'action'} eq 'blocked' ?
		"<font color=#cc0000>$text{'index_block'}</font>" : $text{'index_warn'};
	push(@rows, [
		"<b>$g->{'id'}</b>",
		&html_escape($g->{'hostname'} || "-"),
		$badge,
		$g->{'count'},
		&html_escape($g->{'msg'}),
		"<tt>".&html_escape($g->{'last_uri'})."</tt>",
		$allow,
		]);
	}

print &ui_columns_table(
	[ $text{'index_ruleid'}, $text{'index_domain'}, $text{'index_action'},
	  $text{'index_hits'}, $text{'index_message'}, $text{'index_uri'}, "" ],
	100, \@rows);

if ($hidden) {
	print "<p><i>",&text('index_hidden', $hidden),"</i></p>\n";
	}

# Link to existing exclusions
print "<p>",&ui_link("list_exclusions.cgi", $text{'index_managed'}),"</p>\n";

&modsec_footer("/", $text{'index'});
