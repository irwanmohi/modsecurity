#!/usr/bin/perl
# byip.cgi
# Show ModSecurity events grouped by client IP, with quick actions to
# whitelist (trust) or block each IP.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'byip_title'}, "");

my @events = &parse_blocks();
if (!@events) {
	print "<p>",$text{'byip_none'},"</p>\n";
	&modsec_footer("index.cgi", $text{'index_return'});
	exit;
	}

my @ips = &group_by_ip(\@events);
@ips = @ips[0 .. 99] if (@ips > 100);

my %wl = map { $_ => 1 } &get_ip_whitelist();
my %bl = map { $_ => 1 } &get_ip_blocklist();

print "<p>",$text{'byip_intro'},"</p>\n";

my @rows;
foreach my $g (@ips) {
	my $ip = $g->{'ip'};
	my @doms = sort keys %{$g->{'domains'}};
	my $domcell = @doms ? &html_escape(join(", ", @doms)) : "-";

	my $act;
	if ($wl{$ip}) {
		$act = "<font color=#3a7d5d>$text{'byip_iswl'}</font>";
		}
	elsif ($bl{$ip}) {
		$act = "<font color=#cc0000>$text{'byip_isbl'}</font>";
		}
	else {
		$act = &ui_link("whitelist_ip.cgi?ip=".&urlize($ip), $text{'byip_wl'}).
		       " &nbsp;|&nbsp; ".
		       &ui_link("block_ip.cgi?ip=".&urlize($ip), $text{'byip_bl'});
		}

	push(@rows, [
		"<b>".&html_escape($ip)."</b>",
		$g->{'count'},
		$g->{'blocked'} ? "<font color=#cc0000>$g->{'blocked'}</font>" : "0",
		$domcell,
		&html_escape($g->{'last_id'}),
		$act,
		]);
	}

print &ui_columns_table(
	[ $text{'tail_client'}, $text{'index_hits'}, $text{'index_block'},
	  $text{'index_domain'}, $text{'byip_lastrule'}, "" ],
	100, \@rows);

print "<p>",&ui_link("ipwhitelist.cgi", $text{'index_ipwhitelist'}),
      " &nbsp;|&nbsp; ",&ui_link("ipblock.cgi", $text{'index_ipblock'}),"</p>\n";

&modsec_footer("index.cgi", $text{'index_return'});
