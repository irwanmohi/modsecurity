#!/usr/bin/perl
# domains.cgi
# Per-domain engine mode: set ModSecurity to Default / On / DetectionOnly / Off
# for each Virtualmin domain individually.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'dom_title'}, "");

my %map = &list_domain_engine();

# Build the domain list: Virtualmin domains + any already-configured domains.
my @doms = &list_domains();
my %seen;
$seen{$_}++ foreach (@doms);
foreach my $d (sort keys %map) { push(@doms, $d) if (!$seen{$d}++); }

print "<p>",$text{'dom_intro'},"</p>\n";

my @modes = ( [ "default", $text{'dom_default'} ],
	      [ "On", $text{'eng_on'} ],
	      [ "DetectionOnly", $text{'eng_detect'} ],
	      [ "Off", $text{'eng_off'} ] );

print &ui_form_start("save_domains.cgi", "post");
if (@doms) {
	my @rows;
	foreach my $d (@doms) {
		my $cur = $map{$d} || "default";
		push(@rows, [ "<tt>".&html_escape($d)."</tt>",
			      &ui_select("mode_".$d, $cur, \@modes) ]);
		}
	print &ui_columns_table([ $text{'index_domain'}, $text{'dom_mode'} ],
				100, \@rows);
	print &ui_hidden("domains", join(",", @doms));
	}
else {
	print "<p>",$text{'dom_nodoms'},"</p>\n";
	}

# Manual entry — works even if the Virtualmin domain list is unavailable.
print &ui_table_start($text{'dom_manual'}, "width=100%", 2);
print &ui_table_row($text{'index_domain'}, &ui_textbox("newdom", "", 30));
print &ui_table_row($text{'dom_mode'}, &ui_select("newmode", "Off", \@modes));
print &ui_table_end();

print &ui_form_end([ [ undef, $text{'eng_save'} ] ]);

&modsec_footer("index.cgi", $text{'index_return'});
