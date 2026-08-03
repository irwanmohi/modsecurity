#!/usr/bin/perl
# paths.cgi
# Per-path engine mode: run a URL prefix (a CMS admin area, say) in a different
# ModSecurity mode from the rest of the site.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'path_title'}, "");

print "<p>",$text{'path_intro'},"</p>\n";

my @modes = ( [ "DetectionOnly", $text{'eng_detect'} ],
	      [ "Off", $text{'eng_off'} ],
	      [ "On", $text{'eng_on'} ] );

# --- Existing rules ---
my @ents = &list_path_engine();
if (@ents) {
	my @rows;
	foreach my $e (@ents) {
		my $rm = &can_access("toggle") ?
			&ui_link("remove_path.cgi?genid=".&urlize($e->{'genid'}),
				 $text{'exc_remove'}) : "";
		push(@rows, [
			"<tt>".&html_escape($e->{'path'})."</tt>",
			&html_escape($e->{'domain'} || $text{'path_alldoms'}),
			$e->{'mode'} eq 'On' ? $e->{'mode'}
					     : "<b>$e->{'mode'}</b>",
			$rm,
			]);
		}
	print &ui_columns_table(
		[ $text{'path_path'}, $text{'index_domain'}, $text{'dom_mode'}, "" ],
		100, \@rows);
	}
else {
	print "<p><i>",$text{'path_none'},"</i></p>\n";
	}

# --- Add a rule ---
my @doms = &list_domains();
print &ui_form_start("save_paths.cgi", "post");
print &ui_table_start($text{'path_add'}, "width=100%", 2);
print &ui_table_row($text{'path_path'},
	&ui_textbox("path", "", 40)."<br>".
	"<font size=-1>".$text{'path_path_hint'}."</font>");
print &ui_table_row($text{'index_domain'},
	@doms ? &ui_select("domain", "",
			[ [ "", $text{'path_alldoms'} ],
			  map { [ $_, $_ ] } @doms ])
	      : &ui_textbox("domain", "", 30)." ".$text{'path_dom_hint'});
print &ui_table_row($text{'dom_mode'}, &ui_select("mode", "DetectionOnly", \@modes));
print &ui_table_end();
print &ui_form_end([ [ undef, $text{'path_addbtn'} ] ]);

print "<p><font size=-1>",$text{'path_order'},"</font></p>\n";

&modsec_footer("index.cgi", $text{'index_return'});
