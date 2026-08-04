#!/usr/bin/perl
# allow.cgi
# Confirm and apply a rule exclusion (whitelist a whole rule, or just one
# parameter, for a domain or globally).

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'allow_err'});
&can_access("allow") || &error($text{'allow_eacl'});

my $id = $in{'id'};
my $dom = $in{'domain'};

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'allow_title'}, "");
	print &ui_form_start("allow.cgi", "post");
	print &ui_hidden("id", $id);
	print &ui_hidden("domain", $dom);
	print &ui_hidden("confirm", 1);
	print "<p>",($dom ? &text('allow_rusure_dom', $id, $dom)
			  : &text('allow_rusure_all', $id)),"</p>\n";

	# Allowing a scoring rule disables the blocking mechanism itself.
	if (&is_aggregate_rule($id)) {
		print "<p><font color=#cc0000><b>",$text{'allow_aggregate'},
		      "</b></font></p>\n";
		}

	# Offer the fields this rule has actually fired on, read from the logs.
	my @targets = &rule_targets($id, $dom);
	print &ui_table_start($text{'allow_scope'}, "width=100%", 2);
	print &ui_table_row($text{'allow_target'},
		&ui_select("target", "",
			[ [ "", $text{'allow_whole'} ],
			  map { [ $_, $_ ] } @targets ])."<br>".
		"<font size=-1>".(@targets ? $text{'allow_target_seen'}
					   : $text{'allow_target_none'})."</font>");
	print &ui_table_row($text{'allow_other'},
		&ui_textbox("othertarget", "", 30)."<br>".
		"<font size=-1>".$text{'allow_other_hint'}."</font>");
	print &ui_table_end();
	print "<p><font size=-1>",$text{'allow_explain'},"</font></p>\n";
	print &ui_form_end([ [ undef, $text{'allow_ok'} ] ]);
	&modsec_footer("index.cgi", $text{'index_return'});
	exit;
	}

# A typed field wins over the dropdown; empty means the whole rule.
my $target = $in{'othertarget'} =~ /\S/ ? $in{'othertarget'} : $in{'target'};
$target =~ s/^\s+|\s+$//g;
my ($ok, $err) = &add_exclusion($id, $dom, $target);
&error($err) if (!$ok);
&redirect("index.cgi".($dom ? "?domain=".&urlize($dom) : ""));
