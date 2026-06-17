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
	# Show confirmation page with an optional parameter-scope field.
	&ui_print_header(undef, $text{'allow_title'}, "");
	print &ui_form_start("allow.cgi", "post");
	print &ui_hidden("id", $id);
	print &ui_hidden("domain", $dom);
	print &ui_hidden("confirm", 1);
	print "<p>",($dom ? &text('allow_rusure_dom', $id, $dom)
			  : &text('allow_rusure_all', $id)),"</p>\n";
	print &ui_table_start($text{'allow_scope'}, "width=100%", 2);
	print &ui_table_row($text{'allow_target'},
		&ui_textbox("target", "", 30)."<br>".
		"<font size=-1>".$text{'allow_target_hint'}."</font>");
	print &ui_table_end();
	print &ui_form_end([ [ undef, $text{'allow_ok'} ] ]);
	&modsec_footer("index.cgi", $text{'index_return'});
	exit;
	}

# Apply. Empty target = whole rule; a value = remove just that parameter.
my ($ok, $err) = &add_exclusion($id, $dom, $in{'target'});
&error($err) if (!$ok);
&redirect("index.cgi".($dom ? "?domain=".&urlize($dom) : ""));
