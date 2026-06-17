#!/usr/bin/perl
# allow.cgi
# Confirm and apply a rule exclusion (whitelist a rule id for a domain).

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'allow_err'});
&can_access("allow") || &error($text{'allow_eacl'});

my $id = $in{'id'};
my $dom = $in{'domain'};

if (!$in{'confirm'}) {
	# Show confirmation page.
	&ui_print_header(undef, $text{'allow_title'}, "");
	print &ui_confirmation_form(
		"allow.cgi",
		$dom ? &text('allow_rusure_dom', $id, $dom)
		     : &text('allow_rusure_all', $id),
		[ [ "id", $id ], [ "domain", $dom ] ],
		[ [ "confirm", $text{'allow_ok'} ] ]);
	&ui_print_footer("index.cgi", $text{'index_return'});
	exit;
	}

# Apply.
my ($ok, $err) = &add_exclusion($id, $dom);
&error($err) if (!$ok);
&redirect("index.cgi".($dom ? "?domain=".&urlize($dom) : ""));
