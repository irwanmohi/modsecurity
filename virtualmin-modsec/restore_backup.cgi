#!/usr/bin/perl
# restore_backup.cgi
# Confirm and restore a config backup over its original file.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'bk_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

my $name = $in{'name'};

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'bk_title'}, "");
	print &ui_confirmation_form(
		"restore_backup.cgi",
		&text('bk_rusure', &html_escape($name)),
		[ [ "name", $name ] ],
		[ [ "confirm", $text{'bk_restore'} ] ]);
	&modsec_footer("backups.cgi", $text{'bk_return'});
	exit;
	}

my ($ok, $err) = &restore_backup($name);
&error($err) if (!$ok);
&redirect("backups.cgi");
