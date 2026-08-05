#!/usr/bin/perl
# restore_backup.cgi
# Confirm and restore a config backup over its original file.

require './modsec-lib.pl';
&ReadParse();
&can_access("toggle") || &error($text{'eng_eacl'});

my $name = $in{'name'};

if (!$in{'confirm'}) {
	&ui_print_header(undef, $text{'bk_title'}, "");
	# Explicit POST: the apply branch requires it, so the method must not
	# depend on a helper's default.
	print &ui_form_start("restore_backup.cgi", "post");
	print &ui_hidden("name", $name);
	print &ui_hidden("confirm", 1);
	print "<p>",&text('bk_rusure', &html_escape($name)),"</p>\n";
	print &ui_form_end([ [ undef, $text{'bk_restore'} ] ]);
	&modsec_footer("backups.cgi", $text{'bk_return'});
	exit;
	}

&require_post();
my ($ok, $err) = &restore_backup($name);
&error($err) if (!$ok);
&redirect("backups.cgi");
