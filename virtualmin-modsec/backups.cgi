#!/usr/bin/perl
# backups.cgi
# List automatic config backups and offer to restore each one.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'bk_title'}, "");

my @b = &list_backups();
print "<p>",$text{'bk_intro'},"</p>\n";

if (!@b) {
	print "<p>",$text{'bk_none'},"</p>\n";
	&modsec_footer("index.cgi", $text{'index_return'});
	exit;
	}

my @rows;
foreach my $e (@b) {
	# Render the timestamp 20260618-011500 as 2026-06-18 01:15:00.
	my $when = $e->{'ts'};
	$when =~ s/^(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)$/$1-$2-$3 $4:$5:$6/;
	my $restore = &can_access("toggle") ?
		&ui_link("restore_backup.cgi?name=".&urlize($e->{'name'}),
			 $text{'bk_restore'}) : "";
	push(@rows, [
		"<tt>".&html_escape($e->{'base'})."</tt>",
		$when,
		sprintf("%.1f KB", ($e->{'size'} || 0) / 1024),
		$restore,
		]);
	}
print &ui_columns_table(
	[ $text{'bk_file'}, $text{'bk_when'}, $text{'logs_size'}, "" ],
	100, \@rows);

&modsec_footer("index.cgi", $text{'index_return'});
