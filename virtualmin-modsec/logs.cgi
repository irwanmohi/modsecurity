#!/usr/bin/perl
# logs.cgi
# Show exactly which error logs are being scanned (for troubleshooting
# discovery of per-domain Virtualmin logs).

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'logs_title'}, "");

my @logs = &log_files();
print "<p>",&text('logs_intro', scalar(@logs)),"</p>\n";

# Effective platform settings (auto-detected; the saved Module Config may show
# different defaults since detection is applied in-memory).
my $plat = &has_command("apache2ctl") ? "apache2 (Debian/Ubuntu)" : "httpd (RHEL family)";
print &ui_table_start($text{'logs_platform'}, "width=100%", 2);
print &ui_table_row($text{'logs_detected'}, "<b>$plat</b>");
print &ui_table_row($text{'logs_reload'}, "<tt>$config{'apache_reload'}</tt>");
print &ui_table_row($text{'logs_modsec'}, "<tt>$config{'modsec_conf'}</tt>");
print &ui_table_row($text{'logs_excl'},   "<tt>$config{'exclusion_file'}</tt>");
print &ui_table_end();

my @rows;
foreach my $f (@logs) {
	my @st = stat($f);
	push(@rows, [ "<tt>".&html_escape($f)."</tt>",
		      $st[7] ? sprintf("%.1f KB", $st[7] / 1024) : "0" ]);
	}
print &ui_columns_table([ $text{'logs_path'}, $text{'logs_size'} ], 100, \@rows);

print "<p><font size=-1>",$text{'logs_hint'},"</font></p>\n";
&modsec_footer("index.cgi", $text{'index_return'});
